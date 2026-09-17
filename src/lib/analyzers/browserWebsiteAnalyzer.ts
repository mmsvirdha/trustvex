// src/lib/analyzers/browserWebsiteAnalyzer.ts
//
// Analyzes a website by actually rendering it in a sandboxed, headless
// Chromium browser (via Playwright) rather than parsing raw HTML text.
// This sees content injected by client-side JavaScript after load, which
// a static-HTML parser (websiteAnalyzer.ts) cannot.
//
// SECURITY (crawler runs against untrusted, potentially hostile pages):
// - Every request the page makes (main document + every subresource) is
//   intercepted and SSRF-checked before Chromium is allowed to send it —
//   see browserSsrfGuard.ts.
// - Downloads are disabled at the context level and download-shaped
//   requests are aborted before they start.
// - The crawler never clicks, types, or submits anything — it only
//   navigates once and reads the resulting DOM.
// - Navigation is bounded by a hard timeout; a page that never finishes
//   loading fails safely into an "unavailable" result rather than hanging
//   the scan.
// - Media/font resources are blocked (not needed for any trust signal we
//   extract, and blocking them reduces bandwidth and attack surface).
//
// LIMITATION (documented, not hidden): this MVP does not enforce a hard
// byte cap on individual subresources, and the browser process is shared
// across scans rather than fully isolated per scan (see browserManager.ts).
// A production deployment should add both, plus run the browser in a
// network-restricted container.

import type { Page } from "playwright";
import { WebsiteAnalysis } from "../types";
import { getBrowser } from "../browser/browserManager";
import { isRequestHostnameSafe, hasBlockedDownloadExtension } from "../security/browserSsrfGuard";

const NAVIGATION_TIMEOUT_MS = 25000;
const SETTLE_TIMEOUT_MS = 3000;
const PAYMENT_KEYWORDS = [
  "card number", "cvv", "cvc", "expiry", "credit card", "billing address", "iban",
];
const BLOCKED_RESOURCE_TYPES = new Set(["media", "font"]);

function hostnameOf(u: string, base?: string): string | null {
  try {
    return new URL(u, base).hostname;
  } catch {
    return null;
  }
}

interface RawPageData {
  title: string | null;
  metaDescription: string | null;
  formCount: number;
  passwordFieldCount: number;
  emailFieldCount: number;
  bodyTextLower: string;
  iframeSrcs: string[];
  scriptSrcs: string[];
  linkHrefs: string[];
}

async function extractPageData(page: Page): Promise<RawPageData> {
  return page.evaluate(() => {
    const title = document.title || null;
    const metaEl = document.querySelector('meta[name="description"]') as HTMLMetaElement | null;
    const metaDescription = metaEl?.content ?? null;

    const forms = document.querySelectorAll("form");
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const emailFields = document.querySelectorAll(
      'input[type="email"], input[name*="email" i]'
    );

    const iframeSrcs = Array.from(document.querySelectorAll("iframe"))
      .map((el) => el.getAttribute("src"))
      .filter((s): s is string => Boolean(s));

    const scriptSrcs = Array.from(document.querySelectorAll("script[src]"))
      .map((el) => el.getAttribute("src"))
      .filter((s): s is string => Boolean(s));

    const linkHrefs = Array.from(document.querySelectorAll("a[href]"))
      .map((el) => el.getAttribute("href"))
      .filter((s): s is string => Boolean(s));

    return {
      title,
      metaDescription,
      formCount: forms.length,
      passwordFieldCount: passwordFields.length,
      emailFieldCount: emailFields.length,
      bodyTextLower: (document.body?.innerText ?? "").toLowerCase().slice(0, 20000),
      iframeSrcs,
      scriptSrcs,
      linkHrefs,
    };
  });
}

export async function analyzeWebsiteWithBrowser(targetUrl: string): Promise<WebsiteAnalysis> {
  const pageHost = hostnameOf(targetUrl);
  const browser = await getBrowser();

  const context = await browser.newContext({
    acceptDownloads: false,
    ignoreHTTPSErrors: true,
    userAgent: "TrustvexScanner/0.1 (+automated risk analysis; see report for details)",
    viewport: { width: 1280, height: 900 },
  });
  context.setDefaultTimeout(NAVIGATION_TIMEOUT_MS);

  let bodyTruncated = false;

  try {
    const page = await context.newPage();

    page.on("dialog", (dialog) => {
      dialog.dismiss().catch(() => {});
    });

    await page.route("**/*", async (route) => {
      const request = route.request();
      const url = request.url();

      let hostname: string;
      try {
        hostname = new URL(url).hostname;
      } catch {
        await route.abort();
        return;
      }

      if (BLOCKED_RESOURCE_TYPES.has(request.resourceType())) {
        await route.abort();
        return;
      }
            // Abort a small set of known-slow tracker/analytics hosts. These
      // never contribute to any trust signal we extract, and on some
      // networks a single hanging analytics beacon can stall a page past
      // its navigation timeout. Matching is by suffix to catch CDN
      // variants (e.g. xyz.google-analytics.com).
      const TRACKER_HOST_SUFFIXES = [
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "facebook.net",
      ];
      if (TRACKER_HOST_SUFFIXES.some((s) => hostname.endsWith(s))) {
        await route.abort();
        return;
      }
      
      if (hasBlockedDownloadExtension(url)) {
        await route.abort();
        return;
      }

      const safe = await isRequestHostnameSafe(hostname);
      if (!safe) {
        await route.abort();
        return;
      }

      await route.continue();
    });

    let navError: string | null = null;
    try {
      await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: NAVIGATION_TIMEOUT_MS,
      });
      await page.waitForLoadState("networkidle", { timeout: SETTLE_TIMEOUT_MS }).catch(() => {
        bodyTruncated = true;
      });
    } catch (err) {
      navError = err instanceof Error ? err.message : String(err);
    }

    if (navError) {
      return {
        status: "unavailable",
        analysisMethod: "browser",
        title: null,
        metaDescription: null,
        formCount: 0,
        passwordFieldCount: 0,
        loginFormDetected: false,
        paymentKeywordDetected: false,
        iframeCount: 0,
        externalIframeDomains: [],
        scriptCount: 0,
        externalScriptDomains: [],
        linkCount: 0,
        externalLinkDomainCount: 0,
        downloadLinksDetected: [],
        error: navError,
      };
    }

    const data = await extractPageData(page);

    const iframeDomains = new Set<string>();
    for (const src of data.iframeSrcs) {
      const host = hostnameOf(src, targetUrl);
      if (host && host !== pageHost) iframeDomains.add(host);
    }

    const scriptDomains = new Set<string>();
    for (const src of data.scriptSrcs) {
      const host = hostnameOf(src, targetUrl);
      if (host && host !== pageHost) scriptDomains.add(host);
    }

    const linkDomains = new Set<string>();
    const downloads: string[] = [];
    for (const href of data.linkHrefs) {
      const host = hostnameOf(href, targetUrl);
      if (host && host !== pageHost) linkDomains.add(host);
      if (hasBlockedDownloadExtension(href)) downloads.push(href);
    }

    const paymentDetected = PAYMENT_KEYWORDS.some((kw) => data.bodyTextLower.includes(kw));
    const loginDetected =
      data.passwordFieldCount > 0 &&
      (data.bodyTextLower.includes("log in") ||
        data.bodyTextLower.includes("login") ||
        data.bodyTextLower.includes("sign in") ||
        data.emailFieldCount > 0);

    return {
      status: bodyTruncated ? "truncated" : "ok",
      analysisMethod: "browser",
      title: data.title ? data.title.trim().slice(0, 200) : null,
      metaDescription: data.metaDescription,
      formCount: data.formCount,
      passwordFieldCount: data.passwordFieldCount,
      loginFormDetected: loginDetected,
      paymentKeywordDetected: paymentDetected,
      iframeCount: data.iframeSrcs.length,
      externalIframeDomains: [...iframeDomains],
      scriptCount: data.scriptSrcs.length,
      externalScriptDomains: [...scriptDomains],
      linkCount: data.linkHrefs.length,
      externalLinkDomainCount: linkDomains.size,
      downloadLinksDetected: downloads,
    };
  } finally {
    await context.close().catch(() => {});
  }
}