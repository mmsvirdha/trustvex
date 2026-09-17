import { WebsiteAnalysis } from "../types";
import type { SafeFetchResult } from "../security/safeFetch";

const DOWNLOAD_EXTENSIONS = [".exe", ".msi", ".apk", ".scr", ".bat", ".jar", ".zip", ".rar", ".dmg"];
const PAYMENT_KEYWORDS = ["card number", "cvv", "cvc", "expiry", "credit card", "billing address", "iban"];

function hostnameOf(u: string, base?: string): string | null {
  try {
    return new URL(u, base).hostname;
  } catch {
    return null;
  }
}

function extractAttr(tag: string, attr: string): string | null {
  const match = tag.match(new RegExp(`${attr}\\s*=\\s*["']([^"']*)["']`, "i"));
  return match ? match[1] : null;
}

/**
 * Deliberately simple regex/string based HTML inspection rather than a full
 * DOM parser or a real browser (Playwright). This is a documented scope
 * decision for the MVP: it reads static markup only and will not see
 * content injected by client-side JavaScript after load. See report
 * limitations.
 */
export function analyzeWebsite(
  pageUrl: string,
  fetchResult: SafeFetchResult | null,
  fetchError: string | null
): WebsiteAnalysis {
 if (!fetchResult) {
    return {
      status: "unavailable",
      analysisMethod: "static",
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
      error: fetchError ?? "Could not fetch page",
    };
  }

  const html = fetchResult.body;
  const pageHost = hostnameOf(pageUrl);

  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const metaMatch = html.match(/<meta[^>]+name=["']description["'][^>]*>/i);

  const formTags = html.match(/<form\b[^>]*>/gi) ?? [];
  const inputTags = html.match(/<input\b[^>]*>/gi) ?? [];
  const passwordFields = inputTags.filter((t) => /type\s*=\s*["']password["']/i.test(t));
  const emailFields = inputTags.filter((t) => /type\s*=\s*["']email["']/i.test(t) || /name\s*=\s*["'][^"']*email[^"']*["']/i.test(t));

  const iframeTags = html.match(/<iframe\b[^>]*>/gi) ?? [];
  const iframeDomains = new Set<string>();
  for (const tag of iframeTags) {
    const src = extractAttr(tag, "src");
    if (src) {
      const host = hostnameOf(src, pageUrl);
      if (host && host !== pageHost) iframeDomains.add(host);
    }
  }

  const scriptTags = html.match(/<script\b[^>]*>/gi) ?? [];
  const scriptDomains = new Set<string>();
  for (const tag of scriptTags) {
    const src = extractAttr(tag, "src");
    if (src) {
      const host = hostnameOf(src, pageUrl);
      if (host && host !== pageHost) scriptDomains.add(host);
    }
  }

  const anchorTags = html.match(/<a\b[^>]*href\s*=\s*["'][^"']*["'][^>]*>/gi) ?? [];
  const linkDomains = new Set<string>();
  const downloads: string[] = [];
  for (const tag of anchorTags) {
    const href = extractAttr(tag, "href");
    if (!href) continue;
    const host = hostnameOf(href, pageUrl);
    if (host && host !== pageHost) linkDomains.add(host);
    if (DOWNLOAD_EXTENSIONS.some((ext) => href.toLowerCase().endsWith(ext))) {
      downloads.push(href);
    }
  }

  const lowerHtml = html.toLowerCase();
  const paymentDetected = PAYMENT_KEYWORDS.some((kw) => lowerHtml.includes(kw));
  const loginDetected =
    passwordFields.length > 0 &&
    (lowerHtml.includes("log in") || lowerHtml.includes("login") || lowerHtml.includes("sign in") || emailFields.length > 0);

  return {
    status: fetchResult.bodyTruncated ? "truncated" : "ok",
    analysisMethod: "static",
    title: titleMatch ? titleMatch[1].trim().slice(0, 200) : null,
    metaDescription: metaMatch ? extractAttr(metaMatch[0], "content") : null,
    formCount: formTags.length,
    passwordFieldCount: passwordFields.length,
    loginFormDetected: loginDetected,
    paymentKeywordDetected: paymentDetected,
    iframeCount: iframeTags.length,
    externalIframeDomains: [...iframeDomains],
    scriptCount: scriptTags.length,
    externalScriptDomains: [...scriptDomains],
    linkCount: anchorTags.length,
    externalLinkDomainCount: linkDomains.size,
    downloadLinksDetected: downloads,
  };
}
