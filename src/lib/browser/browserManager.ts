// src/lib/browser/browserManager.ts
//
// Singleton Chromium instance, reused across scans within this process.
//
// Launching a fresh browser process for every scan would add several
// seconds of startup cost per scan. Instead we keep one long-lived
// Chromium instance alive and give every individual scan its own fresh
// BrowserContext (see browserWebsiteAnalyzer.ts) — that gives per-scan
// isolation (separate cookies, cache, storage) without paying the launch
// cost each time.
//
// LIMITATION (documented, not hidden): this shares one OS process across
// scans. It is not the same as full container/process isolation per scan.
// A hardened production deployment should run this browser inside its own
// sandboxed container with no route to internal infrastructure, in
// addition to the SSRF request-interception guard in browserSsrfGuard.ts.

import { chromium, type Browser } from "playwright";

declare global {
  var __trustvexBrowser: Promise<Browser> | undefined;
}

function launchBrowser(): Promise<Browser> {
  return chromium.launch({ headless: true });
}

export function getBrowser(): Promise<Browser> {
  if (!globalThis.__trustvexBrowser) {
    globalThis.__trustvexBrowser = launchBrowser();
    // If launch fails (e.g. browser binaries not installed), drop the
    // cached promise so the next scan gets a clean retry instead of
    // permanently reusing a rejected promise.
    globalThis.__trustvexBrowser.catch(() => {
      globalThis.__trustvexBrowser = undefined;
    });
  }
  return globalThis.__trustvexBrowser;
}

export async function closeBrowser(): Promise<void> {
  if (globalThis.__trustvexBrowser) {
    try {
      const browser = await globalThis.__trustvexBrowser;
      await browser.close();
    } catch {
      // already gone / never launched — nothing to close
    }
    globalThis.__trustvexBrowser = undefined;
  }
}