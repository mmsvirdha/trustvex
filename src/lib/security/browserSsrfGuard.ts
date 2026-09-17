// src/lib/security/browserSsrfGuard.ts
//
// SSRF protection for the Playwright crawler.
//
// safeFetch.ts protects Node's own http/https clients by handing them a
// custom `lookup` function that re-validates the resolved address at the
// moment of every TCP connection. Playwright/Chromium does not expose an
// equivalent hook — it does its own DNS resolution deep inside its network
// stack, after our request has already been approved.
//
// The mitigation here is request interception: every request the page
// makes (the main document AND every subresource) is intercepted via
// page.route() BEFORE Chromium sends it. We resolve the hostname ourselves
// and abort the request if every resolved address is private/reserved.
//
// PERFORMANCE NOTE: a page like github.com makes 40+ requests across many
// subdomains. Doing a fresh DNS lookup for each request, synchronously in
// the route handler, added 20+ seconds to some scans because the OS
// resolver is slow under rapid sequential queries. We now cache DNS
// resolution results per hostname for the duration of a scan (short TTL)
// — same protection, dramatically less overhead.

import * as dns from "node:dns";
import { isBlockedAddress, looksLikeIpLiteral } from "./ssrfGuard";

// Simple in-process DNS cache. Keyed by hostname, holds the resolved
// address list + a timestamp. TTL is deliberately short (60s) — long
// enough to cover a single scan, short enough that we don't accidentally
// hold stale DNS across scans where rebinding could matter.
const DNS_CACHE_TTL_MS = 60_000;
const dnsCache = new Map<string, { addresses: dns.LookupAddress[]; at: number }>();

async function lookupCached(hostname: string): Promise<dns.LookupAddress[]> {
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  if (cached && now - cached.at < DNS_CACHE_TTL_MS) {
    return cached.addresses;
  }
  const addresses = await dns.promises.lookup(hostname, { all: true, verbatim: false });
  dnsCache.set(hostname, { addresses, at: now });
  return addresses;
}

export async function isRequestHostnameSafe(hostname: string): Promise<boolean> {
  const bare = hostname.replace(/^\[|\]$/g, "");
  const { isIp, family } = looksLikeIpLiteral(bare);

  if (isIp && family) {
    return !isBlockedAddress(bare, family);
  }

  try {
    const addresses = await lookupCached(hostname);
    if (addresses.length === 0) return false;
    return addresses.every((a) => !isBlockedAddress(a.address, a.family as 4 | 6));
  } catch {
    return false;
  }
}

/** File extensions the crawler refuses to download. Mirrors websiteAnalyzer.ts's list. */
export const BLOCKED_DOWNLOAD_EXTENSIONS = [
  ".exe", ".msi", ".apk", ".scr", ".bat", ".jar", ".zip", ".rar", ".dmg",
];

export function hasBlockedDownloadExtension(url: string): boolean {
  const path = url.split("?")[0].toLowerCase();
  return BLOCKED_DOWNLOAD_EXTENSIONS.some((ext) => path.endsWith(ext));
}