import * as http from "node:http";
import * as https from "node:https";
import * as dns from "node:dns";
import type { LookupOneOptions } from "node:dns";
import { assertHostnameSafeIfLiteralIp, isBlockedAddress } from "./ssrfGuard";

// Node's http/https clients try addresses in the order the DNS resolver
// returns them. On networks with a slow or partially-broken IPv6 route,
// trying AAAA first can consume the entire request timeout before the
// client falls back to A. "ipv4first" makes the initial connection try A
// records first. This does NOT disable IPv6 — a host with only AAAA
// records will still be reached — it just changes the preference order
// when both are available.
dns.setDefaultResultOrder("ipv4first");

export class SsrfBlockedError extends Error {
  constructor(hostname: string, reason: string) {
    super(`Blocked request to "${hostname}": ${reason}`);
    this.name = "SsrfBlockedError";
  }
}

const MAX_REDIRECTS_DEFAULT = 8;
const TIMEOUT_MS_DEFAULT = 20000;
const MAX_RESPONSE_BYTES_DEFAULT = 2 * 1024 * 1024; // 2 MB cap on body we read

/**
 * A dns.lookup-compatible function that resolves the hostname and rejects
 * (via the callback error) if every candidate address is private/reserved.
 * This function is invoked by Node's http/https agent at *connection time*,
 * for every single request (including each hop of a redirect chain), which
 * is what protects against DNS-rebinding races between validation and use.
 */
function ssrfSafeLookup(
  hostname: string,
  options: dns.LookupOptions,
  callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void
): void {
  dns.lookup(hostname, { all: true, verbatim: false }, (err, addresses) => {
        if (err) {
      callback(err, "" as unknown as string);
      return;
    }
    const list = addresses as dns.LookupAddress[];
    const safe = list.filter((a) => !isBlockedAddress(a.address, a.family as 4 | 6));
    if (safe.length === 0) {
      callback(
        new SsrfBlockedError(hostname, "resolves only to private/reserved/loopback addresses"),
        "" as unknown as string
      );
      return;
    }
    if ((options as LookupOneOptions).all) {
      callback(null, safe);
    } else {
      callback(null, safe[0].address, safe[0].family);
    }
  });
}

export interface RedirectHop {
  sequence: number;
  requestedUrl: string;
  status: number | null;
  locationHeader: string | null;
  resolvedHostname: string;
  error?: string;
}

export interface SafeFetchResult {
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  bodyTruncated: boolean;
  redirectChain: RedirectHop[];
  timedOut: boolean;
}

export interface SafeFetchOptions {
  method?: "GET" | "HEAD";
  maxRedirects?: number;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

function validateUrlOrThrow(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Malformed URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SsrfBlockedError(url.hostname, `unsupported protocol "${url.protocol}"`);
  }
  try {
    assertHostnameSafeIfLiteralIp(url.hostname);
  } catch {
    throw new SsrfBlockedError(url.hostname, "private/reserved/loopback IP literal");
  }
  return url;
}

/**
 * Performs a single GET/HEAD request with SSRF-guarded DNS resolution,
 * manually following redirects (never letting the underlying client
 * auto-follow them) so that every hop is independently re-validated before
 * the next request is made.
 */
export function safeFetch(rawUrl: string, opts: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  const method = opts.method ?? "GET";
  const maxRedirects = opts.maxRedirects ?? MAX_REDIRECTS_DEFAULT;
  const timeoutMs = opts.timeoutMs ?? TIMEOUT_MS_DEFAULT;
  const maxResponseBytes = opts.maxResponseBytes ?? MAX_RESPONSE_BYTES_DEFAULT;

  const chain: RedirectHop[] = [];

  return new Promise((resolve, reject) => {
    let overallTimedOut = false;
    let settled = false;
    const overallDeadline = Date.now() + timeoutMs * (maxRedirects + 1);

    function safeResolve(value: SafeFetchResult) {
      if (settled) return;
      settled = true;
      resolve(value);
    }

    function safeReject(err: Error) {
      if (settled) return;
      settled = true;
      reject(err);
    }

    function requestOnce(currentUrl: URL, hopIndex: number) {
      if (hopIndex > maxRedirects) {
        safeReject(new Error(`Too many redirects (> ${maxRedirects})`));
        return;
      }
      if (Date.now() > overallDeadline) {
        overallTimedOut = true;
        safeReject(new Error("Request timed out"));
        return;
      }

      const hop: RedirectHop = {
        sequence: hopIndex,
        requestedUrl: currentUrl.toString(),
        status: null,
        locationHeader: null,
        resolvedHostname: currentUrl.hostname,
      };

      const client = currentUrl.protocol === "https:" ? https : http;
      const req = client.request(
        currentUrl,
        {
          method,
          lookup: ssrfSafeLookup as unknown as typeof dns.lookup,
          timeout: timeoutMs,
          headers: {
            "User-Agent": "TrustvexScanner/0.1 (+automated risk analysis; see report for details)",
            Accept: "text/html,application/xhtml+xml",
          },
          rejectUnauthorized: false, // we WANT to see broken-TLS sites; certificate trust is analyzed separately by the TLS analyzer, not enforced here
        },
        (res) => {
          hop.status = res.statusCode ?? null;

          const isRedirect = res.statusCode !== undefined && res.statusCode >= 300 && res.statusCode < 400;
          const location = res.headers.location;

          if (isRedirect && location) {
            hop.locationHeader = location;
            chain.push(hop);
            res.resume(); // discard body of redirect responses
            let nextUrl: URL;
            try {
              nextUrl = new URL(location, currentUrl);
            } catch {
              safeReject(new Error(`Redirect to invalid location: ${location}`));
              return;
            }
            try {
              validateUrlOrThrow(nextUrl.toString());
            } catch (e) {
              safeReject(e instanceof Error ? e : new Error(String(e)));
              return;
            }
            requestOnce(nextUrl, hopIndex + 1);
            return;
          }

          chain.push(hop);

          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") headers[k] = v;
            else if (Array.isArray(v)) headers[k] = v.join(", ");
          }

          let received = 0;
          let truncated = false;
          const chunks: Buffer[] = [];

          res.on("data", (chunk: Buffer) => {
            received += chunk.length;
            if (received > maxResponseBytes) {
              truncated = true;
              res.destroy();
              return;
            }
            chunks.push(chunk);
          });

          res.on("end", () => {
            safeResolve({
              finalUrl: currentUrl.toString(),
              status: res.statusCode ?? 0,
              headers,
              body: Buffer.concat(chunks).toString("utf-8"),
              bodyTruncated: truncated,
              redirectChain: chain,
              timedOut: overallTimedOut,
            });
          });

          res.on("error", (err) => {
            if (truncated) {
              safeResolve({
                finalUrl: currentUrl.toString(),
                status: res.statusCode ?? 0,
                headers,
                body: Buffer.concat(chunks).toString("utf-8"),
                bodyTruncated: true,
                redirectChain: chain,
                timedOut: overallTimedOut,
              });
            } else {
              safeReject(err);
            }
          });
        }
      );

      req.on("timeout", () => {
        overallTimedOut = true;
        // Destroy the socket so the underlying connection is torn down,
        // then reject with a clear, typed error. Without an explicit
        // reject here, the destroy() would surface as a raw socket error
        // via the "error" handler instead of a meaningful timeout.
        req.destroy();
        safeReject(new Error(`Request to ${currentUrl.hostname} timed out after ${timeoutMs}ms`));
      });

      req.on("error", (err) => {
        hop.error = err.message;
        if (!chain.includes(hop)) chain.push(hop);
        safeReject(err);
      });

      req.end();
    }

    try {
      const initial = validateUrlOrThrow(rawUrl);
      requestOnce(initial, 0);
    } catch (e) {
      safeReject(e instanceof Error ? e : new Error(String(e)));
    }
  });
}