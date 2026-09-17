import * as tls from "node:tls";
import * as dns from "node:dns";
import { TlsAnalysis } from "../types";
import { assertHostnameSafeIfLiteralIp, isBlockedAddress } from "../security/ssrfGuard";

const CONNECT_TIMEOUT_MS = 6000;

function ssrfSafeLookup(
  hostname: string,
  options: dns.LookupOptions,
  callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void
): void {
  // verbatim: false makes Node apply the global default result order.
  // Combined with dns.setDefaultResultOrder("ipv4first") (set in
  // safeFetch.ts), this causes IPv4 to be tried before IPv6 when both
  // are available. Without this, a slow or broken IPv6 route can eat the
  // entire connection timeout before falling back to IPv4 — which is
  // exactly the bug we saw on neverssl.com.
  dns.lookup(hostname, { all: true, verbatim: false }, (err, addresses) => {
    if (err) {
      callback(err, "");
      return;
    }
    const list = addresses as dns.LookupAddress[];
    const safe = list.filter((a) => !isBlockedAddress(a.address, a.family as 4 | 6));
    if (safe.length === 0) {
      callback(new Error("resolves only to private/reserved addresses"), "");
      return;
    }
    // Node's Happy Eyeballs (autoSelectFamily, on by default in modern Node)
    // calls this lookup function with options.all = true and expects an
    // array of candidates back. If we always returned a single address
    // regardless of what was requested, the connection would fail with a
    // confusing "Invalid IP address: undefined" error.
    if (options.all) {
      callback(null, safe);
    } else {
      callback(null, safe[0].address, safe[0].family);
    }
  });
}

function daysBetween(a: Date, b: Date): number {
  return Math.round((a.getTime() - b.getTime()) / (1000 * 60 * 60 * 24));
}

export function analyzeTls(hostname: string): Promise<TlsAnalysis> {
  return new Promise((resolve) => {
    try {
      assertHostnameSafeIfLiteralIp(hostname);
    } catch (err) {
      resolve({
        status: "unavailable",
        httpsAvailable: false,
        authorized: null,
        authorizationError: null,
        protocol: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        hostnameMatches: null,
        daysUntilExpiry: null,
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    let settled = false;

    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false, // we inspect trust ourselves rather than let the socket throw
        timeout: CONNECT_TIMEOUT_MS,
        lookup: ssrfSafeLookup as unknown as typeof dns.lookup,
      },
      () => {
        if (settled) return;
        settled = true;

        const cert = socket.getPeerCertificate(false);
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const authError = socket.authorizationError
          ? String(socket.authorizationError)
          : null;

        let hostnameMatches: boolean | null = null;
        try {
          hostnameMatches = tls.checkServerIdentity(hostname, cert) === undefined;
        } catch {
          hostnameMatches = false;
        }

        const validTo = cert?.valid_to ? new Date(cert.valid_to) : null;

        resolve({
          status: "ok",
          httpsAvailable: true,
          authorized,
          authorizationError: authError,
          protocol: protocol ?? null,
          issuer: cert?.issuer ? Object.values(cert.issuer).join(", ") : null,
          subject: cert?.subject ? Object.values(cert.subject).join(", ") : null,
          validFrom: cert?.valid_from ?? null,
          validTo: cert?.valid_to ?? null,
          hostnameMatches,
          daysUntilExpiry: validTo ? daysBetween(validTo, new Date()) : null,
        });

        socket.end();
      }
    );

    socket.on("timeout", () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        status: "unavailable",
        httpsAvailable: false,
        authorized: null,
        authorizationError: null,
        protocol: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        hostnameMatches: null,
        daysUntilExpiry: null,
        error: "Connection timed out",
      });
    });

    socket.on("error", (err) => {
      if (settled) return;
      settled = true;
      resolve({
        status: "no_https",
        httpsAvailable: false,
        authorized: null,
        authorizationError: null,
        protocol: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        hostnameMatches: null,
        daysUntilExpiry: null,
        error: err.message,
      });
    });
  });
}