/**
 * SSRF protection primitives.
 *
 * TRUSTVEX treats every scan target as untrusted, hostile input. Before the
 * app makes any outbound network request to a user-submitted host, and again
 * before following any redirect, we validate that the address the hostname
 * actually resolves to is not a private, loopback, link-local, or otherwise
 * internal address. This validation happens inside the DNS `lookup`
 * implementation we hand to Node's http/https client (see safeFetch.ts), so
 * it is re-checked at the moment of every individual TCP connection rather
 * than once up front — this closes the classic "DNS rebinding" gap where a
 * hostname resolves safely at check-time but points somewhere internal at
 * connect-time.
 *
 * LIMITATION (documented, not hidden): this is application-level SSRF
 * defense. It is not a substitute for network-level egress controls
 * (firewall rules, running the app in an isolated network namespace/
 * container with no route to internal infrastructure). For a real
 * production deployment, both layers should exist together.
 */

function ipv4ToLong(ip: string): number | null {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const ipLong = ipv4ToLong(ip);
  const rangeLong = ipv4ToLong(range);
  if (ipLong === null || rangeLong === null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipLong & mask) === (rangeLong & mask);
}

// RFC 1918, RFC 5735, RFC 6598, RFC 3927, RFC 2544, RFC 6890 etc.
const BLOCKED_IPV4_CIDRS = [
  "0.0.0.0/8", // "this" network
  "10.0.0.0/8", // private
  "100.64.0.0/10", // carrier-grade NAT
  "127.0.0.0/8", // loopback
  "169.254.0.0/16", // link-local
  "172.16.0.0/12", // private
  "192.0.0.0/24", // IETF protocol assignments
  "192.0.2.0/24", // TEST-NET-1
  "192.168.0.0/16", // private
  "198.18.0.0/15", // benchmarking
  "198.51.100.0/24", // TEST-NET-2
  "203.0.113.0/24", // TEST-NET-3
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // reserved
  "255.255.255.255/32", // broadcast
];

function isBlockedIpv4(ip: string): boolean {
  return BLOCKED_IPV4_CIDRS.some((cidr) => inCidr(ip, cidr));
}

function isBlockedIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  if (normalized === "::1") return true; // loopback
  if (normalized === "::") return true; // unspecified
  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") ||
      normalized.startsWith("fea") || normalized.startsWith("feb")) {
    return true; // fe80::/10 link-local
  }
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
    return true; // fc00::/7 unique local
  }
  // IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) — unwrap and check the v4 rules
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) {
    return isBlockedIpv4(mapped[1]);
  }
  return false;
}

export function isBlockedAddress(address: string, family: 4 | 6): boolean {
  return family === 4 ? isBlockedIpv4(address) : isBlockedIpv6(address);
}

export function looksLikeIpLiteral(hostname: string): { isIp: boolean; family: 4 | 6 | null } {
  if (ipv4ToLong(hostname) !== null) return { isIp: true, family: 4 };
  // very small IPv6 literal heuristic — good enough to flag it, real
  // validation happens via dns.lookup regardless
  if (hostname.includes(":")) return { isIp: true, family: 6 };
  return { isIp: false, family: null };
}

/**
 * CRITICAL: Node's http/https/tls clients skip the custom `lookup` function
 * entirely when the given host is already a literal IP address — there's
 * nothing to resolve, so the DNS-based guard in safeFetch.ts / tlsAnalyzer.ts
 * never runs for that case. A submitted URL like "https://10.0.0.5" would
 * otherwise sail straight past SSRF protection. This function must be called
 * explicitly, before ever handing a hostname to a network client, to close
 * that gap for IP-literal targets. Non-literal hostnames are still re-checked
 * at connect time via the custom lookup function (that's what protects
 * against DNS rebinding for domain names).
 */
export function assertHostnameSafeIfLiteralIp(hostname: string): void {
  const { isIp, family } = looksLikeIpLiteral(hostname);
  if (!isIp || !family) return;
  const bare = hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets if present
  if (isBlockedAddress(bare, family)) {
    throw new Error(`Blocked request to "${hostname}": private/reserved/loopback IP literal`);
  }
}
