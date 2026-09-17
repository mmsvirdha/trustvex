import { UrlAnalysis } from "../types";
import { looksLikeIpLiteral } from "../security/ssrfGuard";

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "secure", "account", "update", "confirm", "signin",
  "banking", "billing", "password", "wallet", "recover", "unlock", "suspended",
];

// Not exhaustive — real root-domain extraction needs a public-suffix list.
// This is a documented, simplified heuristic (see limitations in the report).
function guessRootDomain(hostname: string): { root: string; subdomain: string } {
  const labels = hostname.split(".");
  if (labels.length <= 2) return { root: hostname, subdomain: "" };
  const root = labels.slice(-2).join(".");
  const subdomain = labels.slice(0, -2).join(".");
  return { root, subdomain };
}

export function analyzeUrl(rawUrl: string): UrlAnalysis {
  const url = new URL(rawUrl);
  const hostname = url.hostname;
  const { root, subdomain } = guessRootDomain(hostname);
  const { isIp } = looksLikeIpLiteral(hostname);

  const path = url.pathname;
  const query = url.search.replace(/^\?/, "");
  const digitCount = (rawUrl.match(/[0-9]/g) ?? []).length;
  const specialCharCount = (rawUrl.match(/[^a-zA-Z0-9.:/?&=_-]/g) ?? []).length;
  const subdomainCount = subdomain ? subdomain.split(".").length : 0;
  const isPunycode = hostname.split(".").some((label) => label.startsWith("xn--"));
  const hasEmbeddedCredentials = Boolean(url.username || url.password);
  const commonPorts = ["", "80", "443"];
  const hasUnusualPort = !commonPorts.includes(url.port);
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter((kw) =>
    rawUrl.toLowerCase().includes(kw)
  );

  return {
    raw: rawUrl,
    protocol: url.protocol.replace(":", ""),
    hostname,
    rootDomain: root,
    subdomain,
    path,
    query,
    fragment: url.hash.replace(/^#/, ""),
    port: url.port || null,
    lengths: {
      url: rawUrl.length,
      hostname: hostname.length,
      path: path.length,
      query: query.length,
    },
    subdomainCount,
    digitCount,
    specialCharCount,
    flags: {
      isIpHostname: isIp,
      isPunycode,
      hasEmbeddedCredentials,
      hasUnusualPort,
      excessiveSubdomains: subdomainCount >= 4,
      excessiveLength: rawUrl.length > 120,
      suspiciousKeywords: foundKeywords,
    },
  };
}
