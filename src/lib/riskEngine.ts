import {
  Confidence,
  DnsAnalysis,
  PositiveSignal,
  RedirectAnalysis,
  ReputationAnalysis,
  RiskFactor,
  RiskLevel,
  TlsAnalysis,
  UrlAnalysis,
  WebsiteAnalysis,
} from "./types";
import { IMPACT, MIN_CONFIDENCE_FOR_VERDICT, TRUST_SCORE_THRESHOLDS } from "./riskConfig";

interface EngineInput {
  url: UrlAnalysis;
  dns: DnsAnalysis;
  tls: TlsAnalysis;
  redirects: RedirectAnalysis;
  website: WebsiteAnalysis;
  reputation: ReputationAnalysis;
}

interface EngineOutput {
  trustScore: number;
  riskLevel: RiskLevel;
  confidence: Confidence;
  riskFactors: RiskFactor[];
  positiveSignals: PositiveSignal[];
  limitations: string[];
  recommendation: string;
}

function factor(
  category: RiskFactor["category"],
  severity: RiskFactor["severity"],
  factorName: string,
  description: string,
  impact: number,
  evidence: Record<string, unknown>
): RiskFactor {
  return { category, severity, factor: factorName, description, impact, evidence };
}

function severityFor(impact: number): RiskFactor["severity"] {
  if (impact >= 15) return "HIGH";
  if (impact >= 8) return "MEDIUM";
  return "LOW";
}

export function runRiskEngine(input: EngineInput): EngineOutput {
  const { url, dns, tls, redirects, website, reputation } = input;
  const riskFactors: RiskFactor[] = [];
  const positiveSignals: PositiveSignal[] = [];
  const limitations: string[] = [];

  // ---- URL signals ----
  if (url.flags.isIpHostname) {
    riskFactors.push(
      factor("URL", severityFor(IMPACT.URL_IS_IP_HOSTNAME), "IP address used as hostname",
        "The URL uses a raw IP address instead of a domain name, which legitimate consumer-facing sites rarely do.",
        IMPACT.URL_IS_IP_HOSTNAME, { hostname: url.hostname })
    );
  }
  if (url.flags.isPunycode) {
    riskFactors.push(
      factor("URL", severityFor(IMPACT.URL_PUNYCODE), "Punycode (internationalized) hostname",
        "The hostname contains punycode-encoded labels, which can be used to visually imitate a different domain.",
        IMPACT.URL_PUNYCODE, { hostname: url.hostname })
    );
  }
  if (url.flags.hasEmbeddedCredentials) {
    riskFactors.push(
      factor("URL", severityFor(IMPACT.URL_EMBEDDED_CREDENTIALS), "Credentials embedded in URL",
        "The URL includes a username/password segment, a pattern often used to obscure the real destination.",
        IMPACT.URL_EMBEDDED_CREDENTIALS, {})
    );
  }
  if (url.flags.hasUnusualPort) {
    riskFactors.push(
      factor("URL", severityFor(IMPACT.URL_UNUSUAL_PORT), "Non-standard port",
        `The URL specifies port ${url.port}, which is unusual for a public-facing website.`,
        IMPACT.URL_UNUSUAL_PORT, { port: url.port })
    );
  }
  if (url.flags.excessiveSubdomains) {
    riskFactors.push(
      factor("URL", severityFor(IMPACT.URL_EXCESSIVE_SUBDOMAINS), "Unusually many subdomains",
        `The hostname has ${url.subdomainCount} subdomain labels, which can be used to bury the real domain.`,
        IMPACT.URL_EXCESSIVE_SUBDOMAINS, { subdomainCount: url.subdomainCount, hostname: url.hostname })
    );
  }
  if (url.flags.excessiveLength) {
    riskFactors.push(
      factor("URL", severityFor(IMPACT.URL_EXCESSIVE_LENGTH), "Unusually long URL",
        "The submitted URL is unusually long, a pattern sometimes used to hide structure from a quick visual check.",
        IMPACT.URL_EXCESSIVE_LENGTH, { length: url.lengths.url })
    );
  }
  if (url.flags.suspiciousKeywords.length > 0) {
    const impact = Math.min(
      url.flags.suspiciousKeywords.length * IMPACT.URL_SUSPICIOUS_KEYWORDS,
      IMPACT.URL_SUSPICIOUS_KEYWORDS_CAP
    );
    riskFactors.push(
      factor("URL", severityFor(impact), "Sensitive/security-related keywords in URL",
        "The URL contains words commonly used in phishing attempts (e.g. account, verify, secure). This alone is not conclusive — many legitimate URLs use these words too.",
        impact, { keywords: url.flags.suspiciousKeywords })
    );
  } else {
    positiveSignals.push({
      category: "URL", signal: "No suspicious keywords",
      description: "The URL does not contain common phishing-associated keywords.",
      evidence: {},
    });
  }

  // ---- DNS signals ----
  if (dns.status === "unavailable") {
    riskFactors.push(
      factor("DNS", severityFor(IMPACT.DNS_UNAVAILABLE), "DNS resolution unavailable",
        "The hostname could not be resolved via standard DNS record types, so this evidence source is missing.",
        IMPACT.DNS_UNAVAILABLE, {})
    );
    limitations.push("DNS records could not be retrieved for this hostname.");
  } else {
    if (dns.caa.status === "ok") {
      positiveSignals.push({
        category: "DNS", signal: "CAA record present",
        description: "A Certificate Authority Authorization record restricts which CAs may issue certificates for this domain.",
        evidence: { caa: dns.caa.records },
      });
    } else {
      riskFactors.push(
        factor("DNS", "LOW", "No CAA record",
          "No Certificate Authority Authorization record was found. This is common and not itself a strong signal, but its absence removes a layer of certificate-issuance protection.",
          IMPACT.DNS_NO_CAA, {})
      );
    }
  }

  // ---- TLS signals ----
  //
  // Two independent things are checked here:
  //   1. The connection the user actually submitted — was it http:// ?
  //      Even if the host also serves HTTPS, a submission over http:// is
  //      an unencrypted connection and deserves its own risk signal.
  //   2. The certificate the host presents on port 443 — trusted? expired?
  //      matching the hostname? These are separate from #1 because a host
  //      can have a perfectly valid cert while the user is still visiting
  //      it over plain HTTP.
  if (url.protocol === "http") {
    const httpsAlsoAvailable = tls.status === "ok";
    riskFactors.push(
      factor(
        "TLS",
        "MEDIUM",
        "Submitted over unencrypted HTTP",
        httpsAlsoAvailable
          ? "The URL uses http:// instead of https://. This host also serves HTTPS, but the connection you asked us to evaluate is unencrypted — anything sent over it could be intercepted or modified in transit."
          : "The URL uses http:// instead of https://, and this host does not appear to serve HTTPS on port 443. Traffic sent over this connection is not encrypted.",
        15,
        { protocol: url.protocol, httpsAvailableOnHost: httpsAlsoAvailable }
      )
    );
  }

  if (tls.status === "no_https") {
    riskFactors.push(
      factor("TLS", severityFor(IMPACT.TLS_NO_HTTPS), "No HTTPS available",
        "The site did not respond to a TLS handshake on port 443. Traffic to this site, if served over HTTP, is not encrypted.",
        IMPACT.TLS_NO_HTTPS, { error: tls.error ?? null })
    );
  } else if (tls.status === "unavailable") {
    riskFactors.push(
      factor("TLS", severityFor(IMPACT.TLS_UNAVAILABLE), "TLS analysis inconclusive",
        "A TLS connection could not be completed in time, so certificate details could not be inspected.",
        IMPACT.TLS_UNAVAILABLE, { error: tls.error ?? null })
    );
    limitations.push("TLS certificate details could not be retrieved (connection timed out).");
  } else {
    if (!tls.authorized) {
      riskFactors.push(
        factor("TLS", severityFor(IMPACT.TLS_UNAUTHORIZED), "Certificate not trusted by default CA store",
          "The presented TLS certificate did not validate against the standard trusted certificate authorities.",
          IMPACT.TLS_UNAUTHORIZED, { authorizationError: tls.authorizationError })
      );
    }
    if (tls.hostnameMatches === false) {
      riskFactors.push(
        factor("TLS", severityFor(IMPACT.TLS_HOSTNAME_MISMATCH), "Certificate hostname mismatch",
          "The certificate's subject does not match the hostname being visited.",
          IMPACT.TLS_HOSTNAME_MISMATCH, { subject: tls.subject })
      );
    }
    if (tls.daysUntilExpiry !== null && tls.daysUntilExpiry <= 7) {
      riskFactors.push(
        factor("TLS", severityFor(IMPACT.TLS_EXPIRING_SOON), "Certificate expiring very soon",
          `The TLS certificate expires in ${tls.daysUntilExpiry} day(s).`,
          IMPACT.TLS_EXPIRING_SOON, { validTo: tls.validTo })
      );
    }
    if (tls.authorized && tls.hostnameMatches) {
      const viaHttp = url.protocol === "http";
      positiveSignals.push({
        category: "TLS",
        signal: viaHttp
          ? "Valid HTTPS certificate available on this host"
          : "Valid, trusted HTTPS certificate",
        description: viaHttp
          ? "This host does serve a valid HTTPS certificate on port 443, but the URL you submitted uses http://, so the connection you're evaluating is not encrypted. A valid certificate shows the connection would be encrypted over HTTPS — it does not prove the site's content is trustworthy."
          : "The site presents a certificate trusted by the standard CA store and matching its hostname. Note: this shows the connection is encrypted, not that the site's content is trustworthy.",
        evidence: { issuer: tls.issuer, validTo: tls.validTo },
      });
    }
  }

  // ---- Redirect signals ----
  if (redirects.status === "unavailable") {
    riskFactors.push(
      factor("REDIRECT", severityFor(IMPACT.REDIRECT_UNAVAILABLE), "Could not load target page",
        "The page could not be reached to analyze its redirect behavior or content.",
        IMPACT.REDIRECT_UNAVAILABLE, { error: redirects.error ?? null })
    );
    limitations.push("The target page could not be fetched, so redirect and content analysis are incomplete.");
  } else {
    if (redirects.excessiveRedirects) {
      riskFactors.push(
        factor("REDIRECT", severityFor(IMPACT.REDIRECT_EXCESSIVE), "Excessive redirect chain",
          `The URL redirected ${redirects.hopCount} times before reaching a final destination.`,
          IMPACT.REDIRECT_EXCESSIVE, { hopCount: redirects.hopCount })
      );
    }
    if (redirects.crossDomainHopCount > 0) {
      const impact = Math.min(
        redirects.crossDomainHopCount * IMPACT.REDIRECT_CROSS_DOMAIN_PER_HOP,
        IMPACT.REDIRECT_CROSS_DOMAIN_CAP
      );
      riskFactors.push(
        factor("REDIRECT", severityFor(impact), "Cross-domain redirect(s)",
          `The request was redirected to a different domain ${redirects.crossDomainHopCount} time(s) before landing on its final destination.`,
          impact, { finalUrl: redirects.finalUrl, chain: redirects.chain })
      );
    }
    if (redirects.hopCount === 0) {
      positiveSignals.push({
        category: "REDIRECT", signal: "No redirects",
        description: "The URL resolved directly without any redirect chain.",
        evidence: {},
      });
    }
  }

  // ---- Website signals ----
  if (website.status === "unavailable") {
    riskFactors.push(
      factor("WEBSITE", severityFor(IMPACT.WEBSITE_UNAVAILABLE), "Page content could not be analyzed",
        "The page's HTML could not be retrieved or parsed.",
        IMPACT.WEBSITE_UNAVAILABLE, { error: website.error ?? null })
    );
    limitations.push("Page content (forms, scripts, iframes) could not be analyzed.");
  } else {
    if (website.loginFormDetected) {
      const nonHttps = tls.status !== "ok" || !tls.authorized;
      const impact = nonHttps ? IMPACT.WEBSITE_LOGIN_FORM_NON_HTTPS : IMPACT.WEBSITE_LOGIN_FORM;
      riskFactors.push(
        factor("WEBSITE", severityFor(impact),
          nonHttps ? "Login form on a connection without a trusted certificate" : "Login form detected",
          nonHttps
            ? "A password field was found on a page that does not have a fully trusted HTTPS certificate. Credentials entered here could be exposed."
            : "The page contains a form with a password field. This is expected on many legitimate sites, but raises the stakes of any other risk factors found.",
          impact, { passwordFieldCount: website.passwordFieldCount })
      );
    }
    if (website.paymentKeywordDetected) {
      riskFactors.push(
        factor("WEBSITE", severityFor(IMPACT.WEBSITE_PAYMENT_KEYWORDS), "Payment-related fields detected",
          "The page appears to request payment card details.",
          IMPACT.WEBSITE_PAYMENT_KEYWORDS, {})
      );
    }
    if (website.externalScriptDomains.length > 5) {
      riskFactors.push(
        factor("WEBSITE", severityFor(IMPACT.WEBSITE_MANY_EXTERNAL_SCRIPTS), "Many third-party script sources",
          `Scripts are loaded from ${website.externalScriptDomains.length} distinct external domains.`,
          IMPACT.WEBSITE_MANY_EXTERNAL_SCRIPTS, { domains: website.externalScriptDomains })
      );
    }
    if (website.downloadLinksDetected.length > 0) {
      riskFactors.push(
        factor("WEBSITE", severityFor(IMPACT.WEBSITE_DOWNLOAD_LINKS), "Executable/archive download links present",
          "The page links directly to executable or archive files.",
          IMPACT.WEBSITE_DOWNLOAD_LINKS, { links: website.downloadLinksDetected })
      );
    }
    limitations.push(
      "Website content analysis reads the rendered DOM; content injected after the settle window may not be observed."
    );
  }

  // ---- Reputation signals ----
  if (reputation.status === "unavailable") {
    limitations.push(reputation.note);
  } else {
    const suspicious = reputation.providers.filter((p) => p.status === "suspicious");
    if (suspicious.length > 0) {
      riskFactors.push(
        factor(
          "REPUTATION",
          "HIGH",
          "Flagged by reputation provider(s)",
          `${suspicious.length} configured reputation source(s) flagged this host as suspicious. This is one evidence source, not a verdict — see provider details below.`,
          Math.min(suspicious.length * IMPACT.REPUTATION_SUSPICIOUS_PER_PROVIDER, 40),
          {
            providers: suspicious.map((p) => ({
              provider: p.provider,
              status: p.status,
              confidence: p.confidence,
              summary: p.summary,
              reference: p.reference,
              evidenceUrl: p.evidenceUrl,
              tags: p.tags,
              checkedAt: p.checkedAt,
              error: p.error,
            })),
          }
        )
      );
       } else if (reputation.providers.length > 0) {
      // Providers answered, but nobody flagged this host. Per B2's design
      // rule, "no results" is NOT a positive signal — it just means the
      // configured providers have no record of this URL. Emit an
      // informational limitation instead of a positive signal, so a
      // reader can't misread absence of data as evidence of safety.
      const answered = reputation.providers.filter(
        (p) => p.status === "no_results"
      );
      if (answered.length > 0) {
        limitations.push(
          `${answered.length} reputation provider(s) returned no record for this URL. ` +
            `Absence of a threat record is not evidence of safety — ` +
            answered.map((p) => p.provider).join(", ") +
            ` may simply not track threats of this kind.`
        );
      }
    }

    const unavailable = reputation.providers.filter((p) => p.status === "unavailable");
    if (unavailable.length > 0) {
      limitations.push(
        `${unavailable.length} reputation provider(s) could not be queried: ` +
          unavailable.map((p) => `${p.provider} (${p.error ?? "unavailable"})`).join(", ")
      );
    }
  }

  // ---- Score ----
  const totalImpact = riskFactors.reduce((sum, f) => sum + f.impact, 0);
  const trustScore = Math.max(0, Math.min(100, Math.round(100 - totalImpact)));

  // ---- Confidence ----
  const componentChecks: { name: string; ok: boolean }[] = [
    { name: "url", ok: true },
    { name: "dns", ok: dns.status === "ok" },
    { name: "tls", ok: tls.status === "ok" },
    { name: "redirects", ok: redirects.status === "ok" },
    { name: "website", ok: website.status === "ok" },
    { name: "reputation", ok: reputation.status === "ok" },
  ];
  const succeeded = componentChecks.filter((c) => c.ok).map((c) => c.name);
  const failed = componentChecks.filter((c) => !c.ok).map((c) => c.name);
  const overallConfidence = succeeded.length / componentChecks.length;

  const confidence: Confidence = {
    overall: Math.round(overallConfidence * 100) / 100,
    componentsSucceeded: succeeded,
    componentsFailed: failed,
  };

  let riskLevel: RiskLevel;
  if (confidence.overall < MIN_CONFIDENCE_FOR_VERDICT) {
    riskLevel = "INCONCLUSIVE";
  } else if (trustScore >= TRUST_SCORE_THRESHOLDS.low) {
    riskLevel = "LOW_OBSERVED_RISK";
  } else if (trustScore >= TRUST_SCORE_THRESHOLDS.moderate) {
    riskLevel = "MODERATE_OBSERVED_RISK";
  } else if (trustScore >= TRUST_SCORE_THRESHOLDS.elevated) {
    riskLevel = "ELEVATED_OBSERVED_RISK";
  } else {
    riskLevel = "HIGH_OBSERVED_RISK";
  }

  const recommendation = buildRecommendation(riskLevel, riskFactors);

  return { trustScore, riskLevel, confidence, riskFactors, positiveSignals, limitations, recommendation };
}

function buildRecommendation(level: RiskLevel, factors: RiskFactor[]): string {
  const hasCredentialRisk = factors.some(
    (f) => f.factor.toLowerCase().includes("login") || f.factor.toLowerCase().includes("payment")
  );

  switch (level) {
    case "HIGH_OBSERVED_RISK":
      return hasCredentialRisk
        ? "Multiple significant risk indicators were found, including a page that may request credentials or payment details. Avoid entering any personal, login, or payment information on this site."
        : "Multiple significant risk indicators were found. Proceed with caution and verify this site through another trusted channel before interacting with it.";
    case "ELEVATED_OBSERVED_RISK":
      return "Some indicators suggest elevated risk. Review the factors below before entering any sensitive information.";
    case "MODERATE_OBSERVED_RISK":
      return "A small number of moderate indicators were found. This is common for many legitimate sites, but worth a second look if you weren't expecting this destination.";
    case "LOW_OBSERVED_RISK":
      return "No significant risk indicators were found in this analysis. This does not guarantee the site is safe — automated analysis cannot detect every threat.";
    case "INCONCLUSIVE":
      return "Not enough data could be gathered to produce a reliable assessment. Treat this result as uninformative rather than reassuring.";
  }
}