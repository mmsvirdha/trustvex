export type RiskLevel =
  | "LOW_OBSERVED_RISK"
  | "MODERATE_OBSERVED_RISK"
  | "ELEVATED_OBSERVED_RISK"
  | "HIGH_OBSERVED_RISK"
  | "INCONCLUSIVE";

export type Severity = "LOW" | "MEDIUM" | "HIGH";

export interface RiskFactor {
  category: "URL" | "DOMAIN" | "DNS" | "TLS" | "REDIRECT" | "WEBSITE" | "REPUTATION";
  severity: Severity;
  factor: string;
  description: string;
  impact: number; // points subtracted from the trust score
  evidence: Record<string, unknown>;
}

export interface PositiveSignal {
  category: RiskFactor["category"];
  signal: string;
  description: string;
  evidence: Record<string, unknown>;
}

export interface UrlAnalysis {
  raw: string;
  protocol: string;
  hostname: string;
  rootDomain: string;
  subdomain: string;
  path: string;
  query: string;
  fragment: string;
  port: string | null;
  lengths: {
    url: number;
    hostname: number;
    path: number;
    query: number;
  };
  subdomainCount: number;
  digitCount: number;
  specialCharCount: number;
  flags: {
    isIpHostname: boolean;
    isPunycode: boolean;
    hasEmbeddedCredentials: boolean;
    hasUnusualPort: boolean;
    excessiveSubdomains: boolean;
    excessiveLength: boolean;
    suspiciousKeywords: string[];
  };
}

export interface DnsRecordResult<T> {
  status: "ok" | "empty" | "error";
  records: T[];
  error?: string;
}

export interface DnsAnalysis {
  status: "ok" | "unavailable";
  a: DnsRecordResult<string>;
  aaaa: DnsRecordResult<string>;
  cname: DnsRecordResult<string>;
  mx: DnsRecordResult<string>;
  ns: DnsRecordResult<string>;
  txt: DnsRecordResult<string>;
  caa: DnsRecordResult<string>;
  resolvedAddressCount: number;
}

export interface TlsAnalysis {
  status: "ok" | "unavailable" | "no_https";
  httpsAvailable: boolean;
  authorized: boolean | null;
  authorizationError: string | null;
  protocol: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  hostnameMatches: boolean | null;
  daysUntilExpiry: number | null;
  error?: string;
}

export interface RedirectHopResult {
  sequence: number;
  fromUrl: string;
  toUrl: string | null;
  status: number | null;
  hostname: string;
  crossDomain: boolean;
}

export interface RedirectAnalysis {
  status: "ok" | "unavailable";
  finalUrl: string | null;
  hopCount: number;
  crossDomainHopCount: number;
  chain: RedirectHopResult[];
  excessiveRedirects: boolean;
  error?: string;
}

export interface WebsiteAnalysis {
  status: "ok" | "unavailable" | "truncated";
  // "browser" = rendered in headless Chromium via Playwright (sees JS-injected content).
  // "static" = fallback regex/string parse of raw HTML only, used if the browser crawler fails.
  analysisMethod: "browser" | "static";
  title: string | null;
  metaDescription: string | null;
  formCount: number;
  passwordFieldCount: number;
  loginFormDetected: boolean;
  paymentKeywordDetected: boolean;
  iframeCount: number;
  externalIframeDomains: string[];
  scriptCount: number;
  externalScriptDomains: string[];
  linkCount: number;
  externalLinkDomainCount: number;
  downloadLinksDetected: string[];
  error?: string;
}

export interface ReputationProviderResult {
  provider: string;
  // "no_results" = provider answered, no record found (NOT the same as
  //                the site being clean — see reputationAnalyzer.ts)
  // "suspicious" = provider answered, positive threat match
  // "unavailable" = provider could not produce an answer
  status: "no_results" | "suspicious" | "unavailable";
  confidence: number;
  reference: string;
  /** ISO timestamp of when this lookup ran. */
  checkedAt?: string;
  /** Short error code/label when status is "unavailable". */
  error?: string;
  /** One-line summary safe to display in the UI. */
  summary?: string;
  /** Provider-specific tags, if any. */
  tags?: string[];
  /** Link back to the provider's public reference page, if available. */
  evidenceUrl?: string;
}


export interface ReputationAnalysis {
  status: "ok" | "unavailable";
  providers: ReputationProviderResult[];
  note: string;
}

export interface Confidence {
  overall: number; // 0-1
  componentsSucceeded: string[];
  componentsFailed: string[];
}

/**
 * Result of the ML prediction call (milestone D2).
 *
 * status semantics:
 *   "ok"          -> the ML service returned a prediction; see riskProbability
 *   "unavailable" -> the service was unreachable, timed out, or returned an
 *                    error. See `error` for the reason. This is NOT treated
 *                    as a prediction of 0 or 0.5 — it is genuinely unknown.
 *
 * The report always distinguishes "we asked and got an answer" from
 * "we couldn't ask". Missing evidence is not the same as benign evidence.
 */
export interface MLPrediction {
  status: "ok" | "unavailable";
  /** Populated only when status === "ok". In [0, 1]. Higher = riskier. */
  riskProbability?: number;
  /** Identifier for the model that produced the prediction. "stub" during D2. */
  modelVersion?: string;
  /** ISO timestamp of when the prediction was requested. */
  checkedAt: string;
  /** Present only when status === "unavailable". Safe to display. */
  error?: string;
}

export interface ScanReport {
  id: string;
  submittedUrl: string;
  createdAt: string;
  featureVersion: string;
  riskEngineVersion: string;
  trustScore: number;
  riskLevel: RiskLevel;
  confidence: Confidence;
  riskFactors: RiskFactor[];
  positiveSignals: PositiveSignal[];
  url: UrlAnalysis;
  dns: DnsAnalysis;
  tls: TlsAnalysis;
  redirects: RedirectAnalysis;
  website: WebsiteAnalysis;
  reputation: ReputationAnalysis;
  limitations: string[];
  recommendation: string;
  features?: {
    schemaVersion: string;
    features: Record<string, number | boolean | null>;
    populatedCount: number;
    missingCount: number;
  };
  /**
   * ML prediction from the Python service (milestone D2). Optional so
   * reports saved before D2 continue to load and render.
   */
  mlResult?: MLPrediction;
}

export interface ScanListItem {
  id: string;
  url: string;
  hostname: string;
  trustScore: number;
  riskLevel: RiskLevel;
  createdAt: string;
}
