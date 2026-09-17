export const FEATURE_VERSION = "1.0";
export const RISK_ENGINE_VERSION = "1.0";


// Trust score starts at 100 and risk factors subtract from it (floored at 0).
export const TRUST_SCORE_THRESHOLDS = {
  low: 80, // score >= 80        -> LOW_OBSERVED_RISK
  moderate: 60, // 60 <= score < 80  -> MODERATE_OBSERVED_RISK
  elevated: 40, // 40 <= score < 60  -> ELEVATED_OBSERVED_RISK
  // score < 40                  -> HIGH_OBSERVED_RISK
};

// Below this overall confidence, the report is reported as INCONCLUSIVE
// regardless of the numeric score, because too little evidence was gathered
// to trust the score at all.
export const MIN_CONFIDENCE_FOR_VERDICT = 0.35;

export const IMPACT = {
  URL_IS_IP_HOSTNAME: 15,
  URL_PUNYCODE: 10,
  URL_EMBEDDED_CREDENTIALS: 20,
  URL_UNUSUAL_PORT: 8,
  URL_EXCESSIVE_SUBDOMAINS: 10,
  URL_EXCESSIVE_LENGTH: 6,
  URL_SUSPICIOUS_KEYWORDS: 5, // per keyword, capped
  URL_SUSPICIOUS_KEYWORDS_CAP: 15,

  DNS_UNAVAILABLE: 8,
  DNS_NO_CAA: 2,

  TLS_NO_HTTPS: 20,
  TLS_UNAUTHORIZED: 18,
  TLS_HOSTNAME_MISMATCH: 18,
  TLS_EXPIRING_SOON: 6, // < 7 days
  TLS_UNAVAILABLE: 10,

  REDIRECT_EXCESSIVE: 10,
  REDIRECT_CROSS_DOMAIN_PER_HOP: 4,
  REDIRECT_CROSS_DOMAIN_CAP: 16,
  REDIRECT_UNAVAILABLE: 5,

  WEBSITE_LOGIN_FORM: 6,
  WEBSITE_LOGIN_FORM_NON_HTTPS: 20,
  WEBSITE_PAYMENT_KEYWORDS: 10,
  WEBSITE_MANY_EXTERNAL_SCRIPTS: 6, // > 5 external script domains
  WEBSITE_DOWNLOAD_LINKS: 10,
  WEBSITE_UNAVAILABLE: 6,

  REPUTATION_SUSPICIOUS_PER_PROVIDER: 25,
} as const;

export const POSITIVE = {
  VALID_HTTPS: 1,
  NO_REDIRECTS: 1,
  NO_SUSPICIOUS_KEYWORDS: 1,
  CAA_PRESENT: 1,
  REPUTATION_NO_MATCH: 1,
} as const;
