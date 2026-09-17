// src/lib/features/featureSchema.ts
//
// The declarative schema for TRUSTVEX feature vector v1.0.
//
// Every feature the extractor produces MUST be declared here. The
// extractor iterates over FEATURE_SCHEMA to build its output, so adding
// a feature is a matter of adding one row and implementing its mapping
// in extractFeatures.ts.
//
// Versioning: bump FEATURE_SCHEMA_VERSION when you add, remove, or
// rename any feature. Old stored reports keep their original version;
// the extraction code only ever produces the current version.

import type { FeatureDefinition } from "./types";

export const FEATURE_SCHEMA_VERSION = "1.0";

export const FEATURE_SCHEMA: readonly FeatureDefinition[] = [
  // ---------- URL ----------
  { name: "url_length", category: "URL", type: "number", canBeMissing: false,
    description: "Total length of the submitted URL in characters." },
  { name: "hostname_length", category: "URL", type: "number", canBeMissing: false,
    description: "Length of the hostname portion of the URL." },
  { name: "path_length", category: "URL", type: "number", canBeMissing: false,
    description: "Length of the URL path (after hostname, before query)." },
  { name: "query_length", category: "URL", type: "number", canBeMissing: false,
    description: "Length of the query string (after ?)." },
  { name: "subdomain_count", category: "URL", type: "number", canBeMissing: false,
    description: "Number of subdomain labels before the root domain." },
  { name: "digit_count", category: "URL", type: "number", canBeMissing: false,
    description: "Number of digit characters in the full URL." },
  { name: "special_char_count", category: "URL", type: "number", canBeMissing: false,
    description: "Number of non-alphanumeric characters outside normal URL punctuation." },
  { name: "has_ip_hostname", category: "URL", type: "boolean", canBeMissing: false,
    description: "True if the URL uses a raw IP address instead of a domain name." },
  { name: "has_punycode", category: "URL", type: "boolean", canBeMissing: false,
    description: "True if the hostname contains punycode (xn--) labels." },
  { name: "has_embedded_credentials", category: "URL", type: "boolean", canBeMissing: false,
    description: "True if the URL includes a user:password@ segment." },
  { name: "has_unusual_port", category: "URL", type: "boolean", canBeMissing: false,
    description: "True if the URL specifies a port other than 80 or 443." },
  { name: "suspicious_keyword_count", category: "URL", type: "number", canBeMissing: false,
    description: "Count of phishing-associated keywords found in the URL." },

  // ---------- DNS ----------
  { name: "dns_status_ok", category: "DNS", type: "boolean", canBeMissing: false,
    description: "True if DNS resolution produced at least one A or AAAA record." },
  { name: "a_record_count", category: "DNS", type: "number", canBeMissing: true,
    description: "Number of A records. Null if the A lookup failed." },
  { name: "aaaa_record_count", category: "DNS", type: "number", canBeMissing: true,
    description: "Number of AAAA records. Null if the AAAA lookup failed." },
  { name: "has_mx_record", category: "DNS", type: "boolean", canBeMissing: true,
    description: "True if at least one MX record was returned. Null if the MX lookup failed." },
  { name: "has_caa_record", category: "DNS", type: "boolean", canBeMissing: true,
    description: "True if at least one CAA record was returned. Null if the CAA lookup failed." },

  // ---------- TLS ----------
  { name: "submitted_over_https", category: "TLS", type: "boolean", canBeMissing: false,
    description: "True if the submitted URL uses https://." },
  { name: "tls_status_ok", category: "TLS", type: "boolean", canBeMissing: false,
    description: "True if the TLS handshake completed successfully." },
  { name: "tls_authorized", category: "TLS", type: "boolean", canBeMissing: true,
    description: "True if the certificate validated against the default trust store. Null if TLS failed." },
  { name: "tls_hostname_matches", category: "TLS", type: "boolean", canBeMissing: true,
    description: "True if the certificate subject matches the hostname. Null if TLS failed." },
  { name: "tls_days_until_expiry", category: "TLS", type: "number", canBeMissing: true,
    description: "Days until the certificate expires. Null if TLS failed." },
  { name: "tls_expires_soon", category: "TLS", type: "boolean", canBeMissing: true,
    description: "True if the certificate expires within 7 days. Null if expiry is unknown." },
  { name: "tls_https_available", category: "TLS", type: "boolean", canBeMissing: false,
    description: "True if a TLS handshake succeeded on port 443." },

  // ---------- REDIRECT ----------
  { name: "redirect_hop_count", category: "REDIRECT", type: "number", canBeMissing: true,
    description: "Number of redirects in the chain. Null if the page could not be loaded." },
  { name: "cross_domain_hop_count", category: "REDIRECT", type: "number", canBeMissing: true,
    description: "Number of redirects that changed domain. Null if the page could not be loaded." },
  { name: "has_redirect_chain", category: "REDIRECT", type: "boolean", canBeMissing: true,
    description: "True if any redirect occurred. Null if the page could not be loaded." },

  // ---------- WEBSITE ----------
  { name: "crawler_status_ok", category: "WEBSITE", type: "boolean", canBeMissing: false,
    description: "True if the browser crawler produced a usable DOM (ok or truncated)." },
  { name: "form_count", category: "WEBSITE", type: "number", canBeMissing: true,
    description: "Number of <form> elements in the rendered DOM. Null if the crawler failed." },
  { name: "password_field_count", category: "WEBSITE", type: "number", canBeMissing: true,
    description: "Number of password input fields. Null if the crawler failed." },
  { name: "login_form_detected", category: "WEBSITE", type: "boolean", canBeMissing: true,
    description: "True if a login form was detected. Null if the crawler failed." },
  { name: "payment_keyword_detected", category: "WEBSITE", type: "boolean", canBeMissing: true,
    description: "True if payment-related keywords were found. Null if the crawler failed." },
  { name: "iframe_count", category: "WEBSITE", type: "number", canBeMissing: true,
    description: "Number of <iframe> elements. Null if the crawler failed." },
  { name: "external_iframe_domain_count", category: "WEBSITE", type: "number", canBeMissing: true,
    description: "Number of distinct external domains in iframes. Null if the crawler failed." },
  { name: "script_count", category: "WEBSITE", type: "number", canBeMissing: true,
    description: "Number of <script> elements. Null if the crawler failed." },
  { name: "external_script_domain_count", category: "WEBSITE", type: "number", canBeMissing: true,
    description: "Number of distinct external domains for scripts. Null if the crawler failed." },
  { name: "has_download_links", category: "WEBSITE", type: "boolean", canBeMissing: true,
    description: "True if the page links to executable/archive files. Null if the crawler failed." },

  // ---------- REPUTATION ----------
  { name: "reputation_provider_count", category: "REPUTATION", type: "number", canBeMissing: false,
    description: "Number of reputation providers configured and queried." },
  { name: "reputation_any_suspicious", category: "REPUTATION", type: "boolean", canBeMissing: true,
    description: "True if any provider flagged the URL as suspicious. Null if no providers were registered." },
  { name: "reputation_any_no_results", category: "REPUTATION", type: "boolean", canBeMissing: true,
    description: "True if any provider returned 'no results'. Null if no providers were registered." },
  { name: "reputation_any_unavailable", category: "REPUTATION", type: "boolean", canBeMissing: true,
    description: "True if any provider could not be queried. Null if no providers were registered." },

  // ---------- CONFIDENCE ----------
  { name: "confidence_overall", category: "CONFIDENCE", type: "number", canBeMissing: false,
    description: "Overall confidence (0-1) that the analysis is representative." },
  { name: "components_failed_count", category: "CONFIDENCE", type: "number", canBeMissing: false,
    description: "Number of analysis components that could not complete." },

  // ---------- RISK_SUMMARY ----------
  { name: "risk_factor_count", category: "RISK_SUMMARY", type: "number", canBeMissing: false,
    description: "Number of risk factors produced by the rule engine." },
  { name: "positive_signal_count", category: "RISK_SUMMARY", type: "number", canBeMissing: false,
    description: "Number of positive signals produced by the rule engine." },
];

/** Fast lookup: feature name -> definition. */
export const FEATURE_SCHEMA_BY_NAME: ReadonlyMap<string, FeatureDefinition> =
  new Map(FEATURE_SCHEMA.map((f) => [f.name, f]));

/** Declared feature count — kept in sync with FEATURE_SCHEMA by construction. */
export const FEATURE_COUNT = FEATURE_SCHEMA.length;