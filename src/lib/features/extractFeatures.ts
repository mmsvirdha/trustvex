// src/lib/features/extractFeatures.ts
//
// Pure function: ScanReport -> FeatureExtractionResult.
//
// Design constraints (these matter):
// - No network, filesystem, DB, or Playwright calls.
// - Deterministic output — same report in, same features out.
// - Never invent a value the source analyzer did not produce. A null
//   here means "not measured", not "assume zero".
// - Independent of the risk engine's scoring: we extract facts, we do
//   not re-derive decisions.

import type { ScanReport } from "../types";
import {
  FEATURE_SCHEMA,
  FEATURE_SCHEMA_VERSION,
  FEATURE_COUNT,
} from "./featureSchema";
import type {
  FeatureExtractionResult,
  FeatureVector,
} from "./types";

function nonEmpty<T>(arr: T[] | undefined | null): boolean {
  return Array.isArray(arr) && arr.length > 0;
}

export function extractFeatures(report: ScanReport): FeatureExtractionResult {
  const { url, dns, tls, redirects, website, reputation, confidence,
          riskFactors, positiveSignals } = report;

  const features: FeatureVector = {};

  // ---------- URL ----------
  features.url_length = url.lengths.url;
  features.hostname_length = url.lengths.hostname;
  features.path_length = url.lengths.path;
  features.query_length = url.lengths.query;
  features.subdomain_count = url.subdomainCount;
  features.digit_count = url.digitCount;
  features.special_char_count = url.specialCharCount;
  features.has_ip_hostname = url.flags.isIpHostname;
  features.has_punycode = url.flags.isPunycode;
  features.has_embedded_credentials = url.flags.hasEmbeddedCredentials;
  features.has_unusual_port = url.flags.hasUnusualPort;
  features.suspicious_keyword_count = url.flags.suspiciousKeywords.length;

  // ---------- DNS ----------
  features.dns_status_ok = dns.status === "ok";
  features.a_record_count = dns.a.status === "error" ? null : dns.a.records.length;
  features.aaaa_record_count = dns.aaaa.status === "error" ? null : dns.aaaa.records.length;
  features.has_mx_record = dns.mx.status === "error" ? null : nonEmpty(dns.mx.records);
  features.has_caa_record = dns.caa.status === "error" ? null : nonEmpty(dns.caa.records);

  // ---------- TLS ----------
  const tlsOk = tls.status === "ok";
  features.submitted_over_https = url.protocol === "https";
  features.tls_status_ok = tlsOk;
  features.tls_authorized = tlsOk ? tls.authorized : null;
  features.tls_hostname_matches = tlsOk ? tls.hostnameMatches : null;
  features.tls_days_until_expiry = tlsOk ? tls.daysUntilExpiry : null;
  features.tls_expires_soon =
    tlsOk && tls.daysUntilExpiry !== null ? tls.daysUntilExpiry <= 7 : null;
  features.tls_https_available = tls.httpsAvailable;

  // ---------- REDIRECT ----------
  const redirectsOk = redirects.status === "ok";
  features.redirect_hop_count = redirectsOk ? redirects.hopCount : null;
  features.cross_domain_hop_count = redirectsOk ? redirects.crossDomainHopCount : null;
  features.has_redirect_chain = redirectsOk ? redirects.hopCount > 0 : null;

  // ---------- WEBSITE ----------
  const crawlerOk = website.status === "ok" || website.status === "truncated";
  features.crawler_status_ok = crawlerOk;
  features.form_count = crawlerOk ? website.formCount : null;
  features.password_field_count = crawlerOk ? website.passwordFieldCount : null;
  features.login_form_detected = crawlerOk ? website.loginFormDetected : null;
  features.payment_keyword_detected = crawlerOk ? website.paymentKeywordDetected : null;
  features.iframe_count = crawlerOk ? website.iframeCount : null;
  features.external_iframe_domain_count = crawlerOk ? website.externalIframeDomains.length : null;
  features.script_count = crawlerOk ? website.scriptCount : null;
  features.external_script_domain_count = crawlerOk ? website.externalScriptDomains.length : null;
  features.has_download_links = crawlerOk ? website.downloadLinksDetected.length > 0 : null;

  // ---------- REPUTATION ----------
  const providerCount = reputation.providers.length;
  features.reputation_provider_count = providerCount;
  if (providerCount === 0) {
    features.reputation_any_suspicious = null;
    features.reputation_any_no_results = null;
    features.reputation_any_unavailable = null;
  } else {
    features.reputation_any_suspicious =
      reputation.providers.some((p) => p.status === "suspicious");
    features.reputation_any_no_results =
      reputation.providers.some((p) => p.status === "no_results");
    features.reputation_any_unavailable =
      reputation.providers.some((p) => p.status === "unavailable");
  }

  // ---------- CONFIDENCE ----------
  features.confidence_overall = confidence.overall;
  features.components_failed_count = confidence.componentsFailed.length;

  // ---------- RISK_SUMMARY ----------
  features.risk_factor_count = riskFactors.length;
  features.positive_signal_count = positiveSignals.length;

  // Sanity: every declared feature must have been populated by name.
  // If this throws, a schema entry was added without an extractor line.
  for (const def of FEATURE_SCHEMA) {
    if (!(def.name in features)) {
      throw new Error(
        `extractFeatures: schema declares "${def.name}" but the extractor did not assign it. ` +
          `Every FEATURE_SCHEMA entry must have a corresponding assignment.`
      );
    }
  }

  // Sanity: no extra features were assigned that aren't declared.
  const declaredNames = new Set(FEATURE_SCHEMA.map((f) => f.name));
  for (const name of Object.keys(features)) {
    if (!declaredNames.has(name)) {
      throw new Error(
        `extractFeatures: assigned "${name}" but it is not declared in FEATURE_SCHEMA.`
      );
    }
  }

  let populatedCount = 0;
  let missingCount = 0;
  for (const name of Object.keys(features)) {
    if (features[name] === null) missingCount++;
    else populatedCount++;
  }

  // Guard against the schema being changed without a version bump.
  if (FEATURE_COUNT !== Object.keys(features).length) {
    throw new Error(
      `extractFeatures: FEATURE_COUNT (${FEATURE_COUNT}) does not match produced key count ` +
        `(${Object.keys(features).length}). Schema and extractor are out of sync.`
    );
  }

  return {
    schemaVersion: FEATURE_SCHEMA_VERSION,
    features,
    populatedCount,
    missingCount,
  };
}