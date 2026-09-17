// tests/features/extractFeatures.test.ts
//
// Unit tests for the pure feature-extraction function. No network,
// no database, no browser. Every test constructs a ScanReport-shaped
// object literal and checks the resulting features.

import { test } from "node:test";
import assert from "node:assert/strict";

import { extractFeatures } from "../../src/lib/features/extractFeatures";
import { FEATURE_SCHEMA, FEATURE_COUNT, FEATURE_SCHEMA_VERSION } from "../../src/lib/features/featureSchema";
import type {
  ScanReport,
  RiskLevel,
} from "../../src/lib/types";

// --- Minimal Report Builder ---
// Each test starts from this and overrides only the parts it cares about.

function baseReport(overrides: Partial<ScanReport> = {}): ScanReport {
  const base: ScanReport = {
    id: "test",
    submittedUrl: "https://example.com/",
    createdAt: "2026-01-01T00:00:00.000Z",
    featureVersion: "1.0",
    riskEngineVersion: "1.0",
    trustScore: 100,
    riskLevel: "LOW_OBSERVED_RISK" as RiskLevel,
    confidence: { overall: 1.0, componentsSucceeded: ["url", "dns", "tls", "redirects", "website", "reputation"], componentsFailed: [] },
    riskFactors: [],
    positiveSignals: [],
    url: {
      raw: "https://example.com/",
      protocol: "https",
      hostname: "example.com",
      rootDomain: "example.com",
      subdomain: "",
      path: "/",
      query: "",
      fragment: "",
      port: null,
      lengths: { url: 20, hostname: 11, path: 1, query: 0 },
      subdomainCount: 0,
      digitCount: 0,
      specialCharCount: 0,
      flags: {
        isIpHostname: false,
        isPunycode: false,
        hasEmbeddedCredentials: false,
        hasUnusualPort: false,
        excessiveSubdomains: false,
        excessiveLength: false,
        suspiciousKeywords: [],
      },
    },
    dns: {
      status: "ok",
      a: { status: "ok", records: ["1.2.3.4"] },
      aaaa: { status: "empty", records: [] },
      cname: { status: "empty", records: [] },
      mx: { status: "empty", records: [] },
      ns: { status: "ok", records: ["ns.example.com"] },
      txt: { status: "empty", records: [] },
      caa: { status: "empty", records: [] },
      resolvedAddressCount: 1,
    },
    tls: {
      status: "ok",
      httpsAvailable: true,
      authorized: true,
      authorizationError: null,
      protocol: "TLSv1.3",
      issuer: "Test CA",
      subject: "CN=example.com",
      validFrom: "2026-01-01",
      validTo: "2027-01-01",
      hostnameMatches: true,
      daysUntilExpiry: 365,
    },
    redirects: {
      status: "ok",
      finalUrl: "https://example.com/",
      hopCount: 0,
      crossDomainHopCount: 0,
      chain: [],
      excessiveRedirects: false,
    },
    website: {
      status: "ok",
      analysisMethod: "browser",
      title: "Example",
      metaDescription: null,
      formCount: 0,
      passwordFieldCount: 0,
      loginFormDetected: false,
      paymentKeywordDetected: false,
      iframeCount: 0,
      externalIframeDomains: [],
      scriptCount: 0,
      externalScriptDomains: [],
      linkCount: 0,
      externalLinkDomainCount: 0,
      downloadLinksDetected: [],
    },
    reputation: {
      status: "ok",
      providers: [
        {
          provider: "urlhaus",
          status: "no_results",
          confidence: 0.5,
          reference: "URLhaus has no matching record for this URL.",
        },
      ],
      note: "",
    },
    limitations: [],
    recommendation: "",
  };
  return { ...base, ...overrides };
}

// --- Tests ---

test("schema declares exactly 45 features", () => {
  assert.equal(FEATURE_COUNT, 45);
  assert.equal(FEATURE_SCHEMA.length, 45);
});

test("schema version is 1.0", () => {
  assert.equal(FEATURE_SCHEMA_VERSION, "1.0");
});

test("complete HTTPS report produces 45 populated features and 0 missing", () => {
  const result = extractFeatures(baseReport());
  assert.equal(result.schemaVersion, "1.0");
  assert.equal(Object.keys(result.features).length, 45);
  assert.equal(result.populatedCount + result.missingCount, 45);
});

test("deterministic: identical reports produce identical feature objects", () => {
  const r = baseReport();
  const a = extractFeatures(r);
  const b = extractFeatures(r);
  assert.deepEqual(a, b);
});

test("HTTP-submitted URL produces submitted_over_https === false", () => {
  const report = baseReport({
    url: {
      ...baseReport().url,
      protocol: "http",
      raw: "http://example.com/",
    },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.submitted_over_https, false);
});

test("IP hostname flag propagates", () => {
  const report = baseReport({
    url: {
      ...baseReport().url,
      flags: { ...baseReport().url.flags, isIpHostname: true },
    },
  });
  assert.equal(extractFeatures(report).features.has_ip_hostname, true);
});

test("punycode flag propagates", () => {
  const report = baseReport({
    url: {
      ...baseReport().url,
      flags: { ...baseReport().url.flags, isPunycode: true },
    },
  });
  assert.equal(extractFeatures(report).features.has_punycode, true);
});

test("embedded credentials flag propagates", () => {
  const report = baseReport({
    url: {
      ...baseReport().url,
      flags: { ...baseReport().url.flags, hasEmbeddedCredentials: true },
    },
  });
  assert.equal(extractFeatures(report).features.has_embedded_credentials, true);
});

test("suspicious keyword count reflects the list length", () => {
  const report = baseReport({
    url: {
      ...baseReport().url,
      flags: { ...baseReport().url.flags, suspiciousKeywords: ["login", "verify", "secure"] },
    },
  });
  assert.equal(extractFeatures(report).features.suspicious_keyword_count, 3);
});

test("redirect hop count and has_redirect_chain", () => {
  const report = baseReport({
    redirects: {
      status: "ok",
      finalUrl: "https://example.com/",
      hopCount: 2,
      crossDomainHopCount: 1,
      chain: [],
      excessiveRedirects: false,
    },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.redirect_hop_count, 2);
  assert.equal(result.features.cross_domain_hop_count, 1);
  assert.equal(result.features.has_redirect_chain, true);
});

test("DNS A/AAAA counts and MX/CAA booleans", () => {
  const report = baseReport({
    dns: {
      status: "ok",
      a: { status: "ok", records: ["1.1.1.1", "2.2.2.2"] },
      aaaa: { status: "ok", records: ["::1"] },
      cname: { status: "empty", records: [] },
      mx: { status: "ok", records: ["10 mail.example.com"] },
      ns: { status: "empty", records: [] },
      txt: { status: "empty", records: [] },
      caa: { status: "ok", records: ["0 issue \"letsencrypt.org\""] },
      resolvedAddressCount: 3,
    },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.a_record_count, 2);
  assert.equal(result.features.aaaa_record_count, 1);
  assert.equal(result.features.has_mx_record, true);
  assert.equal(result.features.has_caa_record, true);
});

test("DNS unavailable sets MX/CAA to null, not false", () => {
  const report = baseReport({
    dns: {
      status: "unavailable",
      a: { status: "error", records: [], error: "timeout" },
      aaaa: { status: "error", records: [], error: "timeout" },
      cname: { status: "error", records: [], error: "timeout" },
      mx: { status: "error", records: [], error: "timeout" },
      ns: { status: "error", records: [], error: "timeout" },
      txt: { status: "error", records: [], error: "timeout" },
      caa: { status: "error", records: [], error: "timeout" },
      resolvedAddressCount: 0,
    },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.has_mx_record, null);
  assert.equal(result.features.has_caa_record, null);
  assert.equal(result.features.a_record_count, null);
  assert.equal(result.features.aaaa_record_count, null);
});

test("TLS unavailable sets nullable fields to null", () => {
  const report = baseReport({
    tls: {
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
      error: "timeout",
    },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.tls_status_ok, false);
  assert.equal(result.features.tls_authorized, null);
  assert.equal(result.features.tls_hostname_matches, null);
  assert.equal(result.features.tls_days_until_expiry, null);
  assert.equal(result.features.tls_expires_soon, null);
});

test("TLS expires_soon is true for a cert with <= 7 days", () => {
  const report = baseReport({
    tls: { ...baseReport().tls, daysUntilExpiry: 3 },
  });
  assert.equal(extractFeatures(report).features.tls_expires_soon, true);
});

test("TLS expires_soon is false for a cert with > 7 days", () => {
  const report = baseReport({
    tls: { ...baseReport().tls, daysUntilExpiry: 90 },
  });
  assert.equal(extractFeatures(report).features.tls_expires_soon, false);
});

test("Website unavailable sets every page feature to null", () => {
  const report = baseReport({
    website: {
      status: "unavailable",
      analysisMethod: "browser",
      title: null,
      metaDescription: null,
      formCount: 0,
      passwordFieldCount: 0,
      loginFormDetected: false,
      paymentKeywordDetected: false,
      iframeCount: 0,
      externalIframeDomains: [],
      scriptCount: 0,
      externalScriptDomains: [],
      linkCount: 0,
      externalLinkDomainCount: 0,
      downloadLinksDetected: [],
      error: "navigation timeout",
    },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.crawler_status_ok, false);
  assert.equal(result.features.form_count, null);
  assert.equal(result.features.password_field_count, null);
  assert.equal(result.features.login_form_detected, null);
  assert.equal(result.features.iframe_count, null);
  assert.equal(result.features.has_download_links, null);
});

test("measured zero vs null: form_count === 0 is not null", () => {
  const report = baseReport({
    website: { ...baseReport().website, formCount: 0, status: "ok" },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.form_count, 0);
  assert.notEqual(result.features.form_count, null);
});

test("no reputation providers -> suspicious/no_results/unavailable all null", () => {
  const report = baseReport({
    reputation: {
      status: "unavailable",
      providers: [],
      note: "no providers configured",
    },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.reputation_provider_count, 0);
  assert.equal(result.features.reputation_any_suspicious, null);
  assert.equal(result.features.reputation_any_no_results, null);
  assert.equal(result.features.reputation_any_unavailable, null);
});

test("URLhaus no_results -> any_no_results true, any_suspicious false", () => {
  const result = extractFeatures(baseReport());
  assert.equal(result.features.reputation_any_no_results, true);
  assert.equal(result.features.reputation_any_suspicious, false);
  assert.equal(result.features.reputation_any_unavailable, false);
});

test("URLhaus suspicious -> any_suspicious true", () => {
  const report = baseReport({
    reputation: {
      status: "ok",
      providers: [
        { provider: "urlhaus", status: "suspicious", confidence: 0.9, reference: "ref" },
      ],
      note: "",
    },
  });
  assert.equal(extractFeatures(report).features.reputation_any_suspicious, true);
});

test("risk_factor_count and positive_signal_count reflect the report", () => {
  const report = baseReport({
    riskFactors: [
      { category: "URL", severity: "LOW", factor: "x", description: "", impact: 1, evidence: {} },
    ],
    positiveSignals: [
      { category: "URL", signal: "y", description: "", evidence: {} },
      { category: "URL", signal: "z", description: "", evidence: {} },
    ],
  });
  const result = extractFeatures(report);
  assert.equal(result.features.risk_factor_count, 1);
  assert.equal(result.features.positive_signal_count, 2);
});

test("confidence_overall and components_failed_count propagate", () => {
  const report = baseReport({
    confidence: {
      overall: 0.67,
      componentsSucceeded: ["url", "dns", "tls", "redirects"],
      componentsFailed: ["website", "reputation"],
    },
  });
  const result = extractFeatures(report);
  assert.equal(result.features.confidence_overall, 0.67);
  assert.equal(result.features.components_failed_count, 2);
});

test("every declared feature is present in the produced vector", () => {
  const result = extractFeatures(baseReport());
  for (const def of FEATURE_SCHEMA) {
    assert.ok(def.name in result.features, `missing feature: ${def.name}`);
  }
});

test("produced vector contains no undeclared features", () => {
  const result = extractFeatures(baseReport());
  const declared = new Set(FEATURE_SCHEMA.map((f) => f.name));
  for (const name of Object.keys(result.features)) {
    assert.ok(declared.has(name), `undeclared feature produced: ${name}`);
  }
});