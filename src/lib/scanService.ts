import { randomUUID } from "node:crypto";
import { analyzeUrl } from "./analyzers/urlAnalyzer";
import { analyzeDns } from "./analyzers/dnsAnalyzer";
import { analyzeTls } from "./analyzers/tlsAnalyzer";
import { analyzeRedirects } from "./analyzers/redirectAnalyzer";
import { analyzeWebsite } from "./analyzers/websiteAnalyzer";
import { analyzeWebsiteWithBrowser } from "./analyzers/browserWebsiteAnalyzer";
import { analyzeReputation } from "./analyzers/reputationAnalyzer";
import { safeFetch, SafeFetchResult } from "./security/safeFetch";
import { runRiskEngine } from "./riskEngine";
import { FEATURE_VERSION, RISK_ENGINE_VERSION } from "./riskConfig";
import { ScanReport } from "./types";
import { saveScan } from "./db";
import { extractFeatures } from "./features/extractFeatures";
import { predictRisk } from "./ml/mlClient";


export class InvalidUrlError extends Error {}

function normalizeAndValidate(rawInput: string): string {
  const trimmed = rawInput.trim();
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withProtocol);
  } catch {
    throw new InvalidUrlError("That doesn't look like a valid URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new InvalidUrlError("Only http:// and https:// URLs can be analyzed.");
  }
  if (!url.hostname || !url.hostname.includes(".")) {
    if (url.hostname !== "localhost") {
      // allow bare IPs/hostnames through to the SSRF guard, which will
      // reject private ones with a clear reason
    }
  }
  return url.toString();
}

export async function runScan(rawInput: string): Promise<ScanReport> {
  const submittedUrl = normalizeAndValidate(rawInput);
  const urlAnalysis = analyzeUrl(submittedUrl);

  // Single network fetch shared by the redirect analyzer and the website
  // analyzer, so we don't hit the target twice.
  let fetchResult: SafeFetchResult | null = null;
  let fetchError: string | null = null;
  try {
    fetchResult = await safeFetch(submittedUrl, { method: "GET" });
  } catch (err) {
    fetchError = err instanceof Error ? err.message : String(err);
  }

  const [dnsAnalysis, tlsAnalysis] = await Promise.all([
    analyzeDns(urlAnalysis.hostname).catch(() => ({
      status: "unavailable" as const,
      a: { status: "error" as const, records: [], error: "lookup failed" },
      aaaa: { status: "error" as const, records: [], error: "lookup failed" },
      cname: { status: "error" as const, records: [], error: "lookup failed" },
      mx: { status: "error" as const, records: [], error: "lookup failed" },
      ns: { status: "error" as const, records: [], error: "lookup failed" },
      txt: { status: "error" as const, records: [], error: "lookup failed" },
      caa: { status: "error" as const, records: [], error: "lookup failed" },
      resolvedAddressCount: 0,
    })),
    analyzeTls(urlAnalysis.hostname),
  ]);

    const redirectAnalysis = analyzeRedirects(submittedUrl, fetchResult, fetchError);

  // Prefer the real-browser crawler (sees JS-rendered content); fall back
  // to the static HTML parser only if the browser crawler itself throws
  // (e.g. Chromium isn't installed yet — see README). A normal navigation
  // failure (site down, timeout) is NOT an exception here — it comes back
  // as a status: "unavailable" WebsiteAnalysis from analyzeWebsiteWithBrowser
  // itself, same contract the risk engine already expects.
  let websiteAnalysis;
  try {
    websiteAnalysis = await analyzeWebsiteWithBrowser(
      redirectAnalysis.finalUrl ?? submittedUrl
    );
  } catch (err) {
    console.error(
      "Browser crawler unavailable, falling back to static HTML analysis:",
      err
    );
    websiteAnalysis = analyzeWebsite(submittedUrl, fetchResult, fetchError);
  }

  const reputationAnalysis = await analyzeReputation(urlAnalysis.hostname, submittedUrl);

  const engineResult = runRiskEngine({
    url: urlAnalysis,
    dns: dnsAnalysis,
    tls: tlsAnalysis,
    redirects: redirectAnalysis,
    website: websiteAnalysis,
    reputation: reputationAnalysis,
  });

    const report: ScanReport = {
    id: randomUUID(),
    submittedUrl,
    createdAt: new Date().toISOString(),
    featureVersion: FEATURE_VERSION,
    riskEngineVersion: RISK_ENGINE_VERSION,
    url: urlAnalysis,
    dns: dnsAnalysis,
    tls: tlsAnalysis,
    redirects: redirectAnalysis,
    website: websiteAnalysis,
    reputation: reputationAnalysis,
    ...engineResult,
  };

  // Feature extraction runs after the risk engine so that the
  // risk_factor_count / positive_signal_count features reflect the
  // engine's final output. The extractor is pure and never throws for
  // well-formed reports.
   report.features = extractFeatures(report);

  // Best-effort ML prediction. Never throws — see mlClient.ts. The scan
  // completes normally regardless of whether the ML service is reachable.
  report.mlResult = await predictRisk(
    report.features.schemaVersion,
    report.features.features
  );

  saveScan(report);
  return report;
}
