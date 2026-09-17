// src/lib/analyzers/reputationAnalyzer.ts
//
// Thin adapter between the reputation provider registry and the rest of
// TRUSTVEX. Its job: call the registry, then translate the normalized
// ReputationEvidence[] into the ReputationAnalysis shape the risk engine
// consumes.

import {
  ReputationAnalysis,
  ReputationProviderResult,
} from "../types";
import { listProviders, runAllProviders } from "../reputation/registry";

function toProviderResult(
  evidence: Awaited<ReturnType<typeof runAllProviders>>[number]
): ReputationProviderResult {
  // Preserve the three-way distinction. "clean" from a provider
  // specifically means "no matching record" (see urlhaus.ts) — we surface
  // that as "no_results", not as "clean", to keep the UI honest.
  let status: ReputationProviderResult["status"];
  switch (evidence.status) {
    case "suspicious":
      status = "suspicious";
      break;
    case "clean":
      status = "no_results";
      break;
    case "unavailable":
      status = "unavailable";
      break;
  }

  return {
    provider: evidence.provider,
    status,
    confidence: evidence.confidence,
    reference: evidence.evidenceUrl ?? evidence.summary,
    checkedAt: evidence.checkedAt,
    error: evidence.error,
    summary: evidence.summary,
    tags: evidence.tags,
    evidenceUrl: evidence.evidenceUrl,
  };
}

export async function analyzeReputation(
  hostname: string,
  submittedUrl: string
): Promise<ReputationAnalysis> {
  const registered = listProviders();

  if (registered.length === 0) {
    return {
      status: "unavailable",
      providers: [],
      note:
        "No reputation/threat-intel providers are configured in this deployment. " +
        "This signal is excluded from the score rather than assumed to be clean.",
    };
  }

  const evidence = await runAllProviders(hostname, submittedUrl);

  // "ok" means at least one provider gave a real answer (match or
  // no_results). "unavailable" means every provider failed to answer —
  // which is genuinely different from "every provider said no match."
  const anyRealAnswer = evidence.some(
    (e) => e.status === "clean" || e.status === "suspicious"
  );

  return {
    status: anyRealAnswer ? "ok" : "unavailable",
    providers: evidence.map(toProviderResult),
    note: anyRealAnswer
      ? "Aggregated from configured reputation providers. A \"no results\" answer means the provider has no record of this URL — it does not mean the URL is safe."
      : "All configured reputation providers were unavailable for this lookup. This signal is excluded from the score.",
  };
}