// src/lib/reputation/provider.ts
//
// Reputation provider abstraction.
//
// Every reputation/threat-intel source is plugged in through this interface.
// The core TRUSTVEX system never depends on a specific vendor: it depends on
// this contract. Adding or removing a provider never requires changing the
// risk engine, the scan service, or any analyzer.

export type ReputationStatus =
  | "clean"
  | "suspicious"
  | "unavailable";

export interface ReputationEvidence {
  provider: string;
  status: ReputationStatus;
  confidence: number;
  summary: string;
  evidenceUrl?: string;
  tags?: string[];
  checkedAt: string;
  error?: string;
}

export interface ReputationProvider {
  readonly name: string;
  isConfigured(): boolean;
  check(hostname: string, submittedUrl: string): Promise<ReputationEvidence>;
}

export function unconfiguredResult(
  providerName: string,
  reason: string
): ReputationEvidence {
  return {
    provider: providerName,
    status: "unavailable",
    confidence: 0,
    summary: `Provider not configured: ${reason}`,
    checkedAt: new Date().toISOString(),
    error: reason,
  };
}