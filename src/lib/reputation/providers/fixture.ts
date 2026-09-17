// src/lib/reputation/providers/fixture.ts
//
// A deterministic, offline "provider" used by tests. It is NEVER
// registered in production code — see reputationAnalyzer.ts, which only
// imports the registry and does not import this file.
//
// It exists so that every failure mode the registry needs to handle
// (suspicious, clean, unavailable, timeout, rate-limit, malformed,
// missing-configuration) can be exercised in tests without ever making a
// real network request.

import type { ReputationEvidence, ReputationProvider } from "../provider";

export type FixtureBehavior =
  | { kind: "suspicious"; summary?: string; tags?: string[] }
  | { kind: "clean"; summary?: string }
  | { kind: "unavailable"; reason?: string }
  | { kind: "timeout" }
  | { kind: "rate_limit" }
  | { kind: "malformed" }
  | { kind: "not_configured" }
  | { kind: "throws"; message: string };

export function createFixtureProvider(
  name: string,
  behavior: FixtureBehavior
): ReputationProvider {
  return {
    name,
    isConfigured() {
      return behavior.kind !== "not_configured";
    },
    async check(): Promise<ReputationEvidence> {
      const checkedAt = new Date().toISOString();

      switch (behavior.kind) {
        case "suspicious":
          return {
            provider: name,
            status: "suspicious",
            confidence: 0.9,
            summary: behavior.summary ?? "Fixture reports this host as suspicious.",
            tags: behavior.tags ?? ["fixture", "test"],
            checkedAt,
            evidenceUrl: "https://example.invalid/fixture/suspicious",
          };

        case "clean":
          return {
            provider: name,
            status: "clean",
            confidence: 0.8,
            summary: behavior.summary ?? "Fixture reports no known matches.",
            checkedAt,
          };

        case "unavailable":
          return {
            provider: name,
            status: "unavailable",
            confidence: 0,
            summary: behavior.reason ?? "Fixture forced unavailable.",
            checkedAt,
            error: behavior.reason ?? "unavailable",
          };

        case "timeout":
          // Never resolves on its own — the registry's timeout wrapper is
          // what must end this call. This test proves the wrapper works.
          return new Promise<ReputationEvidence>(() => {});

        case "rate_limit":
          return {
            provider: name,
            status: "unavailable",
            confidence: 0,
            summary: "Fixture simulated a rate-limit response.",
            checkedAt,
            error: "rate_limited",
          };

        case "malformed":
          // Simulates the provider returning a value that violates the
          // ReputationEvidence contract. The registry does not do runtime
          // shape validation (deliberately — that's the provider's job);
          // this fixture is here so any future validation layer has a
          // test case ready.
          return {
            provider: name,
            status: "suspicious",
            confidence: 999, // out of range on purpose
            summary: "",
            checkedAt,
          } as ReputationEvidence;

        case "not_configured":
          // isConfigured() returns false, so this branch is never reached.
          return {
            provider: name,
            status: "unavailable",
            confidence: 0,
            summary: "not configured",
            checkedAt,
            error: "not_configured",
          };

        case "throws":
          throw new Error(behavior.message);
      }
    },
  };
}