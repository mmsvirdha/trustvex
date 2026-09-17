// src/lib/reputation/registry.ts
//
// Provider registry + aggregate runner.
//
// The registry is the only place that knows about the set of active
// providers. Analyzers and the risk engine interact with the registry,
// never with individual providers directly.

import type { ReputationEvidence, ReputationProvider } from "./provider";

const PER_PROVIDER_TIMEOUT_MS = 5000;

const providers: ReputationProvider[] = [];

export function registerProvider(provider: ReputationProvider): void {
  const existing = providers.findIndex((p) => p.name === provider.name);
  if (existing >= 0) providers[existing] = provider;
  else providers.push(provider);
}

export function clearProviders(): void {
  providers.length = 0;
}

export function listProviders(): readonly ReputationProvider[] {
  return providers;
}

async function runWithTimeout(
  provider: ReputationProvider,
  hostname: string,
  submittedUrl: string
): Promise<ReputationEvidence> {
  let timer: NodeJS.Timeout | undefined;

  const timeoutPromise = new Promise<ReputationEvidence>((resolve) => {
    timer = setTimeout(() => {
      resolve({
        provider: provider.name,
        status: "unavailable",
        confidence: 0,
        summary: `Provider timed out after ${PER_PROVIDER_TIMEOUT_MS}ms`,
        checkedAt: new Date().toISOString(),
        error: "timeout",
      });
    }, PER_PROVIDER_TIMEOUT_MS);
  });

  try {
    const result = await Promise.race([
      provider.check(hostname, submittedUrl),
      timeoutPromise,
    ]);
    return result;
  } catch (err) {
    return {
      provider: provider.name,
      status: "unavailable",
      confidence: 0,
      summary: `Provider threw an error: ${
        err instanceof Error ? err.message : String(err)
      }`,
      checkedAt: new Date().toISOString(),
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function runAllProviders(
  hostname: string,
  submittedUrl: string
): Promise<ReputationEvidence[]> {
  if (providers.length === 0) return [];

  const results = await Promise.all(
    providers.map(async (provider) => {
      if (!provider.isConfigured()) {
        return {
          provider: provider.name,
          status: "unavailable" as const,
          confidence: 0,
          summary: "Provider is not configured in this deployment.",
          checkedAt: new Date().toISOString(),
          error: "not_configured",
        };
      }
      return runWithTimeout(provider, hostname, submittedUrl);
    })
  );

  return results;
}