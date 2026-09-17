import { RedirectAnalysis, RedirectHopResult } from "../types";
import type { SafeFetchResult } from "../security/safeFetch";

function hostnameOf(u: string): string {
  try {
    return new URL(u).hostname;
  } catch {
    return "";
  }
}

export function analyzeRedirects(
  originalUrl: string,
  fetchResult: SafeFetchResult | null,
  fetchError: string | null
): RedirectAnalysis {
  if (!fetchResult) {
    return {
      status: "unavailable",
      finalUrl: null,
      hopCount: 0,
      crossDomainHopCount: 0,
      chain: [],
      excessiveRedirects: false,
      error: fetchError ?? "Request failed",
    };
  }

  const chain: RedirectHopResult[] = [];
  const originalHost = hostnameOf(originalUrl);

  fetchResult.redirectChain.forEach((hop, idx) => {
    const nextHop = fetchResult.redirectChain[idx + 1];
    const toUrl = hop.locationHeader
      ? new URL(hop.locationHeader, hop.requestedUrl).toString()
      : idx === fetchResult.redirectChain.length - 1
      ? fetchResult.finalUrl
      : nextHop?.requestedUrl ?? null;

    chain.push({
      sequence: hop.sequence,
      fromUrl: hop.requestedUrl,
      toUrl,
      status: hop.status,
      hostname: hop.resolvedHostname,
      crossDomain: hostnameOf(toUrl ?? "") !== "" && hostnameOf(toUrl ?? "") !== hop.resolvedHostname,
    });
  });

  const crossDomainHopCount = chain.filter((h) => h.crossDomain).length;
  const finalHost = hostnameOf(fetchResult.finalUrl);

  return {
    status: "ok",
    finalUrl: fetchResult.finalUrl,
    hopCount: Math.max(chain.length - 1, 0),
    crossDomainHopCount:
      crossDomainHopCount + (finalHost && finalHost !== originalHost && chain.length <= 1 ? 1 : 0),
    chain,
    excessiveRedirects: chain.length - 1 > 4,
  };
}
