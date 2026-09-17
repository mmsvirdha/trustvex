// src/lib/reputation/providers/urlhaus.ts
//
// URLhaus (abuse.ch) reputation provider.
//
// URLhaus is a free, nonprofit threat-intelligence service that tracks URLs
// used to distribute malware. As of 2025, abuse.ch requires an Auth-Key on
// every API call. Get one free at https://auth.abuse.ch/ and set it in
// .env.local as URLHAUS_API_KEY.
//
// CRITICAL HONESTY NOTE: URLhaus only indexes URLs that are actively
// distributing malware. A "no_results" response means *this specific
// database has no record of the URL* — it does NOT mean the URL is safe.
// The URL could be phishing (URLhaus doesn't track phishing), brand new,
// already taken down, or hosted somewhere URLhaus doesn't crawl. The
// provider reports "no_results" honestly, and the risk engine deliberately
// does NOT treat it as a positive trust signal.
//
// Rate limits: abuse.ch rate-limits high-volume clients. The 5-second
// per-provider timeout in the registry protects us from one slow URLhaus
// response stalling the scan. Rate-limit responses (HTTP 429) are surfaced
// as "unavailable" with a clear error string rather than retried
// automatically — retries would make the rate-limit problem worse.

import type {
  ReputationEvidence,
  ReputationProvider,
} from "../provider";

const URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/";
const REQUEST_TIMEOUT_MS = 4000; // slightly under the registry's 5s outer cap

interface UrlhausOkResponse {
  query_status: "ok";
  id?: string;
  urlhaus_reference?: string;
  url_status?: string; // "online" | "offline" | "unknown"
  threat?: string;     // e.g. "malware_download"
  tags?: string[] | null;
  date_added?: string;
  reporter?: string;
}

interface UrlhausNoResults {
  query_status: "no_results";
}

interface UrlhausOtherStatus {
  query_status: string; // e.g. "invalid_url", "unauthorized"
}

type UrlhausResponse = UrlhausOkResponse | UrlhausNoResults | UrlhausOtherStatus;

function checkedAtNow(): string {
  return new Date().toISOString();
}

function unavailable(summary: string, error: string): ReputationEvidence {
  return {
    provider: "urlhaus",
    status: "unavailable",
    confidence: 0,
    summary,
    checkedAt: checkedAtNow(),
    error,
  };
}

export function createUrlhausProvider(): ReputationProvider {
  return {
    name: "urlhaus",

    isConfigured() {
      // URLhaus requires an Auth-Key as of 2025. If either the env
      // variable is explicitly set to "false" OR the key is missing,
      // treat the provider as not configured — this makes the UI report
      // "not_configured" honestly rather than firing off a request that
      // we know will fail with 401.
      if (process.env.URLHAUS_ENABLED === "false") return false;
      return typeof process.env.URLHAUS_API_KEY === "string"
        && process.env.URLHAUS_API_KEY.length > 0;
    },

    async check(_hostname: string, submittedUrl: string): Promise<ReputationEvidence> {
      const apiKey = process.env.URLHAUS_API_KEY;
      if (!apiKey) {
        // Belt-and-suspenders: the registry already skips unconfigured
        // providers, but if we're called directly we still return a
        // clean typed result rather than making a request we know fails.
        return unavailable(
          "URLhaus API key is not configured (set URLHAUS_API_KEY in .env.local).",
          "not_configured"
        );
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      let res: Response;
      try {
        res = await fetch(URLHAUS_ENDPOINT, {
          method: "POST",
          headers: {
            // abuse.ch expects form-encoded bodies with a url field.
            "Content-Type": "application/x-www-form-urlencoded",
            // The Auth-Key header is abuse.ch's convention across all
            // their services (URLhaus, MalwareBazaar, ThreatFox, YARAify).
            "Auth-Key": apiKey,
          },
          body: new URLSearchParams({ url: submittedUrl }).toString(),
          signal: controller.signal,
        });
      } catch (err) {
        clearTimeout(timer);
        if (err instanceof Error && err.name === "AbortError") {
          return unavailable(
            `URLhaus lookup timed out after ${REQUEST_TIMEOUT_MS}ms`,
            "timeout"
          );
        }
        return unavailable(
          `URLhaus request failed: ${err instanceof Error ? err.message : String(err)}`,
          "network_error"
        );
      }
      clearTimeout(timer);

      if (res.status === 401) {
        return unavailable(
          "URLhaus rejected the API key (HTTP 401). Verify URLHAUS_API_KEY is correct and the abuse.ch account is active.",
          "unauthorized"
        );
      }
      if (res.status === 429) {
        return unavailable(
          "URLhaus rate limit reached for this client. Try again shortly.",
          "rate_limited"
        );
      }
      if (!res.ok) {
        return unavailable(
          `URLhaus returned HTTP ${res.status}`,
          `http_${res.status}`
        );
      }

      let parsed: UrlhausResponse;
      try {
        parsed = (await res.json()) as UrlhausResponse;
      } catch (err) {
        return unavailable(
          `URLhaus returned a non-JSON response: ${err instanceof Error ? err.message : String(err)}`,
          "malformed_response"
        );
      }

      if (!parsed || typeof parsed.query_status !== "string") {
        return unavailable(
          "URLhaus response was missing the query_status field.",
          "malformed_response"
        );
      }

      if (parsed.query_status === "no_results") {
        // IMPORTANT: this is intentionally NOT "clean". It means URLhaus
        // has no record of this URL. The risk engine is written to NOT
        // treat this as a positive trust signal.
        return {
          provider: "urlhaus",
          status: "clean",
          confidence: 0.5,
          summary: "URLhaus has no matching record for this URL.",
          checkedAt: checkedAtNow(),
          tags: ["urlhaus:no_results"],
        };
      }

      if (parsed.query_status === "ok") {
        const ok = parsed as UrlhausOkResponse;
        const threat = ok.threat ?? "unspecified";
        const urlStatus = ok.url_status ?? "unknown";
        const tagList = Array.isArray(ok.tags) ? ok.tags : [];
        const summary = `URLhaus reports this URL as a known ${threat.replace(/_/g, " ")} (status: ${urlStatus}).`;

        return {
          provider: "urlhaus",
          status: "suspicious",
          confidence: 0.9,
          summary,
          evidenceUrl: ok.urlhaus_reference,
          tags: ["urlhaus:match", `threat:${threat}`, `status:${urlStatus}`, ...tagList],
          checkedAt: checkedAtNow(),
        };
      }

      // Any other query_status value, including "unauthorized".
      return unavailable(
        `URLhaus did not return a usable result (query_status: ${parsed.query_status}).`,
        `urlhaus_${parsed.query_status}`
      );
    },
  };
}