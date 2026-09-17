// tests/reputation/urlhaus.test.ts
//
// Mocked tests for the URLhaus provider. NO live network calls are made.
// Every fetch is stubbed with a controlled response so we can exercise
// every documented URLhaus state — including the ones that would be
// dangerous or impractical to trigger live.
//
// Uses Node's built-in test runner (node --test) — no extra deps.

// tests/reputation/urlhaus.test.ts
//
// Mocked tests for the URLhaus provider. NO live network calls are made.
// Every fetch is stubbed with a controlled response so we can exercise
// every documented URLhaus state — including the ones that would be
// dangerous or impractical to trigger live.
//
// Uses Node's built-in test runner (node --test) — no extra deps.

import { test } from "node:test";
import assert from "node:assert/strict";

import { createUrlhausProvider } from "../../src/lib/reputation/providers/urlhaus";

// URLhaus requires an API key (added in B2). Tests use a fake key so the
// provider's isConfigured() gate passes and check() actually runs. Every
// network call is stubbed per test below, so no real request is ever made.
// This line must appear BEFORE any test() call.
process.env.URLHAUS_API_KEY = "test-key-do-not-use";

const HOST = "example.test";
const URL_UNDER_TEST = "http://example.test/path";

// A tiny fetch-stub helper. Replaces global.fetch for the duration of one
// test, then restores it. This is the ONLY place in the codebase that
// stubs fetch, so mocking is contained and easy to find.
function withFetchStub(
  stub: typeof fetch,
  fn: () => Promise<void>
): () => Promise<void> {
  return async () => {
    const original = globalThis.fetch;
    globalThis.fetch = stub;
    try {
      await fn();
    } finally {
      globalThis.fetch = original;
    }
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}


test(
  "URLhaus ok response → suspicious with evidence",
  withFetchStub(
    async () =>
      jsonResponse({
        query_status: "ok",
        id: "123456",
        urlhaus_reference: "https://urlhaus.abuse.ch/url/123456/",
        url_status: "online",
        threat: "malware_download",
        tags: ["exe", "emotet"],
        date_added: "2024-01-15 12:00:00 UTC",
      }),
    async () => {
      const provider = createUrlhausProvider();
      const result = await provider.check(HOST, URL_UNDER_TEST);

      assert.equal(result.provider, "urlhaus");
      assert.equal(result.status, "suspicious");
      assert.ok(result.summary.includes("malware"));
      assert.equal(result.evidenceUrl, "https://urlhaus.abuse.ch/url/123456/");
      assert.ok(result.tags?.includes("threat:malware_download"));
      assert.ok(result.tags?.includes("status:online"));
      assert.ok(result.tags?.includes("exe"));
      assert.ok(result.checkedAt);
    }
  )
);

test(
  "URLhaus no_results → clean, but with low confidence and no positive implication",
  withFetchStub(
    async () => jsonResponse({ query_status: "no_results" }),
    async () => {
      const provider = createUrlhausProvider();
      const result = await provider.check(HOST, URL_UNDER_TEST);

      assert.equal(result.status, "clean");
      // Confidence is deliberately low — absence of evidence.
      assert.ok(result.confidence <= 0.5);
      // Summary says "no matching record", not "safe".
      assert.match(result.summary, /no matching record/i);
      // No evidenceUrl on a no-match result.
      assert.equal(result.evidenceUrl, undefined);
    }
  )
);

test(
  "URLhaus rate limit (HTTP 429) → unavailable, no throw",
  withFetchStub(
    async () =>
      new Response("rate limited", { status: 429 }),
    async () => {
      const provider = createUrlhausProvider();
      const result = await provider.check(HOST, URL_UNDER_TEST);

      assert.equal(result.status, "unavailable");
      assert.equal(result.error, "rate_limited");
      assert.match(result.summary, /rate limit/i);
    }
  )
);

test(
  "URLhaus HTTP 500 → unavailable with http_500 error code",
  withFetchStub(
    async () => new Response("server error", { status: 500 }),
    async () => {
      const provider = createUrlhausProvider();
      const result = await provider.check(HOST, URL_UNDER_TEST);

      assert.equal(result.status, "unavailable");
      assert.equal(result.error, "http_500");
    }
  )
);

test(
  "URLhaus non-JSON body → unavailable with malformed_response error",
  withFetchStub(
    async () =>
      new Response("<html>oops</html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      }),
    async () => {
      const provider = createUrlhausProvider();
      const result = await provider.check(HOST, URL_UNDER_TEST);

      assert.equal(result.status, "unavailable");
      assert.equal(result.error, "malformed_response");
    }
  )
);

test(
  "URLhaus JSON missing query_status → unavailable with malformed_response error",
  withFetchStub(
    async () => jsonResponse({ surprise: true }),
    async () => {
      const provider = createUrlhausProvider();
      const result = await provider.check(HOST, URL_UNDER_TEST);

      assert.equal(result.status, "unavailable");
      assert.equal(result.error, "malformed_response");
    }
  )
);

test(
  "URLhaus unknown query_status → unavailable with urlhaus_<status> error",
  withFetchStub(
    async () => jsonResponse({ query_status: "invalid_url" }),
    async () => {
      const provider = createUrlhausProvider();
      const result = await provider.check(HOST, URL_UNDER_TEST);

      assert.equal(result.status, "unavailable");
      assert.equal(result.error, "urlhaus_invalid_url");
    }
  )
);

test(
  "URLhaus network error → unavailable, no throw",
  withFetchStub(
    async () => {
      throw new Error("ECONNREFUSED");
    },
    async () => {
      const provider = createUrlhausProvider();
      const result = await provider.check(HOST, URL_UNDER_TEST);

      assert.equal(result.status, "unavailable");
      assert.equal(result.error, "network_error");
      assert.match(result.summary, /ECONNREFUSED/);
    }
  )
);

test(
  "URLHAUS_ENABLED=false disables the provider at the isConfigured gate",
  async () => {
    const prev = process.env.URLHAUS_ENABLED;
    process.env.URLHAUS_ENABLED = "false";
    try {
      const provider = createUrlhausProvider();
      assert.equal(provider.isConfigured(), false);
    } finally {
      if (prev === undefined) delete process.env.URLHAUS_ENABLED;
      else process.env.URLHAUS_ENABLED = prev;
    }
  }
);