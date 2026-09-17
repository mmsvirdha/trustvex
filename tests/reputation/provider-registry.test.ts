// tests/reputation/provider-registry.test.ts
//
// Unit tests for the reputation provider registry.
//
// Uses ONLY the fixture provider (see providers/fixture.ts). No network
// calls, no real reputation APIs, no third-party systems touched.
//
// Run with: npm test
//
// Uses Node's built-in test runner (node --test) so no additional test
// dependency is required.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  registerProvider,
  clearProviders,
  listProviders,
  runAllProviders,
} from "../../src/lib/reputation/registry";
import { createFixtureProvider } from "../../src/lib/reputation/providers/fixture";

const HOSTNAME = "example.test";
const URL = "https://example.test/path";

function freshRegistry() {
  clearProviders();
}

test("registry returns empty array when no providers registered", async () => {
  freshRegistry();
  const results = await runAllProviders(HOSTNAME, URL);
  assert.deepEqual(results, []);
});

test("clean result passes through unchanged", async () => {
  freshRegistry();
  registerProvider(
    createFixtureProvider("fixture-clean", { kind: "clean", summary: "all good" })
  );

  const [result] = await runAllProviders(HOSTNAME, URL);
  assert.equal(result.provider, "fixture-clean");
  assert.equal(result.status, "clean");
  assert.equal(result.confidence, 0.8);
  assert.equal(result.summary, "all good");
  assert.ok(result.checkedAt);
});

test("suspicious result carries evidence, tags, and reference URL", async () => {
  freshRegistry();
  registerProvider(
    createFixtureProvider("fixture-bad", {
      kind: "suspicious",
      summary: "known phishing host",
      tags: ["phishing", "credential-harvest"],
    })
  );

  const [result] = await runAllProviders(HOSTNAME, URL);
  assert.equal(result.status, "suspicious");
  assert.equal(result.summary, "known phishing host");
  assert.deepEqual(result.tags, ["phishing", "credential-harvest"]);
  assert.equal(result.evidenceUrl, "https://example.invalid/fixture/suspicious");
});

test("unavailable result carries an error reason and never throws", async () => {
  freshRegistry();
  registerProvider(
    createFixtureProvider("fixture-down", {
      kind: "unavailable",
      reason: "upstream 503",
    })
  );

  const [result] = await runAllProviders(HOSTNAME, URL);
  assert.equal(result.status, "unavailable");
  assert.equal(result.error, "upstream 503");
  assert.equal(result.confidence, 0);
});

test("timeout is caught by the registry's hard timeout, scan does not hang", async () => {
  freshRegistry();
  registerProvider(createFixtureProvider("fixture-slow", { kind: "timeout" }));

  const start = Date.now();
  const [result] = await runAllProviders(HOSTNAME, URL);
  const elapsed = Date.now() - start;

  assert.equal(result.status, "unavailable");
  assert.equal(result.error, "timeout");
  // Registry timeout is 5000ms; allow generous slack for CI.
  assert.ok(elapsed < 8000, `expected timeout within 8s, took ${elapsed}ms`);
});

test("rate-limit is surfaced as unavailable, not thrown", async () => {
  freshRegistry();
  registerProvider(createFixtureProvider("fixture-limited", { kind: "rate_limit" }));

  const [result] = await runAllProviders(HOSTNAME, URL);
  assert.equal(result.status, "unavailable");
  assert.equal(result.error, "rate_limited");
});

test("provider that throws is isolated — registry still resolves", async () => {
  freshRegistry();
  registerProvider(
    createFixtureProvider("fixture-throws", {
      kind: "throws",
      message: "simulated crash",
    })
  );

  const [result] = await runAllProviders(HOSTNAME, URL);
  assert.equal(result.status, "unavailable");
  assert.match(result.error ?? "", /simulated crash/);
});

test("malformed response is returned as-is (no runtime validation in B1)", async () => {
  freshRegistry();
  registerProvider(createFixtureProvider("fixture-malformed", { kind: "malformed" }));

  const [result] = await runAllProviders(HOSTNAME, URL);
  // B1 does not validate provider output; the point of this test is to
  // lock in the current behavior so future validation layers have a
  // baseline to compare against.
  assert.equal(result.provider, "fixture-malformed");
});

test("not-configured provider is skipped without a network call", async () => {
  freshRegistry();
  registerProvider(
    createFixtureProvider("fixture-unconfigured", { kind: "not_configured" })
  );

  const [result] = await runAllProviders(HOSTNAME, URL);
  assert.equal(result.status, "unavailable");
  assert.equal(result.error, "not_configured");
});

test("one failing provider does not affect a healthy provider in the same run", async () => {
  freshRegistry();
  registerProvider(createFixtureProvider("healthy", { kind: "clean" }));
  registerProvider(createFixtureProvider("broken", { kind: "throws", message: "boom" }));
  registerProvider(createFixtureProvider("slow", { kind: "timeout" }));

  const results = await runAllProviders(HOSTNAME, URL);
  assert.equal(results.length, 3);

  const byName = Object.fromEntries(results.map((r) => [r.provider, r]));
  assert.equal(byName["healthy"].status, "clean");
  assert.equal(byName["broken"].status, "unavailable");
  assert.equal(byName["slow"].status, "unavailable");
});

test("registerProvider is idempotent by name", () => {
  freshRegistry();
  registerProvider(createFixtureProvider("dup", { kind: "clean" }));
  registerProvider(createFixtureProvider("dup", { kind: "suspicious" }));
  const providers = listProviders();
  assert.equal(providers.length, 1);
});