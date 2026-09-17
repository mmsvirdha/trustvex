// src/lib/ml/mlClient.ts
//
// HTTP client for the TRUSTVEX Python ML service.
//
// Contract with the service:
//   POST {ML_SERVICE_URL}/predict
//   Body: { schema_version: "1.0", features: { ...45 fields... } }
//   Response (200): { risk_probability: number, model_version: string }
//
// Failure handling: every failure mode is converted to a typed
// MLPrediction with status "unavailable". This function NEVER throws —
// a scan must not fail just because the ML service is down, slow, or
// buggy. See mlConfig.ts for the 5-second hard timeout rationale.

import { ML_ENABLED, ML_SERVICE_URL, ML_TIMEOUT_MS } from "../mlConfig";
import type { MLPrediction } from "../types";

// The Python service accepts exactly these 12 features. The full 45-feature
// vector remains the report's internal representation; we extract the URL
// subset here before sending.
const MODEL_FEATURE_NAMES = [
  "url_length",
  "hostname_length",
  "path_length",
  "query_length",
  "subdomain_count",
  "digit_count",
  "special_char_count",
  "has_ip_hostname",
  "has_punycode",
  "has_embedded_credentials",
  "has_unusual_port",
  "suspicious_keyword_count",
] as const;

interface PredictRequestBody {
  schema_version: string;
  features: Record<string, number | boolean>;
}

interface PredictResponseBody {
  status: "ok" | "unavailable";
  risk_probability?: number;
  model_version: string;
  error?: string;
}

function unavailable(error: string): MLPrediction {
  return {
    status: "unavailable",
    checkedAt: new Date().toISOString(),
    error,
  };
}

/**
 * Sends a feature vector to the ML service and returns a typed result.
 *
 * @param schemaVersion - e.g. "1.0" — must match the service's expected version
 * @param features      - the FeatureVector object produced by extractFeatures
 */
export async function predictRisk(
  schemaVersion: string,
  features: Record<string, number | boolean | null>
): Promise<MLPrediction> {
  if (!ML_ENABLED) {
    return unavailable("ML is disabled (ML_ENABLED=false).");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ML_TIMEOUT_MS);

   // Extract the subset of features the model consumes. Any feature that
  // is null (unmeasured) becomes 0 — the model was trained on numeric
  // values only, and the URL-string features are never null for a URL
  // that parses. If a feature truly is null here, something upstream is
  // wrong and we'd rather send 0 than crash.
  const modelFeatures: Record<string, number | boolean> = {};
  for (const name of MODEL_FEATURE_NAMES) {
    const raw = features[name];
    if (raw === null || raw === undefined) {
      modelFeatures[name] = 0;
    } else {
      modelFeatures[name] = raw;
    }
  }

  const body: PredictRequestBody = {
    schema_version: schemaVersion,
    features: modelFeatures,
  };

  let res: Response;
  try {
    res = await fetch(`${ML_SERVICE_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      return unavailable(
        `ML service did not respond within ${ML_TIMEOUT_MS}ms.`
      );
    }
    return unavailable(
      `ML service request failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  clearTimeout(timer);

  if (!res.ok) {
    // Try to include the error detail the service returned, if any.
    let detail = `HTTP ${res.status}`;
    try {
      const payload = (await res.json()) as { detail?: string };
      if (payload.detail) detail = `${detail}: ${payload.detail}`;
    } catch {
      /* response wasn't JSON; keep the bare status */
    }
    return unavailable(`ML service returned ${detail}.`);
  }

   let parsed: PredictResponseBody;
  try {
    parsed = (await res.json()) as PredictResponseBody;
  } catch (err) {
    return unavailable(
      `ML service returned non-JSON response: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  if (!parsed || typeof parsed !== "object") {
    return unavailable("ML service returned an unexpected response shape.");
  }

  // The service now distinguishes "ok" from "unavailable" explicitly.
  // An unavailable response is not a bug — it means the model file
  // wasn't loadable, or the payload failed validation. Either way we
  // treat it as "couldn't get a prediction" rather than crashing.
  if (parsed.status === "unavailable") {
    return unavailable(
      parsed.error ?? `ML service reported unavailable (model: ${parsed.model_version}).`
    );
  }

  if (
    typeof parsed.risk_probability !== "number" ||
    typeof parsed.model_version !== "string"
  ) {
    return unavailable(
      "ML service response was missing required fields (risk_probability, model_version)."
    );
  }

  if (parsed.risk_probability < 0 || parsed.risk_probability > 1) {
    return unavailable(
      `ML service returned an out-of-range probability: ${parsed.risk_probability}`
    );
  }

  return {
    status: "ok",
    riskProbability: parsed.risk_probability,
    modelVersion: parsed.model_version,
    checkedAt: new Date().toISOString(),
  };
}