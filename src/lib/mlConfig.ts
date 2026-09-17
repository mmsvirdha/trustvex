// src/lib/mlConfig.ts
//
// Configuration for the ML service integration.
//
// All ML-related tunables live here so there is one place to look when
// behavior needs to change. Values are read once at module load.

/** Base URL of the Python ML service. Override with ML_SERVICE_URL. */
export const ML_SERVICE_URL =
  process.env.ML_SERVICE_URL ?? "http://localhost:8000";

/**
 * Whether to attempt ML predictions at all. Set ML_ENABLED=false to skip
 * the ML call entirely (useful for offline development, CI without a
 * Python service, or debugging).
 */
export const ML_ENABLED = process.env.ML_ENABLED !== "false";

/**
 * Hard timeout for the ML prediction call. After this, the scan continues
 * with mlResult.status = "unavailable". Deliberately short — ML is one
 * signal among many, and no single source should be able to slow a scan
 * down. See design rationale in the D2 milestone notes.
 */
export const ML_TIMEOUT_MS = 5000;