// src/lib/features/types.ts
//
// Types for the TRUSTVEX feature-vector layer.
//
// Feature values are deliberately either `number | boolean` (a real
// measured value) or `null` (the source analyzer did not produce the
// data). We do NOT use -1 or 0 as a "missing" sentinel — that would
// conflate "measured as zero" with "unknown", which matters both for
// downstream ML imputation and for honest reporting.

export type FeatureCategory =
  | "URL"
  | "DNS"
  | "TLS"
  | "REDIRECT"
  | "WEBSITE"
  | "REPUTATION"
  | "CONFIDENCE"
  | "RISK_SUMMARY";

export type FeatureValueType = "number" | "boolean";

export type FeatureValue = number | boolean | null;

export interface FeatureDefinition {
  /** Stable identifier. Never renamed without a schema-version bump. */
  name: string;
  category: FeatureCategory;
  type: FeatureValueType;
  /** One-line human-readable description shown in the report UI. */
  description: string;
  /**
   * Set to false if this feature can never be null for a well-formed
   * ScanReport. Used by the report UI to visually distinguish "measured"
   * from "unavailable".
   */
  canBeMissing: boolean;
}

/**
 * A FeatureVector is a plain object keyed by feature name. Every key in
 * the schema is present; values are number, boolean, or null.
 */
export type FeatureVector = Record<string, FeatureValue>;

export interface FeatureExtractionResult {
  schemaVersion: string;
  features: FeatureVector;
  /** Convenience: number of non-null features in this vector. */
  populatedCount: number;
  /** Convenience: number of null features in this vector. */
  missingCount: number;
}