import { RiskLevel, Severity } from "./types";

export function riskLevelLabel(level: RiskLevel): string {
  switch (level) {
    case "LOW_OBSERVED_RISK":
      return "Low observed risk";
    case "MODERATE_OBSERVED_RISK":
      return "Moderate observed risk";
    case "ELEVATED_OBSERVED_RISK":
      return "Elevated observed risk";
    case "HIGH_OBSERVED_RISK":
      return "High observed risk";
    case "INCONCLUSIVE":
      return "Inconclusive";
  }
}

export function riskLevelColorVar(level: RiskLevel): string {
  switch (level) {
    case "LOW_OBSERVED_RISK":
      return "var(--signal-clear)";
    case "MODERATE_OBSERVED_RISK":
      return "var(--signal-clear)";
    case "ELEVATED_OBSERVED_RISK":
      return "var(--signal-elevated)";
    case "HIGH_OBSERVED_RISK":
      return "var(--signal-high)";
    case "INCONCLUSIVE":
      return "var(--ink-muted)";
  }
}

export function severityColorVar(severity: Severity): string {
  switch (severity) {
    case "HIGH":
      return "var(--signal-high)";
    case "MEDIUM":
      return "var(--signal-elevated)";
    case "LOW":
      return "var(--ink-muted)";
  }
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
