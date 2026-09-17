import { PositiveSignal, RiskFactor } from "@/lib/types";
import { severityColorVar } from "@/lib/uiHelpers";

export function RiskFactorList({ factors }: { factors: RiskFactor[] }) {
  if (factors.length === 0) {
    return <p className="font-body text-sm text-ink-muted">No risk factors were identified.</p>;
  }

  const sorted = [...factors].sort((a, b) => b.impact - a.impact);

  return (
    <div className="flex flex-col gap-3">
      {sorted.map((f, i) => (
        <div
          key={i}
          className="border-l-2 pl-4 py-1"
          style={{ borderColor: severityColorVar(f.severity) }}
        >
          <div className="flex items-baseline justify-between gap-3">
            <p className="font-display font-medium text-ink text-sm">{f.factor}</p>
            <span
              className="font-data text-xs uppercase tracking-wide shrink-0"
              style={{ color: severityColorVar(f.severity) }}
            >
              {f.severity}
            </span>
          </div>
          <p className="font-body text-sm text-ink-muted mt-1 leading-relaxed">{f.description}</p>
          {Object.keys(f.evidence).length > 0 && (
            <pre className="font-data text-xs text-ink-muted mt-2 bg-bg-panel-raised rounded px-3 py-2 overflow-x-auto">
              {JSON.stringify(f.evidence, null, 2)}
            </pre>
          )}
        </div>
      ))}
    </div>
  );
}

export function PositiveSignalList({ signals }: { signals: PositiveSignal[] }) {
  if (signals.length === 0) {
    return <p className="font-body text-sm text-ink-muted">No positive signals were identified.</p>;
  }
  return (
    <div className="flex flex-col gap-3">
      {signals.map((s, i) => (
        <div key={i} className="border-l-2 pl-4 py-1" style={{ borderColor: "var(--signal-clear)" }}>
          <p className="font-display font-medium text-ink text-sm">{s.signal}</p>
          <p className="font-body text-sm text-ink-muted mt-1 leading-relaxed">{s.description}</p>
        </div>
      ))}
    </div>
  );
}
