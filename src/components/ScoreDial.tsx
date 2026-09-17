import { RiskLevel } from "@/lib/types";
import { riskLevelColorVar, riskLevelLabel } from "@/lib/uiHelpers";

export default function ScoreDial({ score, level }: { score: number; level: RiskLevel }) {
  const color = riskLevelColorVar(level);
  const pct = Math.max(0, Math.min(100, score));

  return (
    <div className="flex items-center gap-8">
      <div className="relative shrink-0">
        <div
          aria-hidden
          className="absolute inset-0 rounded-full blur-2xl opacity-40"
          style={{ background: color }}
        />
        <div
          className="relative w-40 h-40 rounded-full"
          style={{
            background: `conic-gradient(${color} ${pct * 3.6}deg, var(--bg-panel-raised) ${
              pct * 3.6
            }deg)`,
          }}
          role="img"
          aria-label={`Trust score ${score} out of 100, ${riskLevelLabel(level)}`}
        >
          <div className="absolute inset-3 rounded-full bg-bg-base flex flex-col items-center justify-center">
            <span className="font-display font-bold text-4xl text-ink tabular-nums">
              {score}
            </span>
            <span className="font-data text-[10px] text-ink-muted tracking-wider">
              / 100
            </span>
          </div>
        </div>
      </div>
      <div>
        <p
          className="font-display font-semibold text-2xl tracking-tight"
          style={{ color }}
        >
          {riskLevelLabel(level)}
        </p>
        <p className="font-body text-sm text-ink-muted mt-2 max-w-xs leading-relaxed">
          Higher scores reflect fewer observed risk indicators, not a guarantee
          of safety.
        </p>
      </div>
    </div>
  );
}