import Link from "next/link";
import { listScans } from "@/lib/db";
import { formatDate, riskLevelColorVar, riskLevelLabel } from "@/lib/uiHelpers";

export default function HistoryPage() {
  const scans = listScans(50);

  return (
    <div className="mx-auto max-w-5xl px-6 py-12">
      <h1 className="font-display font-semibold text-2xl text-ink mb-1 tracking-tight">
        Scan history
      </h1>
      <p className="font-body text-sm text-ink-muted mb-8">
        Most recent {scans.length} scan{scans.length === 1 ? "" : "s"}, stored locally.
      </p>

      {scans.length === 0 ? (
        <p className="font-body text-ink-muted">
          No scans yet.{" "}
          <Link href="/" className="text-signal-clear hover:underline">
            Run your first one.
          </Link>
        </p>
      ) : (
        <div className="border border-border-hairline rounded-xl overflow-hidden">
          {scans.map((s) => (
            <Link
              key={s.id}
              href={`/scan/${s.id}`}
              className="group flex items-center justify-between gap-4 px-5 py-4 border-b border-border-hairline last:border-0 hover:bg-bg-panel-raised transition-colors"
            >
              <div className="min-w-0">
                <p className="font-data text-sm text-ink truncate">{s.url}</p>
                <p className="font-body text-xs text-ink-muted mt-0.5">
                  {formatDate(s.createdAt)}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span
                  className="font-display font-semibold text-sm"
                  style={{ color: riskLevelColorVar(s.riskLevel) }}
                >
                  {riskLevelLabel(s.riskLevel)}
                </span>
                <span className="font-data text-sm text-ink-muted w-14 text-right">
                  {s.trustScore}/100
                </span>
                <span
                  className="font-data text-sm opacity-0 group-hover:opacity-100 transition-opacity -ml-1"
                  style={{ color: "var(--signal-clear)" }}
                >
                  →
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}