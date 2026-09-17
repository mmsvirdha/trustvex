"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function ScanForm() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Something went wrong.");
        setLoading(false);
        return;
      }
      router.push(`/scan/${data.id}`);
    } catch {
      setError("Could not reach the analysis service.");
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="flex flex-col sm:flex-row gap-3">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="example.com or https://example.com/login"
          disabled={loading}
          className="flex-1 bg-bg-panel border border-border-hairline rounded-lg px-4 py-3.5 font-data text-sm text-ink placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-signal-clear focus:border-transparent disabled:opacity-60 transition-shadow"
          autoFocus
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="font-display font-semibold text-sm bg-signal-clear text-bg-base rounded-lg px-6 py-3.5 hover:brightness-110 active:brightness-95 transition disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
        >
          {loading ? "Analyzing…" : "Analyze"}
        </button>
      </div>
      {error && (
        <p className="mt-3 text-sm text-signal-high font-body">{error}</p>
      )}
      {loading && (
        <div className="mt-4 flex items-center gap-3">
          <span className="relative flex h-2 w-2">
            <span
              className="absolute inline-flex h-full w-full rounded-full animate-trustvex-ping"
              style={{ background: "var(--signal-clear)" }}
            />
            <span
              className="relative inline-flex h-2 w-2 rounded-full"
              style={{ background: "var(--signal-clear)" }}
            />
          </span>
          <p className="text-sm text-ink-muted font-body">
            Running six independent analyses — this takes a few seconds.
          </p>
        </div>
      )}
    </form>
  );
}