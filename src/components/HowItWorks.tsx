const STEPS = [
  { n: "01", label: "Parse URL", detail: "structure, punycode, keywords" },
  { n: "02", label: "DNS lookup", detail: "A, AAAA, MX, NS, CAA" },
  { n: "03", label: "TLS inspect", detail: "certificate, issuer, expiry" },
  { n: "04", label: "Follow redirects", detail: "hop by hop, SSRF-guarded" },
  { n: "05", label: "Render page", detail: "headless Chromium" },
  { n: "06", label: "Query URLhaus", detail: "live threat intelligence" },
  { n: "07", label: "Extract 45 features", detail: "versioned v1.0 schema" },
  { n: "08", label: "Score + classify", detail: "rule engine + ML" },
];

export default function HowItWorks() {
  return (
    <section className="py-16 border-t border-border-hairline">
      <h2 className="font-display font-semibold text-xs text-ink-muted mb-10 tracking-[0.18em] uppercase">
        How a scan works
      </h2>
      <div className="relative">
        <div
          className="absolute left-0 right-0 top-[11px] h-px"
          style={{ background: "var(--border-hairline)" }}
        />
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-x-4 gap-y-8">
          {STEPS.map((s) => (
            <div key={s.n} className="relative">
              <div
                className="relative w-6 h-6 rounded-full border-2 bg-bg-base flex items-center justify-center"
                style={{ borderColor: "var(--signal-clear)" }}
              >
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: "var(--signal-clear)" }}
                />
              </div>
              <p className="font-data text-[10px] text-ink-muted mt-3 tracking-wider">
                {s.n}
              </p>
              <p className="font-display text-sm text-ink mt-1 leading-tight">
                {s.label}
              </p>
              <p className="font-body text-xs text-ink-muted mt-1 leading-snug">
                {s.detail}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}