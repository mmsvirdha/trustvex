import ScanForm from "@/components/ScanForm";
import HowItWorks from "@/components/HowItWorks";

const SIGNALS = [
  { label: "URL structure", detail: "length, encoding, IP hosts, punycode, keyword patterns" },
  { label: "DNS", detail: "A/AAAA/MX/NS/TXT/CAA records" },
  { label: "TLS", detail: "certificate trust, hostname match, expiry" },
  { label: "Redirects", detail: "full chain, cross-domain hops" },
  { label: "Page content", detail: "forms, password fields, scripts, iframes, downloads" },
  { label: "Reputation", detail: "pluggable threat-intel providers" },
];

export default function HomePage() {
  return (
    <div className="relative">
      {/* Radial glow behind the hero. Pure decoration. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-[620px] overflow-hidden"
      >
        <div
          className="absolute left-1/2 top-[-80px] h-[520px] w-[900px] -translate-x-1/2 rounded-full opacity-25 blur-3xl"
          style={{
            background:
              "radial-gradient(closest-side, var(--signal-clear), transparent 72%)",
          }}
        />
      </div>

      <div className="relative mx-auto max-w-5xl px-6">
        <section className="pt-24 pb-16 border-b border-border-hairline">
          <div className="inline-flex items-center gap-2 rounded-full border border-border-hairline bg-bg-panel/60 px-3 py-1.5 mb-6">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ background: "var(--signal-clear)" }}
            />
            <span className="font-data text-xs text-ink-muted tracking-wide">
              Website trust &amp; risk intelligence
            </span>
          </div>

          <h1 className="font-display font-semibold text-5xl sm:text-6xl leading-[1.05] text-ink max-w-3xl tracking-tight">
            Look before you{" "}
            <span
              className="bg-clip-text text-transparent"
              style={{
                backgroundImage:
                  "linear-gradient(90deg, var(--signal-clear), #7ee7d2)",
              }}
            >
              trust a link.
            </span>
          </h1>

          <p className="font-body text-lg text-ink-muted mt-6 max-w-xl leading-relaxed">
            TRUSTVEX examines a URL from six independent angles and shows its
            work — score, confidence, and the exact evidence behind every
            factor. No black-box verdicts.
          </p>

          <div className="mt-10 max-w-2xl">
            <ScanForm />
          </div>
        </section>

        <HowItWorks />

        <section className="py-16 border-t border-border-hairline">
          <h2 className="font-display font-semibold text-xs text-ink-muted mb-8 tracking-[0.18em] uppercase">
            What gets analyzed
          </h2>
          <div className="grid sm:grid-cols-2 gap-x-10 gap-y-7">
            {SIGNALS.map((s, i) => (
              <div key={s.label} className="flex gap-4 border-l-2 border-border-hairline pl-4">
                <div>
                  <p className="font-data text-xs text-signal-clear mb-1 tracking-wider">
                    {String(i + 1).padStart(2, "0")}
                  </p>
                  <p className="font-display font-medium text-ink">{s.label}</p>
                  <p className="font-body text-sm text-ink-muted mt-0.5">{s.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}