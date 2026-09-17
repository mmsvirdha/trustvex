import { notFound } from "next/navigation";
import { getScanById } from "@/lib/db";
import ScoreDial from "@/components/ScoreDial";
import SectionCard, { KeyValue } from "@/components/SectionCard";
import { RiskFactorList, PositiveSignalList } from "@/components/FactorList";
import { formatDate } from "@/lib/uiHelpers";

export default async function ScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const report = getScanById(id);
  if (!report) notFound();

  const { url, dns, tls, redirects, website, reputation, confidence } = report;

  return (
    <div className="mx-auto max-w-5xl px-6 py-12">
      <p className="font-data text-sm text-ink-muted break-all">{report.submittedUrl}</p>
      <p className="font-body text-xs text-ink-muted mt-1">
        Scanned {formatDate(report.createdAt)} · feature v{report.featureVersion} · risk engine v
        {report.riskEngineVersion}
      </p>

      <div className="mt-8 mb-12">
        <ScoreDial score={report.trustScore} level={report.riskLevel} />
      </div>

      <div className="flex flex-col gap-6">
      <SectionCard title="Recommendation">
        <p className="font-body text-ink leading-relaxed">{report.recommendation}</p>
      </SectionCard>

      <div className="grid md:grid-cols-2 gap-6">
        <SectionCard title="Risk factors" subtitle="Sorted by weight, with supporting evidence">
          <RiskFactorList factors={report.riskFactors} />
        </SectionCard>
        <SectionCard title="Positive signals">
          <PositiveSignalList signals={report.positiveSignals} />
        </SectionCard>
      </div>

      <SectionCard
        title="Confidence"
        subtitle={`${Math.round(confidence.overall * 100)}% of analysis components completed successfully`}
      >
        <div className="grid sm:grid-cols-2 gap-2">
          {["url", "dns", "tls", "redirects", "website", "reputation"].map((c) => (
            <div key={c} className="flex items-center gap-2 font-data text-sm">
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{
                  background: confidence.componentsSucceeded.includes(c)
                    ? "var(--signal-clear)"
                    : "var(--signal-elevated)",
                }}
              />
              <span className="text-ink capitalize">{c}</span>
              <span className="text-ink-muted">
                {confidence.componentsSucceeded.includes(c) ? "completed" : "unavailable"}
              </span>
            </div>
          ))}
        </div>
      </SectionCard>

      <div className="grid md:grid-cols-2 gap-6">
        <SectionCard title="URL analysis">
          <KeyValue label="Protocol" value={url.protocol} />
          <KeyValue label="Hostname" value={url.hostname} />
          <KeyValue label="Root domain (heuristic)" value={url.rootDomain} />
          <KeyValue label="Subdomain" value={url.subdomain || "—"} />
          <KeyValue label="Path" value={url.path || "/"} />
          <KeyValue label="URL length" value={url.lengths.url} />
          <KeyValue label="IP-based hostname" value={String(url.flags.isIpHostname)} />
          <KeyValue label="Punycode" value={String(url.flags.isPunycode)} />
        </SectionCard>

        <SectionCard title="TLS / certificate">
          <KeyValue label="Status" value={tls.status} />
          <KeyValue label="HTTPS available" value={String(tls.httpsAvailable)} />
          <KeyValue label="Trusted by default CA store" value={String(tls.authorized)} />
          <KeyValue label="Hostname match" value={String(tls.hostnameMatches)} />
          <KeyValue label="Issuer" value={tls.issuer ?? "—"} />
          <KeyValue label="Valid until" value={tls.validTo ?? "—"} />
          <KeyValue label="Days until expiry" value={tls.daysUntilExpiry ?? "—"} />
        </SectionCard>

        <SectionCard title="DNS">
          <KeyValue label="Status" value={dns.status} />
          <KeyValue label="A records" value={dns.a.records.join(", ") || "—"} />
          <KeyValue label="AAAA records" value={dns.aaaa.records.join(", ") || "—"} />
          <KeyValue label="MX records" value={dns.mx.records.join(", ") || "—"} />
          <KeyValue label="NS records" value={dns.ns.records.join(", ") || "—"} />
          <KeyValue label="CAA records" value={dns.caa.records.join(", ") || "—"} />
        </SectionCard>

        <SectionCard title="Redirects">
          <KeyValue label="Status" value={redirects.status} />
          <KeyValue label="Final URL" value={redirects.finalUrl ?? "—"} />
          <KeyValue label="Hop count" value={redirects.hopCount} />
          <KeyValue label="Cross-domain hops" value={redirects.crossDomainHopCount} />
        </SectionCard>

                <SectionCard
          title="Page content"
          subtitle={
            website.analysisMethod === "browser"
              ? "Rendered in a real headless browser — sees JavaScript-injected content"
              : "Static HTML fallback — no JavaScript execution"
          }
        >
          <KeyValue label="Status" value={website.status} />
          <KeyValue label="Title" value={website.title ?? "—"} />
          <KeyValue label="Forms" value={website.formCount} />
          <KeyValue label="Password fields" value={website.passwordFieldCount} />
          <KeyValue label="Login form detected" value={String(website.loginFormDetected)} />
          <KeyValue label="Iframes (external)" value={website.externalIframeDomains.length} />
          <KeyValue label="External script domains" value={website.externalScriptDomains.length} />
        </SectionCard>

        <SectionCard title="Reputation" subtitle={reputation.note}>
          {reputation.providers.length === 0 ? (
            <p className="font-body text-sm text-ink-muted">No providers configured.</p>
          ) : (
            <div className="flex flex-col gap-4">
              {reputation.providers.map((p) => {
                const statusColor =
                  p.status === "suspicious"
                    ? "var(--signal-high)"
                    : p.status === "unavailable"
                    ? "var(--signal-elevated)"
                    : "var(--ink-muted)";
                const statusLabel =
                  p.status === "suspicious"
                    ? "SUSPICIOUS"
                    : p.status === "unavailable"
                    ? "UNAVAILABLE"
                    : "NO RESULTS";
                return (
                  <div
                    key={p.provider}
                    className="border-l-2 pl-3 py-1"
                    style={{ borderColor: statusColor }}
                  >
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="font-display font-medium text-sm text-ink">
                        {p.provider}
                      </span>
                      <span
                        className="font-data text-xs uppercase tracking-wide"
                        style={{ color: statusColor }}
                      >
                        {statusLabel}
                      </span>
                    </div>
                    {p.summary && (
                      <p className="font-body text-sm text-ink-muted mt-1 leading-relaxed">
                        {p.summary}
                      </p>
                    )}
                    {typeof p.confidence === "number" && p.status !== "unavailable" && (
                      <p className="font-data text-xs text-ink-muted mt-1">
                        confidence: {p.confidence}
                      </p>
                    )}
                    {p.tags && p.tags.length > 0 && (
                      <p className="font-data text-xs text-ink-muted mt-1">
                        tags: {p.tags.join(", ")}
                      </p>
                    )}
                    {p.checkedAt && (
                      <p className="font-data text-xs text-ink-muted mt-1">
                        checked {formatDate(p.checkedAt)}
                      </p>
                    )}
                    {p.error && (
                      <p className="font-data text-xs text-signal-elevated mt-1">
                        error: {p.error}
                      </p>
                    )}
                    {p.evidenceUrl && (
                      <a
                        href={p.evidenceUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-data text-xs text-signal-clear hover:underline mt-1 inline-block"
                      >
                        view evidence →
                      </a>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </SectionCard>
      </div>

              <SectionCard
          title="ML prediction"
          subtitle="Best-effort signal from the Python ML service. Optional — a scan is not failed if the service is unavailable."
        >
          {!report.mlResult ? (
            <p className="font-body text-sm text-ink-muted">
              No ML prediction was recorded for this scan (report was saved before milestone D2).
            </p>
          ) : report.mlResult.status === "unavailable" ? (
            <div className="flex flex-col gap-2">
              <p className="font-body text-sm" style={{ color: "var(--signal-elevated)" }}>
                ML service unavailable.
              </p>
              {report.mlResult.error && (
                <p className="font-data text-xs text-ink-muted">
                  {report.mlResult.error}
                </p>
              )}
              <p className="font-data text-xs text-ink-muted">
                checked {formatDate(report.mlResult.checkedAt)}
              </p>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <div className="flex items-baseline gap-3">
                <span className="font-display font-semibold text-3xl text-ink">
                  {(report.mlResult.riskProbability! * 100).toFixed(1)}%
                </span>
                <span className="font-body text-sm text-ink-muted">
                  risk probability
                </span>
              </div>
              <p className="font-body text-sm text-ink-muted leading-relaxed">
                {report.mlResult.modelVersion === "stub"
                  ? "Placeholder stub model — this is NOT a real prediction."
                  : "Produced by trustvex-url-rf-v1 (RandomForest trained on 12 URL-string features). This is one signal among many — it does not see DNS, TLS, redirects, page content, or reputation."}
              </p>
              <div className="flex gap-4 font-data text-xs text-ink-muted">
                <span>model: {report.mlResult.modelVersion}</span>
                <span>checked {formatDate(report.mlResult.checkedAt)}</span>
              </div>
              {report.mlResult.modelVersion !== "stub" && (
                <p className="font-body text-xs text-ink-muted mt-1 leading-relaxed">
                  This ML prediction is independent of the trust score above. The trust score
                  is a rule-based, multi-signal assessment; the ML probability is a
                  single-signal classifier that sees only URL-shape features. Neither
                  overrides the other.
                </p>
              )}
            </div>
          )}
        </SectionCard>

              {report.features && (
          <SectionCard
            title="Feature vector"
            subtitle={`Schema v${report.features.schemaVersion} · ${report.features.populatedCount} populated, ${report.features.missingCount} missing · ML input contract`}
          >
            {(() => {
              // Group by category for readability. Category membership is
              // derived from a static map to keep this file self-contained.
              const categoryOrder: string[] = [
                "URL", "DNS", "TLS", "REDIRECT", "WEBSITE", "REPUTATION", "CONFIDENCE", "RISK_SUMMARY",
              ];
              const byPrefix: Record<string, string[]> = {
                URL: ["url_length", "hostname_length", "path_length", "query_length", "subdomain_count", "digit_count", "special_char_count", "has_ip_hostname", "has_punycode", "has_embedded_credentials", "has_unusual_port", "suspicious_keyword_count"],
                DNS: ["dns_status_ok", "a_record_count", "aaaa_record_count", "has_mx_record", "has_caa_record"],
                TLS: ["submitted_over_https", "tls_status_ok", "tls_authorized", "tls_hostname_matches", "tls_days_until_expiry", "tls_expires_soon", "tls_https_available"],
                REDIRECT: ["redirect_hop_count", "cross_domain_hop_count", "has_redirect_chain"],
                WEBSITE: ["crawler_status_ok", "form_count", "password_field_count", "login_form_detected", "payment_keyword_detected", "iframe_count", "external_iframe_domain_count", "script_count", "external_script_domain_count", "has_download_links"],
                REPUTATION: ["reputation_provider_count", "reputation_any_suspicious", "reputation_any_no_results", "reputation_any_unavailable"],
                CONFIDENCE: ["confidence_overall", "components_failed_count"],
                RISK_SUMMARY: ["risk_factor_count", "positive_signal_count"],
              };
              return (
                <div className="flex flex-col gap-4">
                  {categoryOrder.map((category) => (
                    <div key={category}>
                      <p className="font-data text-xs uppercase tracking-wide text-ink-muted mb-2">
                        {category}
                      </p>
                      <div className="grid sm:grid-cols-2 gap-x-6 gap-y-1">
                        {byPrefix[category].map((name) => {
                          const value = report.features!.features[name];
                          const display =
                            value === null
                              ? "—"
                              : typeof value === "boolean"
                              ? String(value)
                              : String(value);
                          return (
                            <div
                              key={name}
                              className="flex items-baseline justify-between gap-3 py-0.5 border-b border-border-hairline"
                            >
                              <span className="font-data text-xs text-ink-muted truncate">
                                {name}
                              </span>
                              <span
                                className="font-data text-xs text-ink shrink-0"
                                style={
                                  value === null
                                    ? { color: "var(--ink-muted)", opacity: 0.6 }
                                    : undefined
                                }
                              >
                                {display}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              );
            })()}
          </SectionCard>
        )}

      {report.limitations.length > 0 && (
        <SectionCard title="Limitations of this analysis">
          <ul className="list-disc list-inside font-body text-sm text-ink-muted space-y-1.5 leading-relaxed">
            {report.limitations.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </SectionCard>
      )}
      </div>
    </div>
  );
}
