export default function SectionCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="border border-border-hairline rounded-xl bg-bg-panel p-6 transition-colors">
      <h3 className="font-display font-semibold text-ink tracking-tight">
        {title}
      </h3>
      {subtitle && (
        <p className="font-body text-sm text-ink-muted mt-1.5 leading-relaxed">
          {subtitle}
        </p>
      )}
      <div className="mt-5">{children}</div>
    </section>
  );
}

export function KeyValue({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex justify-between gap-4 py-2 border-b border-border-hairline last:border-0">
      <span className="font-body text-sm text-ink-muted">{label}</span>
      <span className="font-data text-sm text-ink text-right break-all">
        {value}
      </span>
    </div>
  );
}