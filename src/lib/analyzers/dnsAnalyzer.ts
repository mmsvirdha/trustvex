import { promises as dns } from "node:dns";
import { DnsAnalysis, DnsRecordResult } from "../types";

async function safeResolve<T>(
  fn: () => Promise<T[]>
): Promise<DnsRecordResult<T>> {
  try {
    const records = await fn();
    return { status: records.length > 0 ? "ok" : "empty", records };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { status: "error", records: [], error: message };
  }
}

export async function analyzeDns(hostname: string): Promise<DnsAnalysis> {
  const [a, aaaa, cname, mx, ns, txt, caa] = await Promise.all([
    safeResolve(() => dns.resolve4(hostname)),
    safeResolve(() => dns.resolve6(hostname)),
    safeResolve(() => dns.resolveCname(hostname)),
    safeResolve(() => dns.resolveMx(hostname).then((r) => r.map((m) => `${m.priority} ${m.exchange}`))),
    safeResolve(() => dns.resolveNs(hostname)),
    safeResolve(() => dns.resolveTxt(hostname).then((r) => r.map((t) => t.join("")))),
    safeResolve(() =>
      dns.resolveCaa(hostname).then((r) => r.map((c) => `${c.critical ?? 0} ${c.issue ?? c.issuewild ?? c.iodef ?? ""}`))
    ),
  ]);

  const allFailed = [a, aaaa].every((r) => r.status === "error");

  return {
    status: allFailed ? "unavailable" : "ok",
    a,
    aaaa,
    cname,
    mx,
    ns,
    txt,
    caa,
    resolvedAddressCount: a.records.length + aaaa.records.length,
  };
}
