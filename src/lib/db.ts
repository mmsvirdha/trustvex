import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import fs from "node:fs";
import { ScanListItem, ScanReport } from "./types";

const DATA_DIR = path.join(process.cwd(), "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, "trustvex.db");

// Reuse a single connection across hot-reloads in dev.
declare global {
  var __trustvexDb: DatabaseSync | undefined;
}

/**
 * Next.js dev mode (Turbopack) runs each route in its own worker process.
 * Each worker loads this module independently, so we can end up with
 * multiple processes racing to open the same SQLite file and run the WAL
 * pragma at the same moment. WAL mode requires a brief exclusive lock,
 * and SQLite returns SQLITE_BUSY ("database is locked") if the lock
 * cannot be acquired immediately.
 *
 * Fix: retry the whole init with exponential backoff. The lock only lasts
 * a few milliseconds, so a handful of retries is enough. Once a database
 * has been put into WAL mode by any process, subsequent opens do not
 * need to repeat the pragma — but we still issue it in a try/catch so
 * that a racing process doesn't crash this worker.
 */
function sleepSync(ms: number): void {
  // Synchronous sleep using Atomics.wait on a SharedArrayBuffer.
  // This is safe because initDb() runs at module load, before any request
  // handling — a blocking sleep here does not block other requests.
  const buf = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(buf), 0, 0, ms);
}

function initDb(): DatabaseSync {
  const MAX_ATTEMPTS = 6;
  let lastErr: unknown = null;

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    try {
      const db = new DatabaseSync(DB_PATH);

      // WAL is persistent on the file, so this is idempotent after the
      // first time. Wrap in try/catch so that if a racing worker holds
      // the lock, we log-and-continue instead of crashing.
      try {
        db.exec("PRAGMA journal_mode = WAL;");
      } catch (err) {
        // If another worker holds the WAL lock briefly, that's fine —
        // the file is already in WAL mode (or will be after they finish).
        const msg = err instanceof Error ? err.message : String(err);
        if (!/database is locked/i.test(msg)) throw err;
      }

      db.exec(`
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY,
          url TEXT NOT NULL,
          hostname TEXT NOT NULL,
          trust_score INTEGER NOT NULL,
          risk_level TEXT NOT NULL,
          created_at TEXT NOT NULL,
          report_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans (hostname);
      `);

      return db;
    } catch (err) {
      lastErr = err;
      const msg = err instanceof Error ? err.message : String(err);
      if (!/database is locked/i.test(msg)) throw err;
      // Back off and retry: 50ms, 100ms, 200ms, 400ms, 800ms.
      sleepSync(50 * Math.pow(2, attempt));
    }
  }

  throw lastErr instanceof Error
    ? lastErr
    : new Error("Failed to initialize SQLite database after retries");
}

export const db = globalThis.__trustvexDb ?? initDb();
if (process.env.NODE_ENV !== "production") {
  globalThis.__trustvexDb = db;
}

export function saveScan(report: ScanReport): void {
  db.prepare(
    `INSERT INTO scans (id, url, hostname, trust_score, risk_level, created_at, report_json)
     VALUES (@id, @url, @hostname, @trustScore, @riskLevel, @createdAt, @reportJson)`
  ).run({
    id: report.id,
    url: report.submittedUrl,
    hostname: report.url.hostname,
    trustScore: report.trustScore,
    riskLevel: report.riskLevel,
    createdAt: report.createdAt,
    reportJson: JSON.stringify(report),
  });
}

export function getScanById(id: string): ScanReport | null {
  const row = db.prepare(`SELECT report_json FROM scans WHERE id = ?`).get(id) as
    | { report_json: string }
    | undefined;
  if (!row) return null;
  return JSON.parse(row.report_json) as ScanReport;
}

export function listScans(limit = 50): ScanListItem[] {
  const rows = db
    .prepare(
      `SELECT id, url, hostname, trust_score, risk_level, created_at
       FROM scans ORDER BY created_at DESC LIMIT ?`
    )
    .all(limit) as {
    id: string;
    url: string;
    hostname: string;
    trust_score: number;
    risk_level: string;
    created_at: string;
  }[];

  return rows.map((r) => ({
    id: r.id,
    url: r.url,
    hostname: r.hostname,
    trustScore: r.trust_score,
    riskLevel: r.risk_level as ScanListItem["riskLevel"],
    createdAt: r.created_at,
  }));
}