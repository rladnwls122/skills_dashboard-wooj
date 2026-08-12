import "server-only";
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { ENV } from "./config";

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (db) return db;
  const dir = path.dirname(path.resolve(ENV.dbPath));
  fs.mkdirSync(dir, { recursive: true });
  db = new Database(path.resolve(ENV.dbPath));
  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS metric_samples (
      key TEXT NOT NULL,
      t INTEGER NOT NULL,
      v REAL NOT NULL,
      PRIMARY KEY (key, t)
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS restart_baseline (
      pod TEXT PRIMARY KEY,
      restarts INTEGER NOT NULL,
      updated INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS restart_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pod TEXT NOT NULL,
      ts INTEGER NOT NULL,
      delta INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS waf_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      rule_name TEXT NOT NULL,
      action TEXT NOT NULL,
      status TEXT NOT NULL,
      detail TEXT NOT NULL,
      prior_rules TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS deploy_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      namespace TEXT NOT NULL,
      name TEXT NOT NULL,
      change TEXT NOT NULL,
      metrics_before TEXT NOT NULL,
      verdict TEXT NOT NULL DEFAULT 'PENDING'
    );
    CREATE TABLE IF NOT EXISTS incident_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      json TEXT NOT NULL
    );
  `);
  return db;
}

export function saveMetricSamples(key: string, points: { t: number; v: number }[]): void {
  const d = getDb();
  const stmt = d.prepare(
    "INSERT INTO metric_samples (key, t, v) VALUES (?, ?, ?) ON CONFLICT(key, t) DO UPDATE SET v = excluded.v",
  );
  const tx = d.transaction((rows: { t: number; v: number }[]) => {
    for (const r of rows) stmt.run(key, r.t, r.v);
  });
  tx(points);
  d.prepare("DELETE FROM metric_samples WHERE t < ?").run(Date.now() - 6 * 3600_000);
}

// --- settings overrides ----------------------------------------------------
//
// Values set on the 설정 screen. They shadow .env so a mistyped resource name
// can be corrected without editing a file and restarting the process — which,
// during a timed exercise, is the difference between fixing it and not.

export function loadSettings(): Record<string, string> {
  const rows = getDb().prepare("SELECT key, value FROM settings").all() as {
    key: string;
    value: string;
  }[];
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

export function saveSetting(key: string, value: string): void {
  const d = getDb();
  // An empty value means "stop overriding", not "override with empty" — the
  // latter would make .env unreachable from the screen.
  if (value === "") {
    d.prepare("DELETE FROM settings WHERE key = ?").run(key);
    return;
  }
  d.prepare(
    "INSERT INTO settings (key, value, updated) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated",
  ).run(key, value, Date.now());
}

// Every series recorded under a prefix that still has a row in the window.
// The caller cannot enumerate pod names ahead of time — pods come and go — so
// the table is the index.
export function listMetricKeys(prefix: string, sinceMs: number): string[] {
  const rows = getDb()
    .prepare("SELECT DISTINCT key FROM metric_samples WHERE key LIKE ? AND t >= ? ORDER BY key")
    .all(`${prefix}%`, sinceMs) as { key: string }[];
  return rows.map((r) => r.key);
}

export function loadMetricSamples(key: string, sinceMs: number): { t: number; v: number }[] {
  return getDb()
    .prepare("SELECT t, v FROM metric_samples WHERE key = ? AND t >= ? ORDER BY t ASC")
    .all(key, sinceMs) as { t: number; v: number }[];
}

export interface RestartUpdateResult {
  recentIncrease: number;
}

export function trackRestarts(podKey: string, restarts: number): RestartUpdateResult {
  const d = getDb();
  const row = d.prepare("SELECT restarts FROM restart_baseline WHERE pod = ?").get(podKey) as
    | { restarts: number }
    | undefined;
  const now = Date.now();
  if (row === undefined) {
    d.prepare("INSERT INTO restart_baseline (pod, restarts, updated) VALUES (?, ?, ?)").run(
      podKey,
      restarts,
      now,
    );
  } else if (restarts > row.restarts) {
    d.prepare("INSERT INTO restart_events (pod, ts, delta) VALUES (?, ?, ?)").run(
      podKey,
      now,
      restarts - row.restarts,
    );
    d.prepare("UPDATE restart_baseline SET restarts = ?, updated = ? WHERE pod = ?").run(
      restarts,
      now,
      podKey,
    );
  }
  const recent = d
    .prepare("SELECT COALESCE(SUM(delta), 0) AS s FROM restart_events WHERE pod = ? AND ts >= ?")
    .get(podKey, now - 10 * 60_000) as { s: number };
  return { recentIncrease: recent.s };
}

export function recentRestartEvents(sinceMs: number): { pod: string; ts: number; delta: number }[] {
  return getDb()
    .prepare("SELECT pod, ts, delta FROM restart_events WHERE ts >= ? ORDER BY ts ASC")
    .all(sinceMs) as { pod: string; ts: number; delta: number }[];
}

export interface WafHistoryRow {
  id: number;
  ts: number;
  rule_name: string;
  action: string;
  status: string;
  detail: string;
  prior_rules: string;
}

export function insertWafHistory(
  ruleName: string,
  action: string,
  status: string,
  detail: string,
  priorRules: string,
): number {
  const info = getDb()
    .prepare(
      "INSERT INTO waf_history (ts, rule_name, action, status, detail, prior_rules) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .run(Date.now(), ruleName, action, status, detail, priorRules);
  return Number(info.lastInsertRowid);
}

export function listWafHistory(): WafHistoryRow[] {
  return getDb()
    .prepare("SELECT * FROM waf_history ORDER BY id DESC LIMIT 50")
    .all() as WafHistoryRow[];
}

export function getWafHistory(id: number): WafHistoryRow | undefined {
  return getDb().prepare("SELECT * FROM waf_history WHERE id = ?").get(id) as
    | WafHistoryRow
    | undefined;
}

export interface DeployHistoryRow {
  id: number;
  ts: number;
  namespace: string;
  name: string;
  change: string;
  metrics_before: string;
  verdict: string;
}

export function insertDeployHistory(
  namespace: string,
  name: string,
  change: string,
  metricsBefore: string,
): number {
  const info = getDb()
    .prepare(
      "INSERT INTO deploy_history (ts, namespace, name, change, metrics_before) VALUES (?, ?, ?, ?, ?)",
    )
    .run(Date.now(), namespace, name, change, metricsBefore);
  return Number(info.lastInsertRowid);
}

export function listDeployHistory(): DeployHistoryRow[] {
  return getDb()
    .prepare("SELECT * FROM deploy_history ORDER BY id DESC LIMIT 50")
    .all() as DeployHistoryRow[];
}

export function getDeployHistory(id: number): DeployHistoryRow | undefined {
  return getDb().prepare("SELECT * FROM deploy_history WHERE id = ?").get(id) as
    | DeployHistoryRow
    | undefined;
}

export function updateDeployVerdict(id: number, verdict: string): void {
  getDb().prepare("UPDATE deploy_history SET verdict = ? WHERE id = ?").run(verdict, id);
}

export function saveIncidentSnapshot(json: string): number {
  const info = getDb()
    .prepare("INSERT INTO incident_snapshots (ts, json) VALUES (?, ?)")
    .run(Date.now(), json);
  return Number(info.lastInsertRowid);
}
