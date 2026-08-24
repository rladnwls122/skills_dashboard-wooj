// The SQLite layer, kept schema-compatible with every earlier backend: the same
// file can be opened by either process, so moving the backend does not lose the
// recorded history.

import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import Database from "better-sqlite3";

import type { ApplyHistoryEntry, Verdict } from "../../src/lib/types.ts";

const SCHEMA = `
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
`;

export interface Sample {
  t: number;
  v: number;
}

/** One series' worth of a batched write — see saveMetricSampleBatch. */
export interface MetricSampleBatchEntry {
  key: string;
  points: Sample[];
}

/**
 * How long a metric sample is kept. Six hours is longer than any window the
 * dashboard offers, so nothing the charts can ask for is ever swept out from
 * under them.
 */
const METRIC_RETENTION_MS = 6 * 3600_000;

/**
 * How often the retention sweep is allowed to run.
 *
 * The sweep is `DELETE FROM metric_samples WHERE t < ?`, and the primary key is
 * (key, t) — there is no index on `t` alone, so every sweep is a full table
 * scan. The kube panel polls every three seconds and writes two series per pod
 * plus two per node; running the sweep per series meant dozens of full scans
 * every three seconds, each one holding the write lock on the same SQLite file
 * the settings and credential reads go through (busy_timeout 5000). Deleting a
 * row a minute late costs nothing — the retention is six hours — so the sweep
 * is throttled and the poll pays for it at most once.
 */
const METRIC_PRUNE_INTERVAL_MS = 60_000;

export interface DeployHistoryRow {
  id: number;
  ts: number;
  namespace: string;
  name: string;
  change: string;
  metricsBefore: string;
  // Written only by updateDeployVerdict; "PENDING" until the verification runs.
  verdict: Verdict | "PENDING";
}

export interface RestartEventRow {
  pod: string;
  ts: number;
  delta: number;
}

export interface WafHistoryRow {
  id: number;
  ts: number;
  ruleName: string;
  action: string;
  status: string;
  detail: string;
}

export class Store {
  private readonly db: Database.Database;

  /**
   * When the retention sweep last ran. Per Store instance, which is per process
   * — a second process opening the same file runs its own sweep, and both are
   * idempotent deletes of rows nobody can still ask for.
   */
  private lastMetricPruneMs = 0;

  private constructor(db: Database.Database) {
    this.db = db;
  }

  /**
   * Creates the parent directory, opens the database in WAL mode and applies the
   * schema. ":memory:" is accepted as-is for tests.
   */
  static open(path: string): Store {
    let target = path;
    if (path !== ":memory:") {
      target = resolve(path);
      mkdirSync(dirname(target), { recursive: true });
    }
    const db = new Database(target);
    if (path !== ":memory:") db.pragma("journal_mode = WAL");
    db.pragma("busy_timeout = 5000");
    db.exec(SCHEMA);
    return new Store(db);
  }

  close(): void {
    this.db.close();
  }

  /** What /healthz reports on. */
  ping(): void {
    this.db.prepare("SELECT 1").get();
  }

  // --- settings overrides ----------------------------------------------------

  /**
   * The overrides set on the settings screen. They shadow the process
   * environment.
   */
  loadSettings(): Record<string, string> {
    const rows = this.db.prepare("SELECT key, value FROM settings").all() as {
      key: string;
      value: string;
    }[];
    const out: Record<string, string> = {};
    for (const r of rows) out[r.key] = r.value;
    return out;
  }

  /**
   * Stores an override. An empty value means "stop overriding", not "override
   * with empty" — the latter would make the environment value unreachable from
   * the screen.
   */
  saveSetting(key: string, value: string, nowMs: number): void {
    if (value === "") {
      this.db.prepare("DELETE FROM settings WHERE key = ?").run(key);
      return;
    }
    this.db
      .prepare(
        "INSERT INTO settings (key, value, updated) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated",
      )
      .run(key, value, nowMs);
  }

  // --- metric samples --------------------------------------------------------

  /** Single-series write. Kept because callers and tests write one series. */
  saveMetricSamples(key: string, points: Sample[]): void {
    this.saveMetricSampleBatch([{ key, points }]);
  }

  /**
   * Every series of one poll in one transaction, with at most one retention
   * sweep behind it.
   *
   * One transaction rather than one per series because a transaction per series
   * is a separate write-lock acquisition and fsync per series: a 20-pod cluster
   * produced ~40 of them every three seconds, and the settings/credentials reads
   * that share this file were queueing behind them until busy_timeout. The
   * sweep is throttled on top of that — see METRIC_PRUNE_INTERVAL_MS for why it
   * is the expensive half.
   */
  saveMetricSampleBatch(entries: MetricSampleBatchEntry[]): void {
    if (entries.length === 0) return;
    const insert = this.db.prepare(
      "INSERT INTO metric_samples (key, t, v) VALUES (?, ?, ?) ON CONFLICT(key, t) DO UPDATE SET v = excluded.v",
    );
    const prune = this.db.prepare("DELETE FROM metric_samples WHERE t < ?");
    const nowMs = Date.now();
    // Decided before the transaction opens so the flag and the statement that
    // actually ran cannot disagree if the transaction throws.
    const sweeping = nowMs - this.lastMetricPruneMs >= METRIC_PRUNE_INTERVAL_MS;
    const tx = this.db.transaction((batch: MetricSampleBatchEntry[]) => {
      for (const entry of batch) {
        for (const p of entry.points) insert.run(entry.key, p.t, p.v);
      }
      if (sweeping) prune.run(nowMs - METRIC_RETENTION_MS);
    });
    tx(entries);
    // Only after the transaction committed: a failed write must not buy the
    // next poll a free hour of skipped retention.
    if (sweeping) this.lastMetricPruneMs = nowMs;
  }

  /**
   * The index: pod names cannot be enumerated ahead of time, so the caller asks
   * the table which series still have rows in the window.
   */
  listMetricKeys(prefix: string, sinceMs: number): string[] {
    const rows = this.db
      .prepare(
        "SELECT DISTINCT key FROM metric_samples WHERE key LIKE ? AND t >= ? ORDER BY key",
      )
      .all(prefix + "%", sinceMs) as { key: string }[];
    return rows.map((r) => r.key);
  }

  loadMetricSamples(key: string, sinceMs: number): Sample[] {
    return this.db
      .prepare("SELECT t, v FROM metric_samples WHERE key = ? AND t >= ? ORDER BY t ASC")
      .all(key, sinceMs) as Sample[];
  }

  // --- deploy history --------------------------------------------------------

  insertDeployHistory(
    namespace: string,
    name: string,
    change: string,
    metricsBefore: string,
    nowMs: number,
  ): number {
    const res = this.db
      .prepare(
        "INSERT INTO deploy_history (ts, namespace, name, change, metrics_before) VALUES (?, ?, ?, ?, ?)",
      )
      .run(nowMs, namespace, name, change, metricsBefore);
    return Number(res.lastInsertRowid);
  }

  listDeployHistory(): DeployHistoryRow[] {
    const rows = this.db
      .prepare(
        "SELECT id, ts, namespace, name, change, metrics_before AS metricsBefore, verdict FROM deploy_history ORDER BY id DESC LIMIT 50",
      )
      .all() as DeployHistoryRow[];
    return rows;
  }

  /** Undefined when the id is unknown — a missing row is an answer, not a failure. */
  getDeployHistory(id: number): DeployHistoryRow | undefined {
    return this.db
      .prepare(
        "SELECT id, ts, namespace, name, change, metrics_before AS metricsBefore, verdict FROM deploy_history WHERE id = ?",
      )
      .get(id) as DeployHistoryRow | undefined;
  }

  updateDeployVerdict(id: number, verdict: Verdict | "PENDING"): void {
    this.db.prepare("UPDATE deploy_history SET verdict = ? WHERE id = ?").run(verdict, id);
  }

  // --- restart tracking ------------------------------------------------------

  /**
   * Records the restart baseline per pod and returns how much the count grew in
   * the last 10 minutes.
   */
  trackRestarts(podKey: string, restarts: number, nowMs: number): number {
    const baseline = this.db
      .prepare("SELECT restarts FROM restart_baseline WHERE pod = ?")
      .get(podKey) as { restarts: number } | undefined;

    if (!baseline) {
      this.db
        .prepare("INSERT INTO restart_baseline (pod, restarts, updated) VALUES (?, ?, ?)")
        .run(podKey, restarts, nowMs);
    } else if (restarts > baseline.restarts) {
      this.db
        .prepare("INSERT INTO restart_events (pod, ts, delta) VALUES (?, ?, ?)")
        .run(podKey, nowMs, restarts - baseline.restarts);
      this.db
        .prepare("UPDATE restart_baseline SET restarts = ?, updated = ? WHERE pod = ?")
        .run(restarts, nowMs, podKey);
    }

    const recent = this.db
      .prepare(
        "SELECT COALESCE(SUM(delta), 0) AS recent FROM restart_events WHERE pod = ? AND ts >= ?",
      )
      .get(podKey, nowMs - 10 * 60_000) as { recent: number };
    return recent.recent;
  }

  recentRestartEvents(sinceMs: number): RestartEventRow[] {
    return this.db
      .prepare("SELECT pod, ts, delta FROM restart_events WHERE ts >= ? ORDER BY ts ASC")
      .all(sinceMs) as RestartEventRow[];
  }

  // --- incident snapshots ----------------------------------------------------

  saveIncidentSnapshot(json: string, nowMs: number): void {
    this.db.prepare("INSERT INTO incident_snapshots (ts, json) VALUES (?, ?)").run(nowMs, json);
  }

  // --- WAF apply history -----------------------------------------------------

  /**
   * The raw shape (ms timestamps) the timeline and the incident report fold in;
   * applyHistory below is the UI shape.
   */
  listWafHistoryRows(): WafHistoryRow[] {
    return this.db
      .prepare(
        "SELECT id, ts, rule_name AS ruleName, action, status, detail FROM waf_history ORDER BY id DESC LIMIT 50",
      )
      .all() as WafHistoryRow[];
  }

  insertWafHistory(
    ruleName: string,
    action: string,
    status: string,
    detail: string,
    priorRules: string,
    nowMs: number,
  ): number {
    const res = this.db
      .prepare(
        "INSERT INTO waf_history (ts, rule_name, action, status, detail, prior_rules) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(nowMs, ruleName, action, status, detail, priorRules);
    return Number(res.lastInsertRowid);
  }

  /**
   * The rows the UI reads. canRollback: only a successful, non-rollback apply can
   * be undone.
   */
  applyHistory(): ApplyHistoryEntry[] {
    return this.listWafHistoryRows().map((r) => ({
      id: r.id,
      ts: new Date(r.ts).toISOString(),
      ruleName: r.ruleName,
      action: r.action,
      status: r.status,
      detail: r.detail,
      canRollback: r.status === "SUCCESS" && r.action !== "ROLLBACK",
    }));
  }
}
