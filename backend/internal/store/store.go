// Package store is the SQLite layer, kept schema-compatible with the Next.js
// backend it replaces (src/lib/server/db.ts): the same file can be opened by
// either process, so moving the backend does not lose the recorded history.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

const schema = `
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
`

type Store struct {
	db *sql.DB

	// When the retention sweep last ran. metric_samples has no index on t, so
	// the sweep is a full table scan; see SaveMetricSampleBatch for why it is
	// rationed rather than run on every write.
	pruneMutex      sync.Mutex
	lastPruneUnixMs int64
}

// Open creates the parent directory, opens the database in WAL mode and applies
// the schema. ":memory:" is accepted as-is for tests.
func Open(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, err
		}
		dsn = "file:" + abs + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer at a time. SQLite serialises writes anyway, and the dashboard's
	// write volume is a handful of rows per poll.
	// ponytail: single connection, raise if read concurrency ever matters.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Ping is what /healthz reports on.
func (s *Store) Ping() error { return s.db.Ping() }

// --- settings overrides ------------------------------------------------------

// LoadSettings returns the overrides set on the settings screen. They shadow the
// process environment.
func (s *Store) LoadSettings() (map[string]string, error) {
	rows, err := s.db.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SaveSetting stores an override. An empty value means "stop overriding", not
// "override with empty" — the latter would make the environment value
// unreachable from the screen.
func (s *Store) SaveSetting(key, value string, nowMs int64) error {
	if value == "" {
		_, err := s.db.Exec("DELETE FROM settings WHERE key = ?", key)
		return err
	}
	_, err := s.db.Exec(
		"INSERT INTO settings (key, value, updated) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated",
		key, value, nowMs,
	)
	return err
}

// --- metric samples ----------------------------------------------------------

type Sample struct {
	T int64
	V float64
}

// SeriesSamples is one metric series and the points to append to it — the unit
// SaveMetricSampleBatch takes so a whole poll lands as one write.
type SeriesSamples struct {
	Key    string
	Points []Sample
}

const (
	// Rows older than this are swept. A three-hour match plus the CloudTrail
	// backfill in front of it fits comfortably; raise it if this is ever used
	// outside a contest day.
	sampleRetentionMs = 6 * 3600_000
	// The sweep is a full scan of metric_samples, so it runs on a clock rather
	// than on a write count.
	prunePeriodMs = 60_000
)

// SaveMetricSampleBatch writes every series of one poll in a single transaction
// and sweeps expired rows at most once a minute.
//
// The previous shape did the sweep — `DELETE FROM metric_samples WHERE t < ?`,
// a full table scan, because the primary key is (key, t) and nothing indexes t
// alone — inside every call, and RecordResourceSamplesTo calls it once per pod
// metric series on a 3-second poll. Twenty pods is forty transactions and forty
// full scans every three seconds against a database opened with
// SetMaxOpenConns(1): the whole dashboard queues behind housekeeping that only
// needs to happen when something has actually aged out. One transaction per
// poll plus one scan per minute is the same retention with none of the
// contention.
func (s *Store) SaveMetricSampleBatch(series []SeriesSamples) error {
	nowMs := time.Now().UnixMilli()

	// Claim the sweep before opening the transaction: concurrent pollers must
	// not all decide to scan, and a caller that claims it and then fails simply
	// leaves the rows for the next minute — expired samples are read by nothing.
	prune := false
	s.pruneMutex.Lock()
	if nowMs-s.lastPruneUnixMs >= prunePeriodMs {
		s.lastPruneUnixMs = nowMs
		prune = true
	}
	s.pruneMutex.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT INTO metric_samples (key, t, v) VALUES (?, ?, ?) ON CONFLICT(key, t) DO UPDATE SET v = excluded.v")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, one := range series {
		for _, point := range one.Points {
			if _, err := stmt.Exec(one.Key, point.T, point.V); err != nil {
				return err
			}
		}
	}
	if prune {
		if _, err := tx.Exec("DELETE FROM metric_samples WHERE t < ?", nowMs-sampleRetentionMs); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SaveMetricSamples is the single-series form, kept for the callers that record
// exactly one reading (the node count) and for the tests written against it.
func (s *Store) SaveMetricSamples(key string, points []Sample) error {
	return s.SaveMetricSampleBatch([]SeriesSamples{{Key: key, Points: points}})
}

// ListMetricKeys is the index: pod names cannot be enumerated ahead of time, so
// the caller asks the table which series still have rows in the window.
func (s *Store) ListMetricKeys(prefix string, sinceMs int64) ([]string, error) {
	rows, err := s.db.Query("SELECT DISTINCT key FROM metric_samples WHERE key LIKE ? AND t >= ? ORDER BY key", prefix+"%", sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) LoadMetricSamples(key string, sinceMs int64) ([]Sample, error) {
	rows, err := s.db.Query("SELECT t, v FROM metric_samples WHERE key = ? AND t >= ? ORDER BY t ASC", key, sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Sample{}
	for rows.Next() {
		var p Sample
		if err := rows.Scan(&p.T, &p.V); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- deploy history ----------------------------------------------------------

type DeployHistoryRow struct {
	ID            int
	Ts            int64
	Namespace     string
	Name          string
	Change        string
	MetricsBefore string
	Verdict       string
}

func (s *Store) InsertDeployHistory(namespace, name, change, metricsBefore string, nowMs int64) (int, error) {
	res, err := s.db.Exec(
		"INSERT INTO deploy_history (ts, namespace, name, change, metrics_before) VALUES (?, ?, ?, ?, ?)",
		nowMs, namespace, name, change, metricsBefore,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return int(id), err
}

func (s *Store) ListDeployHistory() ([]DeployHistoryRow, error) {
	rows, err := s.db.Query("SELECT id, ts, namespace, name, change, metrics_before, verdict FROM deploy_history ORDER BY id DESC LIMIT 50")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeployHistoryRow{}
	for rows.Next() {
		var r DeployHistoryRow
		if err := rows.Scan(&r.ID, &r.Ts, &r.Namespace, &r.Name, &r.Change, &r.MetricsBefore, &r.Verdict); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetDeployHistory returns nil when the id is unknown — a missing row is an
// answer, not a failure.
func (s *Store) GetDeployHistory(id int) (*DeployHistoryRow, error) {
	var r DeployHistoryRow
	err := s.db.QueryRow(
		"SELECT id, ts, namespace, name, change, metrics_before, verdict FROM deploy_history WHERE id = ?", id,
	).Scan(&r.ID, &r.Ts, &r.Namespace, &r.Name, &r.Change, &r.MetricsBefore, &r.Verdict)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) UpdateDeployVerdict(id int, verdict string) error {
	_, err := s.db.Exec("UPDATE deploy_history SET verdict = ? WHERE id = ?", verdict, id)
	return err
}

// --- restart tracking --------------------------------------------------------

// TrackRestarts records the restart baseline per pod and returns how much the
// count grew in the last 10 minutes. Mirrors trackRestarts in db.ts.
func (s *Store) TrackRestarts(podKey string, restarts int, nowMs int64) (int, error) {
	var baseline int
	err := s.db.QueryRow("SELECT restarts FROM restart_baseline WHERE pod = ?", podKey).Scan(&baseline)
	switch {
	case err == sql.ErrNoRows:
		if _, err := s.db.Exec("INSERT INTO restart_baseline (pod, restarts, updated) VALUES (?, ?, ?)", podKey, restarts, nowMs); err != nil {
			return 0, err
		}
	case err != nil:
		return 0, err
	case restarts > baseline:
		if _, err := s.db.Exec("INSERT INTO restart_events (pod, ts, delta) VALUES (?, ?, ?)", podKey, nowMs, restarts-baseline); err != nil {
			return 0, err
		}
		if _, err := s.db.Exec("UPDATE restart_baseline SET restarts = ?, updated = ? WHERE pod = ?", restarts, nowMs, podKey); err != nil {
			return 0, err
		}
	}
	var recent int
	err = s.db.QueryRow("SELECT COALESCE(SUM(delta), 0) FROM restart_events WHERE pod = ? AND ts >= ?", podKey, nowMs-10*60_000).Scan(&recent)
	return recent, err
}

type RestartEventRow struct {
	Pod   string
	Ts    int64
	Delta int
}

func (s *Store) RecentRestartEvents(sinceMs int64) ([]RestartEventRow, error) {
	rows, err := s.db.Query("SELECT pod, ts, delta FROM restart_events WHERE ts >= ? ORDER BY ts ASC", sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RestartEventRow{}
	for rows.Next() {
		var r RestartEventRow
		if err := rows.Scan(&r.Pod, &r.Ts, &r.Delta); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- incident snapshots ------------------------------------------------------

func (s *Store) SaveIncidentSnapshot(json string, nowMs int64) error {
	_, err := s.db.Exec("INSERT INTO incident_snapshots (ts, json) VALUES (?, ?)", nowMs, json)
	return err
}

// --- WAF apply history -------------------------------------------------------

type WafHistoryRow struct {
	ID       int
	Ts       int64
	RuleName string
	Action   string
	Status   string
	Detail   string
}

// ListWafHistoryRows is the raw shape (ms timestamps) the timeline and the
// incident report fold in; ApplyHistory below is the UI shape.
func (s *Store) ListWafHistoryRows() ([]WafHistoryRow, error) {
	rows, err := s.db.Query("SELECT id, ts, rule_name, action, status, detail FROM waf_history ORDER BY id DESC LIMIT 50")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WafHistoryRow{}
	for rows.Next() {
		var r WafHistoryRow
		if err := rows.Scan(&r.ID, &r.Ts, &r.RuleName, &r.Action, &r.Status, &r.Detail); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) InsertWafHistory(ruleName, action, status, detail, priorRules string, nowMs int64) (int, error) {
	res, err := s.db.Exec(
		"INSERT INTO waf_history (ts, rule_name, action, status, detail, prior_rules) VALUES (?, ?, ?, ?, ?, ?)",
		nowMs, ruleName, action, status, detail, priorRules,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return int(id), err
}

// ApplyHistory maps the rows the UI reads. canRollback mirrors the TypeScript
// rule: only a successful, non-rollback apply can be undone.
func (s *Store) ApplyHistory() ([]types.ApplyHistoryEntry, error) {
	rows, err := s.db.Query("SELECT id, ts, rule_name, action, status, detail FROM waf_history ORDER BY id DESC LIMIT 50")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.ApplyHistoryEntry{}
	for rows.Next() {
		var (
			id                               int
			ts                               int64
			ruleName, action, status, detail string
		)
		if err := rows.Scan(&id, &ts, &ruleName, &action, &status, &detail); err != nil {
			return nil, err
		}
		out = append(out, types.ApplyHistoryEntry{
			ID:          id,
			Ts:          time.UnixMilli(ts).UTC().Format(time.RFC3339Nano),
			RuleName:    ruleName,
			Action:      action,
			Status:      status,
			Detail:      detail,
			CanRollback: status == "SUCCESS" && action != "ROLLBACK",
		})
	}
	return out, rows.Err()
}
