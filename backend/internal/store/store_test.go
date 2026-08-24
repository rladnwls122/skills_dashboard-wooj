package store

import (
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDeployHistoryRoundTrip(t *testing.T) {
	s := open(t)
	id, err := s.InsertDeployHistory("default", "api", "replicas=3", `{"trt":1}`, 1_700_000_000_000)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	row, err := s.GetDeployHistory(id)
	if err != nil || row == nil {
		t.Fatalf("get: %v row=%v", err, row)
	}
	if row.Verdict != "PENDING" || row.Change != "replicas=3" {
		t.Fatalf("unexpected row: %+v", row)
	}
	if err := s.UpdateDeployVerdict(id, "IMPROVED"); err != nil {
		t.Fatalf("verdict: %v", err)
	}
	list, err := s.ListDeployHistory()
	if err != nil || len(list) != 1 || list[0].Verdict != "IMPROVED" {
		t.Fatalf("list: %v %+v", err, list)
	}
	// An unknown id is an answer, not a failure.
	missing, err := s.GetDeployHistory(id + 999)
	if err != nil || missing != nil {
		t.Fatalf("expected nil row, got %v %v", missing, err)
	}
}

func TestSaveSettingEmptyClearsOverride(t *testing.T) {
	s := open(t)
	if err := s.SaveSetting("AWS_REGION", "us-east-1", 1); err != nil {
		t.Fatal(err)
	}
	m, _ := s.LoadSettings()
	if m["AWS_REGION"] != "us-east-1" {
		t.Fatalf("override not stored: %v", m)
	}
	if err := s.SaveSetting("AWS_REGION", "", 2); err != nil {
		t.Fatal(err)
	}
	m, _ = s.LoadSettings()
	if _, ok := m["AWS_REGION"]; ok {
		t.Fatalf("empty value must clear the override, got %v", m)
	}
}

func TestMetricSamplesAreIdempotentPerKeyAndTime(t *testing.T) {
	s := open(t)
	key := "res:pod:cpu:api-7d9"
	// Inside the 6h retention the writer enforces — an older sample would be
	// swept by the same call that wrote it.
	now := time.Now().UnixMilli()
	if err := s.SaveMetricSamples(key, []Sample{{T: now, V: 10}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveMetricSamples(key, []Sample{{T: now, V: 42}}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.LoadMetricSamples(key, 0)
	if err != nil || len(rows) != 1 || rows[0].V != 42 {
		t.Fatalf("expected one row overwritten to 42, got %v %v", rows, err)
	}
	keys, err := s.ListMetricKeys("res:", 0)
	if err != nil || len(keys) != 1 || keys[0] != key {
		t.Fatalf("keys: %v %v", keys, err)
	}
}

func TestApplyHistoryRollbackFlag(t *testing.T) {
	s := open(t)
	if _, err := s.InsertWafHistory("r1", "APPLY", "SUCCESS", "ok", "[]", 1_700_000_000_000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertWafHistory("r2", "ROLLBACK", "SUCCESS", "ok", "[]", 1_700_000_001_000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertWafHistory("r3", "APPLY", "FAILED", "boom", "[]", 1_700_000_002_000); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ApplyHistory()
	if err != nil || len(rows) != 3 {
		t.Fatalf("history: %v %v", rows, err)
	}
	// Newest first: failed apply, rollback, successful apply.
	if rows[0].CanRollback || rows[1].CanRollback || !rows[2].CanRollback {
		t.Fatalf("canRollback wrong: %+v", rows)
	}
}

// One poll of the kube panel is one write. The single-series form is kept for
// the callers that record exactly one reading, and both share the retention
// sweep — which now runs on a clock rather than on every insert, because it is
// a full scan of a table whose only index is (key, t).
func TestSaveMetricSampleBatchWritesEverySeries(t *testing.T) {
	s := open(t)
	now := time.Now().UnixMilli()
	err := s.SaveMetricSampleBatch([]SeriesSamples{
		{Key: "res:pod:cpu:api-1", Points: []Sample{{T: now, V: 12}}},
		{Key: "res:pod:mem:api-1", Points: []Sample{{T: now, V: 34}}},
		{Key: "res:node:cpu:ip-10-0-0-1", Points: []Sample{{T: now, V: 56}, {T: now - 10_000, V: 55}}},
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	keys, err := s.ListMetricKeys("res:", 0)
	if err != nil || len(keys) != 3 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	rows, err := s.LoadMetricSamples("res:node:cpu:ip-10-0-0-1", 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	// Same key and time, new value: still one row, still the newer value.
	if err := s.SaveMetricSampleBatch([]SeriesSamples{
		{Key: "res:pod:cpu:api-1", Points: []Sample{{T: now, V: 99}}},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err = s.LoadMetricSamples("res:pod:cpu:api-1", 0)
	if err != nil || len(rows) != 1 || rows[0].V != 99 {
		t.Fatalf("expected one row overwritten to 99, got %v %v", rows, err)
	}
}

func TestRetentionSweepStillDropsExpiredRows(t *testing.T) {
	s := open(t)
	now := time.Now().UnixMilli()
	// Older than the retention horizon, written before the first sweep of this
	// store has run — so this very call is the one that must sweep it.
	if err := s.SaveMetricSamples("nodes:count", []Sample{
		{T: now - sampleRetentionMs - 60_000, V: 1},
		{T: now, V: 2},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.LoadMetricSamples("nodes:count", 0)
	if err != nil || len(rows) != 1 || rows[0].V != 2 {
		t.Fatalf("expected only the fresh row to survive, got %v %v", rows, err)
	}
}
