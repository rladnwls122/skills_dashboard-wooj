package nodecost

import (
	"testing"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func TestParseMatchStart(t *testing.T) {
	now := time.Date(2026, 8, 14, 11, 30, 0, 0, time.Local).UnixMilli()

	got, ok := ParseMatchStart("09:00", now)
	want := time.Date(2026, 8, 14, 9, 0, 0, 0, time.Local).UnixMilli()
	if !ok || got != want {
		t.Errorf("bare hh:mm: got %d ok=%v, want %d", got, ok, want)
	}

	got, ok = ParseMatchStart("2026-08-14 09:00", now)
	if !ok || got != want {
		t.Errorf("date + time: got %d ok=%v, want %d", got, ok, want)
	}
	got, ok = ParseMatchStart("2026-08-14T09:00", now)
	if !ok || got != want {
		t.Errorf("T form: got %d ok=%v, want %d", got, ok, want)
	}
	if _, ok := ParseMatchStart("", now); ok {
		t.Error("empty should not parse")
	}
	if _, ok := ParseMatchStart("어제", now); ok {
		t.Error("garbage should not parse")
	}
}

func TestTimeWeightedAvg(t *testing.T) {
	// A value holds until the next reading replaces it: 10 minutes at 2 then
	// 10 minutes at 4 averages 3 regardless of how many samples repeat each.
	samples := []Sample{{T: 0, V: 2}, {T: 600_000, V: 4}}
	got := TimeWeightedAvg(samples, 0, 1_200_000)
	if got == nil || *got != 3 {
		t.Errorf("step average: got %v, want 3", got)
	}

	// The value in effect when the window opens is the last reading at or
	// before it, not the first inside it.
	got = TimeWeightedAvg(samples, 300_000, 900_000)
	if got == nil || *got != 3 {
		t.Errorf("window straddling a step: got %v, want 3", got)
	}

	if TimeWeightedAvg(nil, 0, 600_000) != nil {
		t.Error("no samples should be nil")
	}
	if TimeWeightedAvg(samples, 600_000, 600_000) != nil {
		t.Error("zero-length window should be nil")
	}
}

func TestProject(t *testing.T) {
	win := types.ScoringWindow{StartMs: 0, EndMs: 2 * 3600_000}
	samples := []Sample{{T: 0, V: 4}}
	// Halfway through at 4, dropping to 2 now: final = (4×1h + 2×1h) / 2h = 3.
	p := Project(samples, types.Ptr(2), win, 3600_000)
	if p.FinalAvg == nil || *p.FinalAvg != 3 {
		t.Errorf("final average: got %v, want 3", p.FinalAvg)
	}
	if p.MarginalPerInstance == nil || *p.MarginalPerInstance != 0.5 {
		t.Errorf("marginal: got %v, want 0.5", p.MarginalPerInstance)
	}
	if *p.ElapsedMin != 60 || *p.RemainingMin != 60 {
		t.Errorf("elapsed/remaining: got %d/%d", *p.ElapsedMin, *p.RemainingMin)
	}
}

func TestReconstruct(t *testing.T) {
	// Current count 3, a RunInstances(+2) at t=200, a Terminate(-1) at t=400:
	// before 200 the count was 1, between 200 and 400 it was 3+1=... walk back:
	// after 400 → 3; before 400 → 4; before 200 → 2.
	deltas := []TrailDelta{{T: 200, Delta: 2}, {T: 400, Delta: -1}}
	samples := Reconstruct(deltas, 3, 0, 1000)
	want := []Sample{{T: 0, V: 2}, {T: 200, V: 4}, {T: 400, V: 3}, {T: 1000, V: 3}}
	if len(samples) != len(want) {
		t.Fatalf("got %v, want %v", samples, want)
	}
	for i := range want {
		if samples[i] != want[i] {
			t.Errorf("sample %d: got %+v, want %+v", i, samples[i], want[i])
		}
	}
}

func TestParseTrailEvents(t *testing.T) {
	events := []types.CloudTrailEvent{
		// One RunInstances launching two instances is one +2 delta.
		{Name: "RunInstances", TsMs: 100, Body: `{"responseElements":{"instancesSet":{"items":[{},{}]}}}`},
		{Name: "TerminateInstances", TsMs: 200, Body: `{}`},
		// A malformed body still counts one instance.
		{Name: "RunInstances", TsMs: 300, Body: `not json`},
		// Unrelated events are dropped.
		{Name: "StopInstances", TsMs: 400, Body: `{}`},
	}
	got := ParseTrailEvents(events)
	want := []TrailDelta{{T: 100, Delta: 2}, {T: 200, Delta: -1}, {T: 300, Delta: 1}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("delta %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestOffSpec(t *testing.T) {
	rows := []types.InstanceRow{
		{ID: "i-ok", Type: AllowedInstanceType(), AZ: "ap-northeast-2a", ClusterTag: types.Ptr("owned")},
		{ID: "i-type", Type: "m5.large", AZ: "ap-northeast-2a", ClusterTag: types.Ptr("owned")},
		{ID: "i-region", Type: AllowedInstanceType(), AZ: "us-east-1a", ClusterTag: types.Ptr("owned")},
		{ID: "i-stray", Type: AllowedInstanceType(), AZ: "ap-northeast-2a"},
	}
	got := OffSpec(rows, "ap-northeast-2")
	if len(got) != 3 {
		t.Fatalf("want 3 off-spec, got %d: %+v", len(got), got)
	}
	if got[0].ID != "i-type" || got[0].Reason != "타입 m5.large" {
		t.Errorf("type reason: %+v", got[0])
	}
	if got[1].ID != "i-region" || got[1].Reason != "리전 us-east-1a" {
		t.Errorf("region reason: %+v", got[1])
	}
	if got[2].ID != "i-stray" || got[2].Reason != "클러스터에 속하지 않음" {
		t.Errorf("cluster reason: %+v", got[2])
	}
}
