package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func TestMaskLine(t *testing.T) {
	in := "authorization: Bearer abc.def token=supersecret AKIA1234567890ABCDEF"
	out := MaskLine(in)
	if strings.Contains(out, "supersecret") || strings.Contains(out, "AKIA1234567890ABCDEF") {
		t.Fatalf("mask failed: %s", out)
	}
}

func TestAggregateFingerprints(t *testing.T) {
	lines := []string{
		"2026-08-14T01:00:00Z error: connection refused to 10.0.0.1:5432 id=abc123def4567890abcd",
		"2026-08-14T01:00:05Z error: connection refused to 10.0.0.2:5432 id=ffff123def4567890abc",
		"2026-08-14T01:00:06Z ok request served",
	}
	fps := AggregateFingerprints([]PodLines{{Pod: "p1", Lines: lines}})
	if len(fps) != 1 {
		t.Fatalf("fingerprints=%d %+v", len(fps), fps)
	}
	if fps[0].Count != 2 {
		t.Fatalf("count=%d", fps[0].Count)
	}
}

func TestAnalyzeRequestLogGinLine(t *testing.T) {
	lines := []string{
		`[GIN] 2026/08/09 - 12:00:00 | 200 |     1.234ms |   127.0.0.1 | GET      "/v1/user"`,
		`[GIN] 2026/08/09 - 12:00:01 | 500 |     2s |   127.0.0.1 | GET      "/v1/stress"`,
	}
	a := AnalyzeRequestLog(lines)
	if len(a.Entries) != 2 || len(a.NonOkEntries) != 1 {
		t.Fatalf("entries=%d nonOk=%d", len(a.Entries), len(a.NonOkEntries))
	}
	if a.NonOkEntries[0].LatencyMs != 2000 {
		t.Fatalf("latency=%v", a.NonOkEntries[0].LatencyMs)
	}
}

func TestDetectAnomaliesScannerIsCritical(t *testing.T) {
	input := AnomalyInput{
		HttpSummary: &types.HttpSummary{
			TotalSampled: 10,
			ByPath:       []types.PathStat{},
			ByUa:         []types.KeyCount{{Key: "sqlmap/1.7", Count: 3}},
		},
	}
	anomalies := DetectAnomalies(input, time.Now())
	found := false
	for _, a := range anomalies {
		if a.Type == "MALICIOUS_CLIENT_SUSPECTED" {
			found = true
			if a.Severity != "CRITICAL" {
				t.Fatalf("scanner severity=%s", a.Severity)
			}
		}
	}
	if !found {
		t.Fatal("scanner UA must raise MALICIOUS_CLIENT_SUSPECTED")
	}
}

func TestPackToLimitDropsWholeSectionsFirst(t *testing.T) {
	header := []string{"h"}
	long := make([]string, 100)
	for i := range long {
		long[i] = strings.Repeat("x", 50)
	}
	out := PackToLimit(header, []QSection{
		{Title: "[A]", Lines: long},
		{Title: "[B]", Lines: []string{"short"}},
	}, 1000)
	if len(out) > 1000 {
		t.Fatalf("len=%d", len(out))
	}
	if !strings.Contains(out, "생략") {
		t.Fatal("must state what was dropped")
	}
}
