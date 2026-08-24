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

// The binaries' own failure lines must fingerprint: the product trap line has
// no generic error keyword, and a 5xx access line is an error by status.
func TestAggregateFingerprintsBinaryLines(t *testing.T) {
	lines := []string{
		"2026-08-14T01:00:00Z Consumed resources by malicious attacks.",
		"2026-08-14T01:00:01Z Consumed resources by malicious attacks.",
		`2026-08-14T01:00:02Z [GIN] 2025/09/23 - 03:12:47 | 500 |  1.234567891s |   203.0.113.10 | POST     "/v1/stress"`,
		"2026-08-14T01:00:03Z 2025/09/23 03:12:47 Failed to query DB: Error 1062 (23000): Duplicate entry 'x' for key 'user.uk_username'",
		`2026-08-14T01:00:04Z [GIN] 2025/09/23 - 03:12:48 | 201 |   12.345678ms |   203.0.113.10 | POST     "/v1/user"`,
	}
	fps := AggregateFingerprints([]PodLines{{Pod: "p1", Lines: lines}})
	if len(fps) != 3 {
		t.Fatalf("fingerprints=%d %+v", len(fps), fps)
	}
	if !strings.Contains(fps[0].Fingerprint, "malicious") || fps[0].Count != 2 {
		t.Fatalf("trap line not grouped first: %+v", fps[0])
	}
}

// Real lines from the 2025 task binaries (gin 1.10 default logger), in every
// unit time.Duration prints, plus the stderr middleware line that must not be
// counted as a second request.
func TestAnalyzeRequestLogGinLine(t *testing.T) {
	lines := []string{
		`[GIN] 2025/09/23 - 03:12:45 | 201 |   12.345678ms |   203.0.113.10 | POST     "/v1/user"`,
		`[GIN] 2025/09/23 - 03:12:46 | 200 |     45.678µs |   203.0.113.10 | GET      "/v1/user?email=dbdump500001%40example.org&requestid=999999999999&uuid=7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729"`,
		`[GIN] 2025/09/23 - 03:12:47 | 500 |  1.234567891s |   203.0.113.10 | POST     "/v1/stress"`,
		`[GIN] 2025/09/23 - 03:12:48 | 404 |       2.501µs |   203.0.113.11 | GET      "/v1/none"`,
		`[GIN] 2025/09/23 - 03:12:49 | 200 |         1m2s |      10.0.1.5 | GET      "/healthcheck"`,
		`[GIN] 2025/09/23 - 03:12:50 | 200 |         850ns |      10.0.1.5 | GET      "/healthcheck"`,
		`2025/09/23 03:12:45 [2025-09-23T03:12:45Z] POST /v1/user from 203.0.113.10`,
		`2025/09/23 03:12:47 Failed to query DB: Error 1062 (23000): Duplicate entry`,
		`[GIN-debug] Listening and serving HTTP on :8080`,
		// k8s API read: RFC3339 prefix; EKS shipper: JSON-wrapped with \" around the path.
		`2026-08-20T09:13:06.402Z {"log":"[GIN] 2025/09/23 - 03:12:54 | 403 |     3.456ms |   203.0.113.10 | POST     \"/v1/user\"\n","stream":"stdout"}`,
	}
	a := AnalyzeRequestLog(lines)
	if len(a.Entries) != 7 {
		t.Fatalf("entries=%d %+v", len(a.Entries), a.Entries)
	}
	want := []struct {
		method, path string
		status       int
		ms           float64
		ip, rid      string
	}{
		{"POST", "/v1/user", 201, 12.346, "203.0.113.10", ""},
		{"GET", "/v1/user", 200, 0.046, "203.0.113.10", "999999999999"},
		{"POST", "/v1/stress", 500, 1234.568, "203.0.113.10", ""},
		{"GET", "/v1/none", 404, 0.003, "203.0.113.11", ""},
		{"GET", "/healthcheck", 200, 62000, "10.0.1.5", ""},
		{"GET", "/healthcheck", 200, 0.001, "10.0.1.5", ""},
		{"POST", "/v1/user", 403, 3.456, "203.0.113.10", ""},
	}
	for i, w := range want {
		e := a.Entries[i]
		if e.Method != w.method || e.Path != w.path || e.Status != w.status || e.LatencyMs != w.ms || e.ClientIP != w.ip || e.RequestID != w.rid {
			t.Errorf("entry %d: got %+v want %+v", i, e, w)
		}
	}
	if len(a.NonOkEntries) != 3 {
		t.Fatalf("nonOk=%d %+v", len(a.NonOkEntries), a.NonOkEntries)
	}
	// Grouped by route, not by the full URI — the requestid query must not
	// split /v1/user into one row per request.
	byPath := map[string]types.PathLatencyStat{}
	for _, p := range a.ByPath {
		byPath[p.Path] = p
	}
	if byPath["/v1/user"].Count != 3 || byPath["/v1/user"].NonOkCount != 1 {
		t.Fatalf("/v1/user stats: %+v", byPath["/v1/user"])
	}
	// The DB error is an error line; the access lines and the arrival line are not.
	if len(a.ErrorWarnLines) != 1 || !strings.Contains(a.ErrorWarnLines[0], "Failed to query DB") {
		t.Fatalf("errorWarnLines=%v", a.ErrorWarnLines)
	}
}

func TestDurationMs(t *testing.T) {
	cases := map[string]float64{
		"850ns": 0.00085, "45.678µs": 0.045678, "45.678us": 0.045678,
		"12.345678ms": 12.345678, "1.234567891s": 1234.567891, "1m2s": 62000, "1h0m0s": 3600000,
	}
	for in, want := range cases {
		got, ok := DurationMs(in)
		if !ok || (got-want) > 1e-9 || (want-got) > 1e-9 {
			t.Errorf("%q: got %v ok=%v want %v", in, got, ok, want)
		}
	}
	if _, ok := DurationMs("fast"); ok {
		t.Error("garbage must not parse")
	}
}

func TestRequestIDOf(t *testing.T) {
	cases := map[string]string{
		"/v1/user?email=a%40b.org&requestid=999999999999&uuid=x": "999999999999",
		"/v1/product?id=1&requestid=abc-1":                       "abc-1",
		"/v1/user":                                               "",
		"/v1/user?uuid=only":                                     "",
	}
	for in, want := range cases {
		if got := RequestIDOf(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestCleanURI(t *testing.T) {
	if got := CleanURI(`/v1/user?requestid=2\`, false); got != "/v1/user?requestid=2" {
		t.Errorf("trailing backslash: %q", got)
	}
	if got := CleanURI("/v1/user?requestid=2", true); got != "/v1/user" {
		t.Errorf("route: %q", got)
	}
}

// The Insights chain has to name the fields every query downstream reads, and
// the pattern form is the one verified against a real log group (see
// logfields.go) — a well-meaning "tightening" with a backslash breaks it.
func TestParseFieldsShape(t *testing.T) {
	for _, f := range []string{"(?<status>", "(?<lat_num>", "(?<lat_unit>", "(?<client_ip>", "(?<method>", "(?<uri>", "as latency_ms", "(?<path>", "(?<requestid>"} {
		if !strings.Contains(ParseFields, f) {
			t.Errorf("ParseFields lacks %s", f)
		}
	}
	if !strings.Contains(GinParse, `.?"(?<uri>[^"]*)`) || strings.Contains(ParseFields, "\\\\") {
		t.Errorf("GinParse must keep the backslash-free form that was verified against Insights: %s", GinParse)
	}
	if !strings.HasPrefix(ParseFields, "parse @message /") {
		t.Errorf("ParseFields must read @message so ECS awslogs and EKS Container Insights groups both work")
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

// A metric CloudWatch never returned is a hole in the evidence, not a
// corroborating spike: counting nil metrics as signals let one alarm escalate
// itself to CRITICAL on a cluster that simply does not publish the others.
func TestMissingMetricsDoNotCorroborate(t *testing.T) {
	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	critical := func(key string) types.MetricSummary {
		return types.MetricSummary{Key: key, Status: "CRITICAL", Previous: 1, Current: 99}
	}
	severityOf := func(anomalies []types.Anomaly, typ string) string {
		for _, a := range anomalies {
			if a.Type == typ {
				return a.Severity
			}
		}
		return ""
	}

	// One alarming metric, every other metric absent.
	lone := DetectAnomalies(AnomalyInput{Metrics: []types.MetricSummary{critical("http4xx")}}, now)
	if got := severityOf(lone, "4XX_SPIKE"); got != "WARNING" {
		t.Fatalf("a lone alarm must not reach CRITICAL, got %q", got)
	}

	// Two metrics that were actually measured and are actually abnormal do
	// corroborate each other.
	pair := DetectAnomalies(AnomalyInput{Metrics: []types.MetricSummary{
		critical("http4xx"), critical("http5xx"),
	}}, now)
	if got := severityOf(pair, "4XX_SPIKE"); got != "CRITICAL" {
		t.Fatalf("two measured alarms must corroborate, got %q", got)
	}
}

// The three totals describe everything parsed, not the tail the panel samples.
// They are set precisely when Logs Insights failed and this fallback ran, so a
// blank count is a blank count at the worst possible moment.
func TestAnalyzeRequestLogCountsBeyondTheSampleTail(t *testing.T) {
	lines := []string{}
	for i := 0; i < 600; i++ {
		lines = append(lines,
			`[GIN] 2025/09/23 - 03:12:45 | 500 |   12.345678ms |   203.0.113.10 | POST     "/v1/user"`)
	}
	a := AnalyzeRequestLog(lines)
	if len(a.Entries) != 500 {
		t.Fatalf("sample list should stay capped at 500, got %d", len(a.Entries))
	}
	if a.TotalRequests == nil || *a.TotalRequests != 600 {
		t.Fatalf("totalRequests=%v, want 600", a.TotalRequests)
	}
	if a.NonOkTotal == nil || *a.NonOkTotal != 600 {
		t.Fatalf("nonOkTotal=%v, want 600", a.NonOkTotal)
	}
	// Error/warn lines are sampled at 100 and counted in full.
	errorLines := []string{}
	for i := 0; i < 150; i++ {
		errorLines = append(errorLines, "2025/09/23 03:12:47 Failed to query DB: Error 1062")
	}
	warn := AnalyzeRequestLog(errorLines)
	if len(warn.ErrorWarnLines) != 100 {
		t.Fatalf("errorWarnLines should stay capped at 100, got %d", len(warn.ErrorWarnLines))
	}
	if warn.ErrorWarnTotal == nil || *warn.ErrorWarnTotal != 150 {
		t.Fatalf("errorWarnTotal=%v, want 150", warn.ErrorWarnTotal)
	}
}
