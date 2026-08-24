package analysis

// Access-log parsing from raw pod/container log lines (spec item 1). Lines are
// already masked upstream. The line shape is gin's default logger — what all
// three competition binaries print (see logfields.go / docs/binaries.md).

import (
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

var (
	// [GIN] 2025/09/23 - 03:12:45 | 201 |   12.345678ms |   203.0.113.10 | POST     "/v1/user?requestid=1"
	// The k8s API prefixes its own RFC3339 timestamp and the EKS log shipper
	// may wrap the line in JSON; neither is anchored on, and the optional
	// backslash before the quote is the JSON-escaped form.
	ginRe = regexp.MustCompile(`\[GIN\]\s+(\d{4}/\d{2}/\d{2}) - (\d{2}:\d{2}:\d{2})\s*\|\s*(\d{3})\s*\|\s*([^\s|]+)\s*\|\s*([^\s|]+)\s*\|\s*([A-Z]+)\s+\\?"([^"\\]*)`)
	// The custom middleware line: 2025/09/23 03:12:45 [2025-09-23T03:12:45Z] POST /v1/user from 203.0.113.10
	// Logged before the handler runs, so it has no status — it duplicates the
	// [GIN] line that follows and must not be counted as a second request.
	arrivalRe = regexp.MustCompile(`\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\]]*)\]\s+([A-Z]+)\s+(\S+)\s+from\s+(\S+)`)
	// Generic "METHOD /path -> STATUS Nms" fallback for anything else.
	genericRe = regexp.MustCompile(`(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\D+?(\d{3})\D+?([\d.]+)\s*(µs|ms|s|ns)?`)
	errWarnRe = regexp.MustCompile(`(?i)\b(error|warn|warning|fail|failed|panic|fatal|malicious)\b`)
)

// DurationMs parses a Go time.Duration as printed by String() — "850ns",
// "45.678µs", "12.345678ms", "1.2s", "1m2s" (gin truncates anything past a
// minute to whole seconds). The unit is taken literally so "ms" is never
// mistaken for "s".
func DurationMs(token string) (float64, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0, false
	}
	// Go's parser accepts both "µs" and "us"; the logger writes "µs".
	d, err := time.ParseDuration(token)
	if err != nil {
		return 0, false
	}
	return float64(d) / float64(time.Millisecond), true
}

func toMs(value float64, unit string) float64 {
	switch unit {
	case "ns":
		return value / 1_000_000
	case "µs":
		return value / 1_000
	case "s":
		return value * 1000
	default:
		return value
	}
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }
func round2(v float64) float64 { return math.Round(v*100) / 100 }

func stripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// RequestIDOf reads the grader's requestid out of a logged URI. "" when the
// request did not carry one in the query string (POST bodies are not logged).
func RequestIDOf(uri string) string {
	i := strings.IndexByte(uri, '?')
	if i < 0 {
		return ""
	}
	q, err := url.ParseQuery(uri[i+1:])
	if err == nil {
		return q.Get("requestid")
	}
	// A malformed query usually still has the key readable.
	for _, pair := range strings.Split(uri[i+1:], "&") {
		if strings.HasPrefix(pair, "requestid=") {
			return strings.TrimPrefix(pair, "requestid=")
		}
	}
	return ""
}

// ParseAccessLine reads one gin access-log line. nil when the line is not one.
func ParseAccessLine(line string) *types.RequestLogEntry {
	m := ginRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	status, _ := strconv.Atoi(m[3])
	lat, ok := DurationMs(m[4])
	if !ok {
		lat = 0
	}
	uri := CleanURI(m[7], false)
	return &types.RequestLogEntry{
		Ts:        m[2],
		Method:    m[6],
		Path:      stripQuery(uri),
		Status:    status,
		LatencyMs: round3(lat),
		ClientIP:  m[5],
		RequestID: RequestIDOf(uri),
	}
}

// IsArrivalLine reports whether the line is the binaries' custom middleware
// line ("[ts] METHOD /path from IP") — a request that arrived, status unknown.
func IsArrivalLine(line string) bool { return arrivalRe.MatchString(line) }

func parseLine(line string) *types.RequestLogEntry {
	if e := ParseAccessLine(line); e != nil {
		return e
	}
	if arrivalRe.MatchString(line) {
		return nil
	}
	if m := genericRe.FindStringSubmatch(line); m != nil {
		status, _ := strconv.Atoi(m[3])
		latency := 0.0
		if m[4] != "" {
			lat, _ := strconv.ParseFloat(m[4], 64)
			unit := m[5]
			if unit == "" {
				unit = "ms"
			}
			latency = round3(toMs(lat, unit))
		}
		return &types.RequestLogEntry{
			Ts:        "",
			Method:    strings.ToUpper(m[1]),
			Path:      stripQuery(m[2]),
			Status:    status,
			LatencyMs: latency,
		}
	}
	return nil
}

func isNonOk(status int) bool { return status < 200 || status >= 300 }

// AnalyzeRequestLog extracts latency / non-2xx responses / error-warn lines
// from raw pod log lines.
func AnalyzeRequestLog(lines []string) types.RequestLogAnalysis {
	entries := []types.RequestLogEntry{}
	errorWarnLines := []string{}

	for _, line := range lines {
		if e := parseLine(line); e != nil {
			entries = append(entries, *e)
		}
		if errWarnRe.MatchString(line) {
			errorWarnLines = append(errorWarnLines, line)
		}
	}

	nonOkEntries := []types.RequestLogEntry{}
	for _, e := range entries {
		if isNonOk(e.Status) {
			nonOkEntries = append(nonOkEntries, e)
		}
	}

	type pathAcc struct {
		count int
		sum   float64
		max   float64
		nonOk int
	}
	byPathMap := map[string]*pathAcc{}
	pathOrder := []string{}
	for _, e := range entries {
		s, ok := byPathMap[e.Path]
		if !ok {
			s = &pathAcc{}
			byPathMap[e.Path] = s
			pathOrder = append(pathOrder, e.Path)
		}
		s.count++
		s.sum += e.LatencyMs
		if e.LatencyMs > s.max {
			s.max = e.LatencyMs
		}
		if isNonOk(e.Status) {
			s.nonOk++
		}
	}
	byPath := make([]types.PathLatencyStat, 0, len(pathOrder))
	for _, path := range pathOrder {
		s := byPathMap[path]
		byPath = append(byPath, types.PathLatencyStat{
			Path:         path,
			Count:        s.count,
			AvgLatencyMs: round2(s.sum / float64(s.count)),
			MaxLatencyMs: round2(s.max),
			NonOkCount:   s.nonOk,
		})
	}
	sort.SliceStable(byPath, func(i, j int) bool { return byPath[i].Count > byPath[j].Count })
	if len(byPath) > 20 {
		byPath = byPath[:20]
	}

	var avgLatency, maxLatency *float64
	if len(entries) > 0 {
		sum, max := 0.0, 0.0
		for _, e := range entries {
			sum += e.LatencyMs
			if e.LatencyMs > max {
				max = e.LatencyMs
			}
		}
		avgLatency = types.Ptr(round2(sum / float64(len(entries))))
		maxLatency = types.Ptr(round2(max))
	}

	tail := func(list []types.RequestLogEntry, n int) []types.RequestLogEntry {
		if len(list) > n {
			return list[len(list)-n:]
		}
		return list
	}
	tailStr := errorWarnLines
	if len(tailStr) > 100 {
		tailStr = tailStr[len(tailStr)-100:]
	}

	return types.RequestLogAnalysis{
		Entries:        tail(entries, 500),
		NonOkEntries:   tail(nonOkEntries, 100),
		ErrorWarnLines: tailStr,
		AvgLatencyMs:   avgLatency,
		MaxLatencyMs:   maxLatency,
		ByPath:         byPath,
		// Counted over everything parsed, not over the truncated sample lists
		// above — the panel prints these three as the totals, and a tail of 500
		// entries would understate a 3,000-line fetch. Leaving them unset was
		// worse still: this function runs exactly when Logs Insights failed and
		// the Kubernetes fallback fired, so the counts went blank at the one
		// moment the operator was already looking at a degraded panel and
		// needed to know how much traffic it had actually seen. The Insights
		// path (internal/live/podlogs.go) fills the same three fields from
		// RecordsMatched.
		TotalRequests:  types.Ptr(len(entries)),
		NonOkTotal:     types.Ptr(len(nonOkEntries)),
		ErrorWarnTotal: types.Ptr(len(errorWarnLines)),
	}
}
