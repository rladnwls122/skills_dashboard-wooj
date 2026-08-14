package analysis

// Access-log parsing from raw pod log lines (spec item 1), ported from
// requestlog.ts. Lines are already masked upstream.

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// Parses Go/Gin's default access-log line, e.g.:
//
//	[GIN] 2026/08/09 - 12:00:00 | 200 |     1.234ms |   127.0.0.1 | GET      "/v1/user"
//
// Falls back to a generic "METHOD /path -> STATUS Nms" shape.
var (
	ginRe     = regexp.MustCompile(`\[GIN\]\s+\S+\s+-\s+(\d{2}:\d{2}:\d{2})\s*\|\s*(\d{3})\s*\|\s*([\d.]+)(µs|ms|s|ns)\s*\|[^|]*\|\s*(\S+)\s+"([^"]+)"`)
	genericRe = regexp.MustCompile(`(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\D+?(\d{3})\D+?([\d.]+)\s*(µs|ms|s|ns)?`)
	errWarnRe = regexp.MustCompile(`(?i)\b(error|warn|warning)\b`)
)

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

func parseLine(line string) *types.RequestLogEntry {
	if m := ginRe.FindStringSubmatch(line); m != nil {
		status, _ := strconv.Atoi(m[2])
		lat, _ := strconv.ParseFloat(m[3], 64)
		return &types.RequestLogEntry{
			Ts:        m[1],
			Method:    m[5],
			Path:      stripQuery(m[6]),
			Status:    status,
			LatencyMs: round3(toMs(lat, m[4])),
		}
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
		if e.Status != 200 && e.Status != 201 {
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
		if e.Status != 200 && e.Status != 201 {
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
	}
}
