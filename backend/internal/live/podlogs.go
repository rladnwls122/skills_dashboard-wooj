package live

// Pod log reads and the app request-log query, ported from podlogs.ts,
// applog.ts and applogquery.ts. Log reads/aggregations go to CloudWatch Logs
// Insights (bills per byte scanned — results cached 30s, failures 10s); the
// k8s API remains for previous-container logs and as a fallback.

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/analysis"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/awsx"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/cache"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/service"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// Pod/container names reach Logs Insights query strings — refuse anything that
// is not a plain DNS-1123 name instead of trying to escape it.
var podNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

func podScope(pod, container string) (string, error) {
	if !podNameRe.MatchString(pod) {
		return "", fmt.Errorf("invalid pod: %s", pod)
	}
	f := fmt.Sprintf(`kubernetes.pod_name = "%s"`, pod)
	if container != "" {
		if !podNameRe.MatchString(container) {
			return "", fmt.Errorf("invalid container: %s", container)
		}
		f += fmt.Sprintf(` and kubernetes.container_name = "%s"`, container)
	}
	return f, nil
}

type podLogsFetch struct {
	lines        []string
	scannedBytes int64
	windowLabel  string
	source       string // "insights" | "kubernetes"
	analysis     *types.RequestLogAnalysis
}

func clampTail(n int) int {
	if n < 10 {
		return 10
	}
	if n > 2000 {
		return 2000
	}
	return n
}

func (p *Provider) fetchPodLogsInsights(ctx context.Context, params service.PodLogsParams, win types.ResolvedWindow) (podLogsFetch, error) {
	scope, err := podScope(params.Pod, params.Container)
	if err != nil {
		return podLogsFetch{}, err
	}
	tail := clampTail(params.TailLines)
	logGroup := p.Settings.AppLogGroup()
	base := awsx.InsightsParams{LogGroup: logGroup, StartMs: &win.StartMs, EndMs: &win.EndMs}

	run := func(query string) (awsx.InsightsResult, error) {
		q := base
		q.Query = query
		return p.AWS.RunInsightsQuery(ctx, q)
	}

	// The four reads are independent; the semaphore in RunInsightsQuery caps
	// real concurrency at the account-safe limit.
	var (
		wg                                      sync.WaitGroup
		tailQ, statsQ, nonOkQ, errWarnQ         awsx.InsightsResult
		tailErr, statsErr, nonOkErr, errWarnErr error
	)
	launch := func(dst *awsx.InsightsResult, errDst *error, query string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			*dst, *errDst = run(query)
		}()
	}
	launch(&tailQ, &tailErr, fmt.Sprintf("fields @timestamp, log | filter %s | sort @timestamp desc | limit %d", scope, tail))
	launch(&statsQ, &statsErr, fmt.Sprintf("filter %s | %s | filter ispresent(path) | stats count(*) as cnt, avg(latency_ms) as avgMs, max(latency_ms) as maxMs, sum(status >= 300) as nonOk by path | sort cnt desc | limit 1000", scope, analysis.ParseFields))
	launch(&nonOkQ, &nonOkErr, fmt.Sprintf("filter %s | %s | filter status >= 300 | display @timestamp, method, path, status, latency_ms | sort @timestamp desc | limit 100", scope, analysis.ParseFields))
	launch(&errWarnQ, &errWarnErr, fmt.Sprintf("fields @timestamp, log | filter %s and log like /(?i)(error|warn)/ | sort @timestamp desc | limit 100", scope))
	wg.Wait()

	if tailErr != nil {
		return podLogsFetch{}, tailErr
	}

	lines := make([]string, 0, len(tailQ.Rows))
	for i := len(tailQ.Rows) - 1; i >= 0; i-- {
		r := tailQ.Rows[i]
		lines = append(lines, analysis.ToIso(r["@timestamp"])+" "+r["log"])
	}
	lines = analysis.MaskLines(lines)

	fetch := podLogsFetch{
		lines:        lines,
		scannedBytes: tailQ.BytesScanned,
		windowLabel:  tailQ.WindowLabel,
		source:       "insights",
	}

	if statsErr == nil {
		fetch.scannedBytes += statsQ.BytesScanned
		byPath := []types.PathLatencyStat{}
		totalRequests := 0
		weighted := 0.0
		maxLatency := 0.0
		nonOkFromStats := 0
		for _, r := range statsQ.Rows {
			cnt := atoiF(r["cnt"])
			avg := math.Round(parseF(r["avgMs"])*100) / 100
			max := math.Round(parseF(r["maxMs"])*100) / 100
			nonOk := atoiF(r["nonOk"])
			byPath = append(byPath, types.PathLatencyStat{
				Path: r["path"], Count: cnt, AvgLatencyMs: avg, MaxLatencyMs: max, NonOkCount: nonOk,
			})
			totalRequests += cnt
			weighted += avg * float64(cnt)
			if max > maxLatency {
				maxLatency = max
			}
			nonOkFromStats += nonOk
		}

		nonOkEntries := []types.RequestLogEntry{}
		nonOkTotal := nonOkFromStats
		if nonOkErr == nil {
			fetch.scannedBytes += nonOkQ.BytesScanned
			nonOkTotal = int(nonOkQ.RecordsMatched)
			for _, r := range nonOkQ.Rows {
				nonOkEntries = append(nonOkEntries, types.RequestLogEntry{
					Ts:        analysis.Hhmmss(analysis.ToIso(r["@timestamp"])),
					Method:    r["method"],
					Path:      r["path"],
					Status:    atoiF(r["status"]),
					LatencyMs: parseF(r["latency_ms"]),
				})
			}
		}

		errorWarnLines := []string{}
		errorWarnTotal := 0
		if errWarnErr == nil {
			fetch.scannedBytes += errWarnQ.BytesScanned
			errorWarnTotal = int(errWarnQ.RecordsMatched)
			for _, r := range errWarnQ.Rows {
				errorWarnLines = append(errorWarnLines, analysis.ToIso(r["@timestamp"])+" "+r["log"])
			}
			errorWarnLines = analysis.MaskLines(errorWarnLines)
		}

		var avgP, maxP *float64
		if totalRequests > 0 {
			avgP = types.Ptr(math.Round(weighted/float64(totalRequests)*100) / 100)
		}
		if len(byPath) > 0 {
			maxP = types.Ptr(maxLatency)
		}
		if len(byPath) > 20 {
			byPath = byPath[:20]
		}
		fetch.analysis = &types.RequestLogAnalysis{
			Entries:        []types.RequestLogEntry{},
			NonOkEntries:   nonOkEntries,
			ErrorWarnLines: errorWarnLines,
			AvgLatencyMs:   avgP,
			MaxLatencyMs:   maxP,
			ByPath:         byPath,
			TotalRequests:  types.Ptr(totalRequests),
			NonOkTotal:     types.Ptr(nonOkTotal),
			ErrorWarnTotal: types.Ptr(errorWarnTotal),
			Basis:          types.Ptr(fmt.Sprintf("Logs Insights %s 전체 (샘플 목록은 최근 100건)", fetch.windowLabel)),
		}
	}

	return fetch, nil
}

func (p *Provider) fetchPodLogsKube(ctx context.Context, params service.PodLogsParams) (podLogsFetch, error) {
	lines, err := p.Kube.GetPodLogs(ctx, params.Pod, params.Container, params.Previous, params.TailLines)
	if err != nil {
		return podLogsFetch{}, err
	}
	return podLogsFetch{
		lines:       lines,
		windowLabel: fmt.Sprintf("tail %d", params.TailLines),
		source:      "kubernetes",
	}, nil
}

func (p *Provider) PodLogs(ctx context.Context, params service.PodLogsParams, win types.ResolvedWindow) (types.PodLogsResult, error) {
	key := fmt.Sprintf("logs:%s:%s:%t:%d:%s", params.Pod, params.Container, params.Previous, params.TailLines, windowKey(win))
	fetched, err := cache.Cached(key, config.Polling.LogCacheTTL, func() (podLogsFetch, error) {
		if params.Previous {
			return p.fetchPodLogsKube(ctx, params)
		}
		if f, err := p.fetchPodLogsInsights(ctx, params, win); err == nil {
			return f, nil
		}
		return p.fetchPodLogsKube(ctx, params)
	}, config.Polling.LogFailTTL)
	if err != nil {
		return types.PodLogsResult{}, err
	}

	fingerprints := analysis.AggregateFingerprints([]analysis.PodLines{{Pod: params.Pod, Lines: fetched.lines}})
	requestLog := types.RequestLogAnalysis{}
	if fetched.analysis != nil {
		requestLog = *fetched.analysis
	} else {
		requestLog = analysis.AnalyzeRequestLog(fetched.lines)
		requestLog.Basis = types.Ptr(fmt.Sprintf("tail %d 샘플 (k8s API)", params.TailLines))
	}

	cache.Put("panel:fingerprints", 10*time.Minute, fingerprints)
	lastKey := "panel:lastlogs"
	if params.Previous {
		lastKey = "panel:lastprevlogs"
	}
	cache.Put(lastKey, 10*time.Minute, analysis.LogsRef{
		Pod: params.Pod, Container: params.Container, Previous: params.Previous, Lines: fetched.lines,
	})

	result := types.PodLogsResult{
		Lines:        fetched.lines,
		Container:    params.Container,
		Previous:     params.Previous,
		Fingerprints: fingerprints,
		RequestLog:   requestLog,
		Source:       fetched.source,
		WindowLabel:  fetched.windowLabel,
	}
	if fetched.source == "insights" {
		result.ScannedBytes = types.Ptr(fetched.scannedBytes)
	} else {
		result.ScannedBytes = types.Ptr(int64(0))
	}
	return result, nil
}

func parseF(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func atoiF(s string) int { return int(parseF(s)) }

// --- app request-log query ---------------------------------------------------

const (
	rowLimit      = 200
	pathFilterMax = 120
)

var statusRange = map[string][2]int{
	"2xx": {200, 300}, "3xx": {300, 400}, "4xx": {400, 500}, "5xx": {500, 600},
}

// The filter is interpolated into an Insights query string inside double
// quotes. The allowed set excludes both the quote and the backslash, so no
// escaping is reachable — this validation is the whole guarantee.
var pathFilterRe = regexp.MustCompile(`^[A-Za-z0-9/_.-]*$`)

func validatePathFilter(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if len(v) > pathFilterMax {
		return "", fmt.Errorf("경로 검색어가 너무 김 (최대 %d자)", pathFilterMax)
	}
	if !pathFilterRe.MatchString(v) {
		return "", fmt.Errorf("경로 검색어에 허용되지 않는 문자가 있음 (영문·숫자와 / _ . - 만 가능)")
	}
	return v, nil
}

func buildRequestLogQuery(statusClass, pathContains string) (string, error) {
	parts := []string{analysis.ParseFields, "filter ispresent(status)"}
	if statusClass != "ALL" {
		r, ok := statusRange[statusClass]
		if !ok {
			return "", fmt.Errorf("알 수 없는 상태 클래스: %s", statusClass)
		}
		parts = append(parts, fmt.Sprintf("filter status >= %d and status < %d", r[0], r[1]))
	}
	path, err := validatePathFilter(pathContains)
	if err != nil {
		return "", err
	}
	if path != "" {
		parts = append(parts, fmt.Sprintf(`filter path like "%s"`, path))
	}
	parts = append(parts,
		"display @timestamp, method, path, status, latency_ms",
		"sort @timestamp desc",
		fmt.Sprintf("limit %d", rowLimit),
	)
	return strings.Join(parts, " | "), nil
}

func (p *Provider) RequestLogRows(ctx context.Context, params service.RequestLogParams, win types.ResolvedWindow) (types.RequestLogQueryResult, error) {
	// Validation lives in the query builder and fails before anything is
	// cached — a rejected filter is a user error, not a cacheable result.
	query, err := buildRequestLogQuery(params.StatusClass, params.PathContains)
	if err != nil {
		return types.RequestLogQueryResult{}, err
	}
	key := fmt.Sprintf("applog:rows:%s:%s:%d-%d", params.StatusClass, params.PathContains, win.WindowMin, win.EndMs)
	return cache.Cached(key, config.Polling.LogCacheTTL, func() (types.RequestLogQueryResult, error) {
		res, err := p.AWS.RunInsightsQuery(ctx, awsx.InsightsParams{
			LogGroup: p.Settings.AppLogGroup(),
			Query:    query,
			StartMs:  &win.StartMs,
			EndMs:    &win.EndMs,
		})
		if err != nil {
			return types.RequestLogQueryResult{}, err
		}
		rows := make([]types.RequestLogRow, 0, len(res.Rows))
		for _, r := range res.Rows {
			rows = append(rows, types.RequestLogRow{
				Ts:        analysis.ToIso(r["@timestamp"]),
				Method:    r["method"],
				Path:      r["path"],
				Status:    atoiF(r["status"]),
				LatencyMs: parseF(r["latency_ms"]),
			})
		}
		return types.RequestLogQueryResult{
			Rows:         rows,
			TotalMatched: res.RecordsMatched,
			ScannedBytes: res.BytesScanned,
			WindowLabel:  res.WindowLabel,
			Truncated:    len(rows) >= rowLimit,
		}, nil
	}, config.Polling.LogFailTTL)
}
