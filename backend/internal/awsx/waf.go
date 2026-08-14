package awsx

// WAF reads and the HTTP traffic summary, ported from waf.ts and waflogagg.ts.

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/cache"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type aclHandle struct {
	webACL    *waftypes.WebACL
	lockToken string
	arn       string
}

func (a *AWS) getAclHandle(ctx context.Context) (aclHandle, error) {
	client, err := a.wafClient(ctx, a.Settings.WafRegion())
	if err != nil {
		return aclHandle{}, err
	}
	scope := waftypes.Scope(a.Settings.WafScope())
	list, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{Scope: scope})
	if err != nil {
		return aclHandle{}, err
	}
	name := a.Settings.WafWebAclName()
	var summary *waftypes.WebACLSummary
	for i := range list.WebACLs {
		if aws.ToString(list.WebACLs[i].Name) == name {
			summary = &list.WebACLs[i]
			break
		}
	}
	if summary == nil && len(list.WebACLs) > 0 {
		summary = &list.WebACLs[0]
	}
	if summary == nil || summary.Name == nil || summary.Id == nil || summary.ARN == nil {
		return aclHandle{}, fmt.Errorf("WebACL not found (scope=%s, name=%s)", scope, name)
	}
	res, err := client.GetWebACL(ctx, &wafv2.GetWebACLInput{Name: summary.Name, Id: summary.Id, Scope: scope})
	if err != nil {
		return aclHandle{}, err
	}
	if res.WebACL == nil || res.LockToken == nil {
		return aclHandle{}, fmt.Errorf("GetWebACL returned empty result")
	}
	return aclHandle{webACL: res.WebACL, lockToken: *res.LockToken, arn: *summary.ARN}, nil
}

func (a *AWS) GetAclInfo(ctx context.Context) (types.WafAclInfo, error) {
	h, err := a.getAclHandle(ctx)
	if err != nil {
		return types.WafAclInfo{}, err
	}
	acl := h.webACL
	rules := make([]types.WafAclRule, 0, len(acl.Rules))
	for _, r := range acl.Rules {
		action := "GROUP"
		switch {
		case r.Action != nil && r.Action.Block != nil:
			action = "BLOCK"
		case r.Action != nil && r.Action.Count != nil:
			action = "COUNT"
		case r.OverrideAction != nil && r.OverrideAction.Count != nil:
			action = "COUNT(override)"
		case r.Action != nil && r.Action.Allow != nil:
			action = "ALLOW"
		}
		rules = append(rules, types.WafAclRule{
			Name:     aws.ToString(r.Name),
			Priority: int(r.Priority),
			Action:   action,
		})
	}
	return types.WafAclInfo{
		Name:         aws.ToString(acl.Name),
		ID:           aws.ToString(acl.Id),
		Scope:        a.Settings.WafScope(),
		CapacityUsed: acl.Capacity,
		RuleCount:    len(acl.Rules),
		Rules:        rules,
	}, nil
}

// --- sampled requests --------------------------------------------------------

type SampleSet struct {
	Samples       []waftypes.SampledHTTPRequest
	WindowMinutes int
}

func (a *AWS) FetchSampledRequests(ctx context.Context) (SampleSet, error) {
	return cache.Cached("waf:samples", 30*time.Second, func() (SampleSet, error) {
		client, err := a.wafClient(ctx, a.Settings.WafRegion())
		if err != nil {
			return SampleSet{}, err
		}
		h, err := a.getAclHandle(ctx)
		if err != nil {
			return SampleSet{}, err
		}
		end := time.Now()
		start := end.Add(-time.Duration(config.WafLimits.SampleWindowMinutes) * time.Minute)
		metricNames := map[string]struct{}{}
		order := []string{}
		add := func(name string) {
			if name == "" {
				return
			}
			if _, ok := metricNames[name]; !ok {
				metricNames[name] = struct{}{}
				order = append(order, name)
			}
		}
		if h.webACL.VisibilityConfig != nil {
			add(aws.ToString(h.webACL.VisibilityConfig.MetricName))
		}
		for _, r := range h.webACL.Rules {
			if r.VisibilityConfig != nil {
				add(aws.ToString(r.VisibilityConfig.MetricName))
			}
		}
		samples := []waftypes.SampledHTTPRequest{}
		for _, metricName := range order {
			// one rule's samples failing must not kill the whole set
			res, err := client.GetSampledRequests(ctx, &wafv2.GetSampledRequestsInput{
				WebAclArn:      aws.String(h.arn),
				RuleMetricName: aws.String(metricName),
				Scope:          waftypes.Scope(a.Settings.WafScope()),
				TimeWindow:     &waftypes.TimeWindow{StartTime: aws.Time(start), EndTime: aws.Time(end)},
				MaxItems:       aws.Int64(500),
			})
			if err != nil {
				continue
			}
			samples = append(samples, res.SampledRequests...)
		}
		return SampleSet{Samples: samples, WindowMinutes: config.WafLimits.SampleWindowMinutes}, nil
	}, 0)
}

func sampleURI(s waftypes.SampledHTTPRequest) string {
	if s.Request == nil {
		return ""
	}
	return aws.ToString(s.Request.URI)
}

func samplePath(s waftypes.SampledHTTPRequest) string {
	uri := sampleURI(s)
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
}

func sampleQuery(s waftypes.SampledHTTPRequest) string {
	uri := sampleURI(s)
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[i+1:]
	}
	return ""
}

func sampleHeader(s waftypes.SampledHTTPRequest, name string) string {
	if s.Request == nil {
		return ""
	}
	for _, h := range s.Request.Headers {
		if strings.ToLower(aws.ToString(h.Name)) == name {
			return aws.ToString(h.Value)
		}
	}
	return ""
}

var boringHeaders = map[string]struct{}{
	"host": {}, "user-agent": {}, "accept": {}, "accept-encoding": {},
	"accept-language": {}, "content-type": {}, "content-length": {},
	"connection": {}, "x-forwarded-for": {}, "x-forwarded-proto": {},
	"x-forwarded-port": {}, "x-amzn-trace-id": {}, "via": {}, "cookie": {},
	"authorization": {},
}

// counter preserves first-seen order so ties sort the way the TS Maps did.
type counter struct {
	counts map[string]int
	order  []string
}

func newCounter() *counter { return &counter{counts: map[string]int{}} }

func (c *counter) add(key string, n int) {
	if _, ok := c.counts[key]; !ok {
		c.order = append(c.order, key)
	}
	c.counts[key] += n
}

func (c *counter) top(n int) []types.KeyCount {
	out := make([]types.KeyCount, 0, len(c.order))
	for _, k := range c.order {
		out = append(out, types.KeyCount{Key: k, Count: c.counts[k]})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// Why the Insights path was skipped on the most recent call, so the fallback's
// source line can say it instead of silently reading as the intended source.
var (
	insightsFallbackMu     sync.Mutex
	insightsFallbackReason string
)

// EmptySampleNotes explains an empty panel: GetSampledRequests only samples
// requests that a rule matched, so "no samples" means "nothing was collected",
// not "nothing suspicious is happening".
func EmptySampleNotes(total int) []string {
	if total > 0 {
		return []string{}
	}
	return []string{
		"샘플 0건 — 트래픽이 없다는 뜻이 아니라 수집되지 않았다는 뜻입니다. WAF GetSampledRequests 는 규칙에 매칭된 요청만 표본으로 남기므로, 아무 규칙도 매칭하지 않는 WebACL 에서는 항상 0건입니다.",
		"따라서 경로·IP·User-Agent 통계가 전부 비어 있고, 이 상태에서는 UA 규칙을 조립할 수 없습니다.",
		"채우는 방법 ①: WAF 로깅을 CloudWatch Logs 로 켜고 .env 의 WAF_LOG_GROUP 을 그 로그 그룹으로 지정 — 표본이 아닌 전수 집계로 바뀝니다.",
		"채우는 방법 ②: WebACL 에 광범위한 COUNT 규칙을 하나 추가 — 차단 없이 매칭만 시켜 표본을 만듭니다.",
		"앱 액세스 로그로는 대체할 수 없습니다 — 이 환경의 앱 로그에는 user_agent 필드가 없습니다(app · client_ip · latency_ms · method · path · status · ts).",
	}
}

func (a *AWS) BuildHttpSummary(ctx context.Context, statusDist *types.StatusDistribution, win types.ResolvedWindow) (types.HttpSummary, error) {
	// Real counts over the shared window when WAF logs are available; the
	// sampled-requests path below is the fallback and says so.
	if logGroup := a.Settings.WafLogGroup(); logGroup != "" {
		agg, err := a.fetchWafLogInsightsCached(ctx, win)
		if err == nil {
			return types.HttpSummary{
				TotalSampled: agg.total,
				WindowLabel:  win.Label,
				Source: fmt.Sprintf("WAF 로그 Logs Insights(%s) · 구간 %s · 스캔 %s · 표본이 아닌 전수 집계%s",
					logGroup, win.Label, FmtBytes(agg.bytesScanned), insightsAgeNote(agg.coveredEndMs, time.Now().UnixMilli())),
				ByPath:         agg.byPath,
				ByIp:           agg.byIP,
				ByUa:           agg.byUa,
				ByMethod:       agg.byMethod,
				QueryPatterns:  agg.queryPatterns,
				HeaderPatterns: []types.KeyCount{},
				BlockedTotal:   agg.blockedTotal,
				StatusDist:     statusDist,
				DetailedStatus: nil,
				Notes: []string{
					"헤더 패턴은 WAF 로그 집계에서 수집하지 않음 — 헤더는 요청마다 순서가 달라 인덱스로 집계할 수 없다. 샘플 모드(WAF_LOG_GROUP 미설정)에서만 나온다.",
				},
			}, nil
		}
		// Fall through to sampling, but say why the better source is missing.
		insightsFallbackMu.Lock()
		insightsFallbackReason = ErrMsg(err)
		insightsFallbackMu.Unlock()
	}

	set, err := a.FetchSampledRequests(ctx)
	if err != nil {
		return types.HttpSummary{}, err
	}
	type pathCount struct {
		count   int
		blocked int
	}
	byPathMap := map[string]*pathCount{}
	pathOrder := []string{}
	byIP := newCounter()
	byUa := newCounter()
	byMethod := newCounter()
	byQuery := newCounter()
	byHeader := newCounter()

	for _, s := range set.Samples {
		path := samplePath(s)
		entry, ok := byPathMap[path]
		if !ok {
			entry = &pathCount{}
			byPathMap[path] = entry
			pathOrder = append(pathOrder, path)
		}
		entry.count++
		if aws.ToString(s.Action) == "BLOCK" {
			entry.blocked++
		}
		if s.Request != nil {
			if ip := aws.ToString(s.Request.ClientIP); ip != "" {
				byIP.add(ip, 1)
			}
			if method := aws.ToString(s.Request.Method); method != "" {
				byMethod.add(method, 1)
			}
		}
		ua := sampleHeader(s, "user-agent")
		if ua == "" {
			ua = "(empty UA)"
		}
		byUa.add(ua, 1)
		if query := sampleQuery(s); query != "" {
			byQuery.add(truncateStr(query, 120), 1)
		}
		if s.Request != nil {
			for _, h := range s.Request.Headers {
				name := strings.ToLower(aws.ToString(h.Name))
				if name == "" {
					continue
				}
				if _, boring := boringHeaders[name]; boring {
					continue
				}
				byHeader.add(name+": "+truncateStr(aws.ToString(h.Value), 60), 1)
			}
		}
	}

	total := len(set.Samples)
	// Full-population blocked count, taken before byPath is truncated to 20.
	blockedTotal := 0
	for _, v := range byPathMap {
		blockedTotal += v.blocked
	}

	pathStats := make([]types.PathStat, 0, len(pathOrder))
	for _, path := range pathOrder {
		v := byPathMap[path]
		pathStats = append(pathStats, types.PathStat{
			Path:        path,
			Count:       v.count,
			Blocked:     v.blocked,
			LowPriority: config.IsLowPriorityPath(path),
			Suspicious:  config.IsPathSuspicious(path, v.count, total),
		})
	}
	sort.SliceStable(pathStats, func(i, j int) bool { return pathStats[i].Count > pathStats[j].Count })
	if len(pathStats) > 20 {
		pathStats = pathStats[:20]
	}

	source := fmt.Sprintf("WAF GetSampledRequests (최근 %d분, 샘플 %d건 — 규칙당 500건 상한이라 전수가 아님, 선택한 구간을 따르지 않음)", set.WindowMinutes, total)
	insightsFallbackMu.Lock()
	if insightsFallbackReason != "" {
		source += " · WAF 로그 집계 실패로 폴백: " + insightsFallbackReason
		insightsFallbackReason = ""
	} else if a.Settings.WafLogGroup() == "" {
		source += " · WAF_LOG_GROUP 을 설정하면 선택 구간의 전수 집계로 바뀜"
	}
	insightsFallbackMu.Unlock()
	if logGroup := a.Settings.WafLogGroup(); logGroup != "" {
		if byIPLog, err := a.fetchWafLogIPCounts(ctx); err == nil {
			for _, r := range byIPLog {
				if cur, ok := byIP.counts[r.Key]; !ok || r.Count > cur {
					byIP.add(r.Key, 0)
					byIP.counts[r.Key] = r.Count
				}
			}
			source += fmt.Sprintf(" + WAF 로그(%s)", logGroup)
		} else {
			source += " (WAF 로그 조회 실패, 샘플만 사용)"
		}
	}

	denom := total
	if denom < 1 {
		denom = 1
	}
	ipStats := []types.IpStat{}
	for _, r := range byIP.top(10) {
		ipStats = append(ipStats, types.IpStat{
			Key:          r.Key,
			Count:        r.Count,
			SharePct:     int(math.Round(float64(r.Count) / float64(denom) * 100)),
			Concentrated: config.IsIPConcentrated(r.Count, total),
		})
	}

	return types.HttpSummary{
		TotalSampled:   total,
		WindowLabel:    fmt.Sprintf("%dm", set.WindowMinutes),
		Source:         source,
		ByPath:         pathStats,
		ByIp:           ipStats,
		ByUa:           byUa.top(10),
		ByMethod:       byMethod.top(8),
		QueryPatterns:  byQuery.top(10),
		HeaderPatterns: byHeader.top(10),
		BlockedTotal:   blockedTotal,
		StatusDist:     statusDist,
		DetailedStatus: nil,
		Notes:          EmptySampleNotes(total),
	}, nil
}

// --- WAF logs via Logs Insights ---------------------------------------------

type wafLogAggregation struct {
	byPath        []types.PathStat
	byIP          []types.IpStat
	byUa          []types.KeyCount
	byMethod      []types.KeyCount
	queryPatterns []types.KeyCount
	total         int
	blockedTotal  int
	bytesScanned  int64
	// End of the span these numbers actually cover — a cached result is older
	// than the window the caller resolved, and the panel has to say so.
	coveredEndMs int64
}

// Keyed by span alone: the aggregation groups by key, never by time bucket, so
// the interval does not change the result.
func (a *AWS) fetchWafLogInsightsCached(ctx context.Context, win types.ResolvedWindow) (wafLogAggregation, error) {
	key := fmt.Sprintf("waf:insights:%s:%d", a.Settings.WafLogGroup(), win.WindowMin)
	return cache.Cached(key, config.WafInsightsTTL, func() (wafLogAggregation, error) {
		return a.fetchWafLogInsights(ctx, win)
	}, config.Polling.LogFailTTL)
}

type folded struct {
	count   int
	blocked int
}

func rowCount(row InsightsRow) int {
	n, err := strconv.ParseFloat(row["cnt"], 64)
	if err != nil {
		return 0
	}
	return int(n)
}

func foldByAction(rows []InsightsRow, keyField string) (map[string]*folded, []string) {
	out := map[string]*folded{}
	order := []string{}
	for _, r := range rows {
		key := r[keyField]
		entry, ok := out[key]
		if !ok {
			entry = &folded{}
			out[key] = entry
			order = append(order, key)
		}
		n := rowCount(r)
		entry.count += n
		if strings.ToUpper(r["action"]) == "BLOCK" {
			entry.blocked += n
		}
	}
	return out, order
}

func insightsAgeNote(coveredEndMs, nowMs int64) string {
	min := (nowMs - coveredEndMs) / 60_000
	if min >= 1 {
		return fmt.Sprintf(" · %d분 전 집계", min)
	}
	return ""
}

func topKeyCounts(rows []InsightsRow, keyField string, n int) []types.KeyCount {
	out := []types.KeyCount{}
	for _, r := range rows {
		if key := r[keyField]; key != "" {
			out = append(out, types.KeyCount{Key: key, Count: rowCount(r)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (a *AWS) fetchWafLogInsights(ctx context.Context, win types.ResolvedWindow) (wafLogAggregation, error) {
	// The region matters and is not the workload region: a CLOUDFRONT-scope
	// WAF only writes its logs in us-east-1.
	base := InsightsParams{
		Region:   a.Settings.WafRegion(),
		LogGroup: a.Settings.WafLogGroup(),
		StartMs:  &win.StartMs,
		EndMs:    &win.EndMs,
	}
	run := func(query string) (InsightsResult, error) {
		p := base
		p.Query = query
		return a.RunInsightsQuery(ctx, p)
	}

	// The User-Agent lives inside httpRequest.headers[], whose index varies per
	// request, so it is pulled off the raw message rather than a JSON field.
	pathRes, err := run("stats count(*) as cnt by httpRequest.uri as path, action | sort cnt desc | limit 200")
	if err != nil {
		return wafLogAggregation{}, err
	}
	ipRes, err := run("stats count(*) as cnt by httpRequest.clientIp as ip, action | sort cnt desc | limit 100")
	if err != nil {
		return wafLogAggregation{}, err
	}
	uaRes, err := run(`parse @message /"name":"(?i)user-agent","value":"(?<ua>[^"]*)"/ | stats count(*) as cnt by ua | sort cnt desc | limit 20`)
	if err != nil {
		return wafLogAggregation{}, err
	}
	methodRes, err := run("stats count(*) as cnt by httpRequest.httpMethod as method | sort cnt desc | limit 10")
	if err != nil {
		return wafLogAggregation{}, err
	}
	argsRes, err := run("filter httpRequest.args != '' | stats count(*) as cnt by httpRequest.args as args | sort cnt desc | limit 20")
	if err != nil {
		return wafLogAggregation{}, err
	}

	pathFolded, pathOrder := foldByAction(pathRes.Rows, "path")
	total, blockedTotal := 0, 0
	for _, v := range pathFolded {
		total += v.count
		blockedTotal += v.blocked
	}

	byPath := make([]types.PathStat, 0, len(pathOrder))
	for _, path := range pathOrder {
		v := pathFolded[path]
		byPath = append(byPath, types.PathStat{
			Path:        path,
			Count:       v.count,
			Blocked:     v.blocked,
			LowPriority: config.IsLowPriorityPath(path),
			Suspicious:  config.IsPathSuspicious(path, v.count, total),
		})
	}
	sort.SliceStable(byPath, func(i, j int) bool { return byPath[i].Count > byPath[j].Count })
	if len(byPath) > 20 {
		byPath = byPath[:20]
	}

	ipFolded, ipOrder := foldByAction(ipRes.Rows, "ip")
	denom := total
	if denom < 1 {
		denom = 1
	}
	byIP := []types.IpStat{}
	for _, key := range ipOrder {
		if key == "" {
			continue
		}
		v := ipFolded[key]
		byIP = append(byIP, types.IpStat{
			Key:          key,
			Count:        v.count,
			SharePct:     int(math.Round(float64(v.count) / float64(denom) * 100)),
			Concentrated: config.IsIPConcentrated(v.count, total),
		})
	}
	sort.SliceStable(byIP, func(i, j int) bool { return byIP[i].Count > byIP[j].Count })
	if len(byIP) > 10 {
		byIP = byIP[:10]
	}

	queryPatterns := []types.KeyCount{}
	for _, r := range topKeyCounts(argsRes.Rows, "args", 10) {
		queryPatterns = append(queryPatterns, types.KeyCount{Key: truncateStr(r.Key, 120), Count: r.Count})
	}

	return wafLogAggregation{
		byPath:        byPath,
		byIP:          byIP,
		byUa:          topKeyCounts(uaRes.Rows, "ua", 10),
		byMethod:      topKeyCounts(methodRes.Rows, "method", 8),
		queryPatterns: queryPatterns,
		total:         total,
		blockedTotal:  blockedTotal,
		bytesScanned:  pathRes.BytesScanned + ipRes.BytesScanned + uaRes.BytesScanned + methodRes.BytesScanned + argsRes.BytesScanned,
		coveredEndMs:  win.EndMs,
	}, nil
}

// fetchWafLogIPCounts: the 15-minute top-IP merge used by the sampling
// fallback (fetchWafLogAggregation in TS).
func (a *AWS) fetchWafLogIPCounts(ctx context.Context) ([]types.KeyCount, error) {
	res, err := a.RunInsightsQuery(ctx, InsightsParams{
		Region:   a.Settings.WafRegion(),
		LogGroup: a.Settings.WafLogGroup(),
		WindowMs: 15 * 60_000,
		Query:    "stats count(*) as cnt by httpRequest.clientIp as ip | sort cnt desc | limit 10",
	})
	if err != nil {
		return nil, err
	}
	out := []types.KeyCount{}
	for _, row := range res.Rows {
		out = append(out, types.KeyCount{Key: row["ip"], Count: rowCount(row)})
	}
	return out, nil
}

// --- sample rows -------------------------------------------------------------

func ToSampleRow(s waftypes.SampledHTTPRequest) types.WafSampleRow {
	ts := ""
	if s.Timestamp != nil {
		ts = s.Timestamp.UTC().Format(time.RFC3339Nano)
	}
	row := types.WafSampleRow{
		Ts:        ts,
		Method:    "",
		Path:      samplePath(s),
		Query:     truncateStr(sampleQuery(s), 120),
		UserAgent: truncateStr(sampleHeader(s, "user-agent"), 80),
		Action:    aws.ToString(s.Action),
		Rule:      aws.ToString(s.RuleNameWithinRuleGroup),
	}
	if s.Request != nil {
		row.IP = aws.ToString(s.Request.ClientIP)
		row.Country = aws.ToString(s.Request.Country)
		row.Method = aws.ToString(s.Request.Method)
	}
	if s.ResponseCodeSent != nil {
		row.ResponseCode = types.Ptr(int(*s.ResponseCodeSent))
	}
	return row
}

// ListSampleRows: raw sampled requests as table rows (newest first, capped at
// 300).
func (a *AWS) ListSampleRows(ctx context.Context) ([]types.WafSampleRow, error) {
	set, err := a.FetchSampledRequests(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]types.WafSampleRow, 0, len(set.Samples))
	for _, s := range set.Samples {
		rows = append(rows, ToSampleRow(s))
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Ts > rows[j].Ts })
	if len(rows) > 300 {
		rows = rows[:300]
	}
	return rows, nil
}
