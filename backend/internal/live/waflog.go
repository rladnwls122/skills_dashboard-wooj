package live

// The WAF's own record of each request, as rows rather than aggregates.
//
// Everything else on this dashboard reads the WAF through counters: how many
// were blocked, which paths, which User-Agents. That answers "what is
// happening" and cannot answer "what happened to *this* request" — which rule
// ended it, what the client sent, what code went back. Those questions come up
// exactly when a block is disputed, and the only place the answer exists is the
// full log.
//
// GetSampledRequests is not a substitute: it samples 500 per rule over WAF's
// own three-hour window, it only ever sees requests a rule matched, and it
// cannot follow the window the operator selected.
//
// Ported from waflog.ts.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/analysis"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/awsx"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/cache"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/service"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

const wafRowLimit = 500

// Same convention as the app-log query: one parse per field. The UA regex keeps
// the inline (?i) flag because this log's header names are written by CloudFront
// in mixed case ("User-Agent") and the WAF stats queries already depend on it
// working here.
const uaParse = `parse @message /"name":"(?i)user-agent","value":"(?<ua>[^"]*)"/`

// The task appends requestid to the query string, so the WAF sees it in args.
// It is what lines a WAF row up with the app's log line for the same request.
const ridParse = `parse httpRequest.args /requestid=(?<rid>[0-9A-Za-z-]+)/`

var wafActions = map[string]struct{}{"ALL": {}, "BLOCK": {}, "ALLOW": {}, "COUNT": {}}

const noWafLogGroup = "WAF 로그 그룹이 설정되지 않았습니다 — 설정 화면의 WAF_LOG_GROUP 에 로그 그룹 이름을 넣으세요. " +
	"(CLOUDFRONT 스코프의 WAF 로그는 us-east-1 에만 존재합니다.)"

func buildWafLogQuery(action, pathContains string) (string, error) {
	if action == "" {
		action = "ALL"
	}
	if _, ok := wafActions[action]; !ok {
		return "", fmt.Errorf("알 수 없는 동작 필터: %s", action)
	}
	parts := []string{
		"fields @timestamp, action, terminatingRuleId, terminatingRuleType, responseCodeSent," +
			" httpRequest.clientIp as ip, httpRequest.country as country," +
			" httpRequest.httpMethod as method, httpRequest.uri as uri, httpRequest.args as args," +
			" ruleGroupList.0.terminatingRule.ruleId as sub0, ruleGroupList.1.terminatingRule.ruleId as sub1",
		uaParse,
		ridParse,
	}
	if action != "ALL" {
		parts = append(parts, fmt.Sprintf(`filter action = "%s"`, action))
	}
	path, err := validatePathFilter(pathContains)
	if err != nil {
		return "", err
	}
	if path != "" {
		parts = append(parts, fmt.Sprintf(`filter uri like "%s"`, path))
	}
	parts = append(parts, "sort @timestamp desc", fmt.Sprintf("limit %d", wafRowLimit))
	return strings.Join(parts, " | "), nil
}

func toWafLogRow(r awsx.InsightsRow) types.WafLogRow {
	row := types.WafLogRow{
		Ts:     analysis.ToIso(r["@timestamp"]),
		Action: r["action"],
		Rule:   r["terminatingRuleId"],
		// A managed group reports itself as the terminating rule; the sub-rule
		// is the one an operator can actually act on (override it, scope it
		// down).
		SubRule:   firstNonEmpty(r["sub1"], r["sub0"]),
		IP:        r["ip"],
		Country:   r["country"],
		Method:    r["method"],
		URI:       r["uri"],
		RequestID: r["rid"],
		UserAgent: r["ua"],
	}
	// Query strings carry ids and e-mail addresses in this scenario, so they
	// leave the server masked like every other log text (spec §20).
	row.Args = truncate(analysis.MaskText(r["args"]), 200)
	if code := atoiF(r["responseCodeSent"]); code > 0 {
		row.ResponseCode = types.Ptr(code)
	}
	return row
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

func (p *Provider) WafLogRows(ctx context.Context, params service.WafLogParams, win types.ResolvedWindow) (types.WafLogQueryResult, error) {
	logGroup := p.Settings.WafLogGroup()
	if logGroup == "" {
		return types.WafLogQueryResult{}, errors.New(noWafLogGroup)
	}
	// Validation fails before anything is cached — a rejected filter is a user
	// error, not a cacheable result.
	query, err := buildWafLogQuery(params.Action, params.PathContains)
	if err != nil {
		return types.WafLogQueryResult{}, err
	}
	key := fmt.Sprintf("waflog:rows:%s:%s:%s:%d-%d", logGroup, params.Action, params.PathContains, win.WindowMin, win.EndMs)
	return cache.Cached(key, config.Polling.LogCacheTTL, func() (types.WafLogQueryResult, error) {
		// To now, not to the window's floored end — this is a tail, and the
		// last partial minute is the part being watched (same reason as the app
		// request log).
		endMs := win.EndMs
		if now := p.Now().UnixMilli(); now > endMs {
			endMs = now
		}
		res, err := p.AWS.RunInsightsQuery(ctx, awsx.InsightsParams{
			LogGroup: logGroup,
			Region:   p.Settings.WafRegion(),
			Query:    query,
			StartMs:  &win.StartMs,
			EndMs:    &endMs,
		})
		if err != nil {
			return types.WafLogQueryResult{}, err
		}
		rows := make([]types.WafLogRow, 0, len(res.Rows))
		for _, r := range res.Rows {
			rows = append(rows, toWafLogRow(r))
		}
		return types.WafLogQueryResult{
			Rows:         rows,
			TotalMatched: res.RecordsMatched,
			ScannedBytes: res.BytesScanned,
			WindowLabel:  res.WindowLabel,
			Truncated:    len(rows) >= wafRowLimit,
			LogGroup:     logGroup,
		}, nil
	}, config.Polling.LogFailTTL)
}
