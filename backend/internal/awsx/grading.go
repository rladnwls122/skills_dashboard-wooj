package awsx

// The grader's view of this environment. The keys follow the 2025 national
// task-3 scoring sheet (docs/binaries.md §채점 키): per-API "로드 처리"
// (availability) and "로드 처리 <= SLO" (performance) for user · product ·
// stress, "Email Request Validation" and "비정상 요청 처리율" (abnormal
// requests answered 403), plus the task's own "undefined path → 404" contract.
//
// The scoring itself is pure; the AWS-touching function runs the Insights
// queries and hands rows to the builder. No points are assigned anywhere here —
// the score is the grader's to compute from its own run.

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/analysis"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// The task sheet: every API must answer within 5 s to count as served at all;
// user and product aim at 0.2 s, stress at 1 s.
const AvailDeadlineMs = 5_000

var SloMs = map[string]int{"user": 200, "product": 200, "stress": 1_000}

var GradingAPIs = []string{"user", "product", "stress"}

// measure: observed value for one grading key.
func measure(label string, okCount, total int, source string, approximate bool) types.GradingScore {
	pct := 0.0
	if total > 0 {
		pct = math.Round(float64(okCount)/float64(total)*1000) / 10
	}
	return types.GradingScore{Label: label, Pct: pct, OkCount: okCount, Total: total, Source: source, Approximate: approximate}
}

// APIOf says which API a path belongs to; "" when the path is off the served
// surface and never counts toward availability.
func APIOf(path string) string {
	p := path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	for _, api := range GradingAPIs {
		base := "/v1/" + api
		if p == base || strings.HasPrefix(p, base+"/") {
			return api
		}
	}
	return ""
}

// BuildGradingQuery counts availability, both SLO tiers and the contract
// codes in the query rather than pulling rows back — the rows would be the
// whole traffic volume. Grouped by route (no query string), or every GET is
// its own row because the grader's requestid rides in the query.
func BuildGradingQuery() string {
	return strings.Join([]string{
		analysis.ParseFields,
		analysis.AccessLogFilter,
		"stats count(*) as total," +
			fmt.Sprintf(" sum(status >= 200 and status < 300 and latency_ms <= %d) as availOk,", AvailDeadlineMs) +
			fmt.Sprintf(" sum(status >= 200 and status < 300 and latency_ms <= %d) as fastOk,", SloMs["user"]) +
			fmt.Sprintf(" sum(status >= 200 and status < 300 and latency_ms <= %d) as slowOk,", SloMs["stress"]) +
			" sum(status = 404) as notFound," +
			" sum(status = 403) as forbidden," +
			" sum(status >= 500) as serverErr" +
			" by path",
		"sort total desc",
		"limit 200",
	}, " | ")
}

// BuildTrapQuery counts the product binary's trap line — one per Attacker-Bot
// request that reached the app instead of being blocked.
func BuildTrapQuery() string {
	return fmt.Sprintf(`filter @message like "%s" | stats count(*) as leaked`, analysis.MaliciousTrapLine)
}

// BuildWafGradingQuery folds the WAF log by uri × method × action. uri in the
// WAF log is the path without its query string, so it groups like `path` does
// on the app side.
func BuildWafGradingQuery() string {
	return "stats count(*) as cnt by httpRequest.uri as uri, httpRequest.httpMethod as method, action | sort cnt desc | limit 500"
}

type PathRow struct {
	Path      string
	Total     int
	AvailOk   int
	FastOk    int
	SlowOk    int
	NotFound  int
	Forbidden int
	ServerErr int
}

func rowInt(row InsightsRow, k string) int {
	n, err := strconv.ParseFloat(row[k], 64)
	if err != nil {
		return 0
	}
	return int(n)
}

func ToPathRow(row InsightsRow) PathRow {
	return PathRow{
		Path:      analysis.CleanPath(row["path"]),
		Total:     rowInt(row, "total"),
		AvailOk:   rowInt(row, "availOk"),
		FastOk:    rowInt(row, "fastOk"),
		SlowOk:    rowInt(row, "slowOk"),
		NotFound:  rowInt(row, "notFound"),
		Forbidden: rowInt(row, "forbidden"),
		ServerErr: rowInt(row, "serverErr"),
	}
}

// WafRow is one uri × method × action cell of the WAF log.
type WafRow struct {
	URI    string
	Method string
	Action string
	Count  int
}

func ToWafRow(row InsightsRow) WafRow {
	return WafRow{
		URI:    row["uri"],
		Method: strings.ToUpper(row["method"]),
		Action: strings.ToUpper(row["action"]),
		Count:  rowInt(row, "cnt"),
	}
}

type GradingParams struct {
	Rows []PathRow
	// The WAF log fold; nil when no WAF log group is configured (WafAvailable
	// false). Requests the firewall blocked never reach the app, so they are not
	// in Rows — they are what the 403 keys are made of.
	WafRows      []WafRow
	WafAvailable bool
	// Attacker-Bot requests the app served (and answered 500) — abnormal
	// requests that leaked past the WAF.
	TrapLeaked   int
	Window       types.ResolvedWindow
	Source       string
	ScannedBytes int64
	Notes        []string
}

// BuildGradingPanel builds the panel from already-fetched pieces so the
// scoring itself is pure.
func BuildGradingPanel(p GradingParams) types.GradingPanel {
	type apiAcc struct{ total, availOk, sloOk int }
	perAPI := map[string]*apiAcc{}
	for _, api := range GradingAPIs {
		perAPI[api] = &apiAcc{}
	}
	// Requests to paths the binaries do not serve, and how many the app ended
	// with the 404 the task requires.
	undefTotal, undefOk := 0, 0

	for _, r := range p.Rows {
		api := APIOf(r.Path)
		if api == "" {
			if !config.IsLowPriorityPath(r.Path) {
				undefTotal += r.Total
				undefOk += r.NotFound
			}
			continue
		}
		acc := perAPI[api]
		acc.total += r.Total
		acc.availOk += r.AvailOk
		// The SLO differs per API, so the right column is picked here rather
		// than baked into the query.
		if SloMs[api] <= SloMs["user"] {
			acc.sloOk += r.FastOk
		} else {
			acc.sloOk += r.SlowOk
		}
	}

	// WAF side: blocks on the served surface are the 403s the abnormal-request
	// keys count; blocks on undefined paths are 404s that became 403s.
	wafServedBlocked, wafEmailBlocked, wafUndefBlocked := 0, 0, 0
	for _, w := range p.WafRows {
		if w.Action != "BLOCK" {
			continue
		}
		if APIOf(w.URI) != "" {
			wafServedBlocked += w.Count
			if w.Method == "POST" && config.NormalizePath(w.URI) == "/v1/user" {
				wafEmailBlocked += w.Count
			}
			continue
		}
		if !config.IsLowPriorityPath(w.URI) {
			wafUndefBlocked += w.Count
		}
	}

	const appSrc = "앱 로그"
	lines := []types.GradingScore{}
	for _, api := range GradingAPIs {
		a := perAPI[api]
		lines = append(lines, measure(fmt.Sprintf("%s API 로드 처리", api), a.availOk, a.total, appSrc, false))
	}
	for _, api := range GradingAPIs {
		a := perAPI[api]
		lines = append(lines, measure(fmt.Sprintf("%s API 로드 처리 ≤ %.1fs", api, float64(SloMs[api])/1000), a.sloOk, a.total, appSrc, false))
	}

	wafSrc := "WAF 로그"
	if !p.WafAvailable {
		wafSrc = "WAF 로그 없음"
	}
	// Denominator = what we saw end as 403 + what we saw get through. The
	// grader's own count of what it injected is not observable anywhere.
	lines = append(lines, measure("Email Request Validation (403)", wafEmailBlocked, wafEmailBlocked, wafSrc+" · POST /v1/user 차단 건수, 분모 없음", true))
	lines = append(lines, measure("비정상 요청 처리율 (403)", wafServedBlocked, wafServedBlocked+p.TrapLeaked, wafSrc+" + 앱 로그 trap 라인", true))
	lines = append(lines, measure("미지정 경로 404", undefOk, undefTotal+wafUndefBlocked, appSrc+" + WAF 차단", false))

	notes := append([]string{}, p.Notes...)
	notes = append(notes,
		fmt.Sprintf("로드 처리 = 2xx && %ds 이내 / 해당 API 로 들어온 요청 전체. 성능 키는 그중 SLO(user·product %dms / stress %dms) 이내.", AvailDeadlineMs/1000, SloMs["user"], SloMs["stress"]),
		"분모는 앱 로그의 [GIN] 액세스 라인 전체라 앱이 스스로 내는 403(username 중복 → 'It already exists in a database.')·400·500 도 들어간다. 채점기는 자신이 보낸 요청만 세므로 값이 다를 수 있다.",
		fmt.Sprintf("비정상 요청 처리율: 분자 = WAF BLOCK(서비스 경로), 분모 = 분자 + 앱까지 새어 들어온 Attacker-Bot 요청 %d건 (product 가 'Consumed resources by malicious attacks.' 를 찍고 500 으로 응답). 채점기가 보낸 비정상 요청 전체 수는 관측 불가 — 새는 건수가 0 인지를 본다.", p.TrapLeaked),
		"Email Request Validation: WAF 가 POST /v1/user 를 차단한 건수만 보인다 — 잘못된 이메일이 몇 건 주입됐는지는 어디에도 기록되지 않는다(앱은 이메일을 검사하지 않는다). 0건이면 규칙이 없거나 COUNT 상태다.",
		"미지정 경로 404: 앱 로그의 비서비스 경로 요청 중 404 로 끝난 비율. WAF 가 미지정 경로를 BLOCK 하면 403 이 나가 위반 — 그 건수는 분모에만 더했다.",
		"점수는 매기지 않는다. 이 표는 관측값을 채점기 키에 맞춰 정렬해 둔 것이고, 점수는 채점 플랫폼이 정한다.",
		"서비스 경로: "+strings.Join(config.AppTrafficPaths(), ", "),
	)
	if !p.WafAvailable {
		notes = append(notes, "WAF_LOG_GROUP 이 비어 있어 403 키는 앱 로그만으로 채웠다 — 차단 건수는 0 으로 보인다. 설정에서 WAF 로그 그룹을 지정하면 채워진다.")
	}

	return types.GradingPanel{
		Lines:        lines,
		Window:       p.Window,
		Source:       p.Source,
		ScannedBytes: p.ScannedBytes,
		Notes:        notes,
	}
}

// FetchGradingPanel is the one AWS-touching function here: one app-log query
// for the per-path stats, one for the trap line, and — when a WAF log group is
// configured — one WAF-log fold.
func (a *AWS) FetchGradingPanel(ctx context.Context, win types.ResolvedWindow) (types.GradingPanel, error) {
	logGroup := a.Settings.AppLogGroup()
	res, err := a.RunInsightsQuery(ctx, InsightsParams{
		LogGroup: logGroup,
		Query:    BuildGradingQuery(),
		StartMs:  &win.StartMs,
		EndMs:    &win.EndMs,
	})
	if err != nil {
		return types.GradingPanel{}, err
	}
	rows := make([]PathRow, 0, len(res.Rows))
	for _, r := range res.Rows {
		rows = append(rows, ToPathRow(r))
	}
	params := GradingParams{
		Rows:         rows,
		Window:       win,
		Source:       fmt.Sprintf("앱 로그 Logs Insights(%s)", logGroup),
		ScannedBytes: res.BytesScanned,
		Notes:        []string{},
	}

	if trap, err := a.RunInsightsQuery(ctx, InsightsParams{
		LogGroup: logGroup, Query: BuildTrapQuery(), StartMs: &win.StartMs, EndMs: &win.EndMs,
	}); err == nil {
		params.ScannedBytes += trap.BytesScanned
		if len(trap.Rows) > 0 {
			params.TrapLeaked = rowInt(trap.Rows[0], "leaked")
		}
	} else {
		params.Notes = append(params.Notes, "Attacker-Bot trap 라인 집계 실패: "+ErrMsg(err))
	}

	if wafGroup := a.Settings.WafLogGroup(); wafGroup != "" {
		wafRes, err := a.RunInsightsQuery(ctx, InsightsParams{
			LogGroup: wafGroup,
			Region:   a.Settings.WafRegion(),
			Query:    BuildWafGradingQuery(),
			StartMs:  &win.StartMs,
			EndMs:    &win.EndMs,
		})
		if err == nil {
			params.WafAvailable = true
			params.ScannedBytes += wafRes.BytesScanned
			params.Source += fmt.Sprintf(" + WAF 로그(%s)", wafGroup)
			for _, r := range wafRes.Rows {
				params.WafRows = append(params.WafRows, ToWafRow(r))
			}
		} else {
			params.Notes = append(params.Notes, "WAF 로그 집계 실패 — 403 키는 앱 로그만으로 채움: "+ErrMsg(err))
		}
	}
	return BuildGradingPanel(params), nil
}
