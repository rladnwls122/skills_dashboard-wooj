package awsx

// The grader's view of this environment. The keys are the ones the 2026
// national task-3 scoring sheet (and its results_<비번호>.log) actually carry:
// "image download" and "Exception Handling" (비정상 요청 처리), and per-API
// "availability" and "performance ≤ SLO" for user · product · stress. Each key
// is measured from the source that can see it — the app log for the four served
// ratios, the WAF log for the 403 side of Exception Handling.
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

// trimTrailingSlash: "/v1/user/" and "/v1/user" are one route; only the
// comparison needs to say so. "/" itself is left alone — it is a path, not a
// trailing slash.
func trimTrailingSlash(path string) string {
	if len(path) > 1 {
		return strings.TrimSuffix(path, "/")
	}
	return path
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

// IsImagePath: image delivery is S3 objects served under /images/<object path>
// through the same endpoint as the APIs. It is a scoring key of its own ("image
// download"), not part of any API's availability, so it has to be split out
// before APIOf ever sees the row. Anchored at a segment boundary so a route
// that merely starts with the same letters (/imagesearch) does not collide.
func IsImagePath(path string) bool {
	p := path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p == "/images" || strings.HasPrefix(p, "/images/")
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

// scoreBandsAvailability: the score bands the 2026 sheet pays on, highest
// first. Every percentage key uses the same ladder, and each rung crossed is
// worth 0.5점 — so the number an operator needs is not "86.2%" but "one band
// below the next 0.5, and 1.3%p away from it". Kept as numbers rather than a
// formatted string so the gap can be computed against them.
var scoreBandsAvailability = []float64{90, 87.5, 85, 82.5, 80, 70, 50, 30}

// scoreBandsAbnormal: 비정상 요청 처리 (image download · Exception Handling)
// pays on four rungs, not eight. Same shape, different ladder — do not merge
// them.
var scoreBandsAbnormal = []float64{90, 85, 80, 50}

// trimFloat formats a band or gap the way a JS template literal would: 90 → "90",
// 87.5 → "87.5", 4 → "4" — no trailing zeros, so the console reads clean.
func trimFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// bandOf returns the band a percentage currently sits in and the next one up.
func bandOf(pct float64, bands []float64) (tier, nextTier *string) {
	// bands is descending, so the first rung at or below the value is the one it
	// has already earned; the rung above it is what the next 0.5점 costs.
	earnedIndex := -1
	for i, b := range bands {
		if pct >= b {
			earnedIndex = i
			break
		}
	}
	if earnedIndex >= 0 {
		tier = types.Ptr(fmt.Sprintf("%s%% 구간", trimFloat(bands[earnedIndex])))
	}
	var nextValue float64
	haveNext := false
	if earnedIndex == -1 {
		nextValue = bands[len(bands)-1]
		haveNext = true
	} else if earnedIndex-1 >= 0 {
		nextValue = bands[earnedIndex-1]
		haveNext = true
	}
	if !haveNext {
		return tier, nil
	}
	gap := math.Round((nextValue-pct)*10) / 10
	nextTier = types.Ptr(fmt.Sprintf("%s%% 까지 %s%%p", trimFloat(nextValue), trimFloat(gap)))
	return tier, nextTier
}

// BuildGradingPanel builds the panel from already-fetched pieces so the
// scoring itself is pure.
func BuildGradingPanel(p GradingParams) types.GradingPanel {
	type apiAcc struct{ total, availOk, sloOk int }
	perAPI := map[string]*apiAcc{}
	for _, api := range GradingAPIs {
		perAPI[api] = &apiAcc{}
	}

	// Image delivery is its own scoring key ("image download") and its own
	// surface: S3 objects served under /images/ through the same endpoint. Its
	// SLO is the availability deadline itself — 5s for both — so there is no
	// second tier.
	imageTotal, imageOk := 0, 0

	// Requests to paths the task does not serve. The contract is 404 there, and
	// "Exception Handling" is what the grader calls the ratio that ends
	// correctly.
	undefTotal, undefOk := 0, 0

	for _, r := range p.Rows {
		if IsImagePath(r.Path) {
			imageTotal += r.Total
			imageOk += r.AvailOk
			continue
		}
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

	// WAF side. A block on the served surface is an abnormal request answered
	// 403 — which is what the task asks for. A block on an undefined path is a
	// 404 that became a 403, which is the violation, so it only ever enlarges
	// the denominator. A block on the image surface is neither — it would cost
	// image download points — so it is excluded before either bucket.
	wafServedBlocked, wafUndefBlocked := 0, 0
	for _, w := range p.WafRows {
		if w.Action != "BLOCK" {
			continue
		}
		if IsImagePath(w.URI) {
			continue
		}
		if APIOf(w.URI) != "" {
			wafServedBlocked += w.Count
			continue
		}
		if !config.IsLowPriorityPath(w.URI) {
			wafUndefBlocked += w.Count
		}
	}

	const appSrc = "앱 로그"
	wafSrc := "WAF 로그"
	if !p.WafAvailable {
		wafSrc = "WAF 로그 없음"
	}
	lines := []types.GradingScore{}

	push := func(label string, okCount, total int, source string, bands []float64, approximate bool) {
		line := measure(label, okCount, total, source, approximate)
		// A band is a claim about data; when nothing was observed there is no
		// claim to make, so both stay nil.
		if total > 0 {
			line.Tier, line.NextTier = bandOf(line.Pct, bands)
		}
		lines = append(lines, line)
	}

	// Ordered exactly as the sheet lists them, so the two read side by side.
	push("image download", imageOk, imageTotal, appSrc, scoreBandsAbnormal, false)
	// Numerator = abnormal requests the WAF turned into 403 + undefined-path
	// requests the app ended as 404. Denominator adds what leaked to the app and
	// what the WAF wrongly blocked on an undefined path.
	push(
		"Exception Handling",
		wafServedBlocked+undefOk,
		wafServedBlocked+undefOk+p.TrapLeaked+(undefTotal-undefOk)+wafUndefBlocked,
		fmt.Sprintf("%s + %s", wafSrc, appSrc),
		scoreBandsAbnormal,
		true,
	)
	for _, api := range GradingAPIs {
		a := perAPI[api]
		push(fmt.Sprintf("(%s) availability", api), a.availOk, a.total, appSrc, scoreBandsAvailability, false)
	}
	for _, api := range GradingAPIs {
		a := perAPI[api]
		push(fmt.Sprintf("(%s) performance ≤ %.1fs", api, float64(SloMs[api])/1000), a.sloOk, a.total, appSrc, scoreBandsAvailability, false)
	}

	notes := append([]string{}, p.Notes...)
	notes = append(notes,
		"채점기 로그(results_<비번호>.log)의 키 이름을 그대로 썼다 — image download · Exception Handling · (api) availability · (api) performance. cost ratio 는 이 화면이 아니라 아래 노드 대수 패널이 다룬다.",
		fmt.Sprintf("availability = 2xx && %ds 이내. performance = 그중 SLO(user·product %dms / stress %dms) 이내. image download 는 둘 다 %ds 라 한 줄뿐이다.", AvailDeadlineMs/1000, SloMs["user"], SloMs["stress"], AvailDeadlineMs/1000),
		"채점기의 응답시간은 **클라이언트 도착 기준**이고 이 표는 앱이 기록한 처리 시간이다 — 네트워크·ALB·CloudFront 구간이 빠져 있어 항상 낙관적으로 보인다. 실제 점수는 이 값보다 낮게 나온다고 보는 편이 안전하다.",
		"분모는 앱 로그의 [GIN] 액세스 라인 전체라 앱이 스스로 내는 403(username 중복)·400·500 도 들어간다. 채점기는 자신이 보낸 요청만 세므로 값이 다를 수 있다.",
		fmt.Sprintf("Exception Handling: 분자 = WAF BLOCK(서비스 경로) + 앱이 404 로 끝낸 미지정 경로. 분모에 앱까지 새어 들어온 비정상 요청 %d건과 WAF 가 미지정 경로를 막아 403 이 된 %d건을 더했다 — 후자는 그 자체로 계약 위반이다.", p.TrapLeaked, wafUndefBlocked),
		"구간 표시는 채점표의 문턱(90 / 87.5 / 85 / 82.5 / 80 / 70 / 50 / 30%, 비정상 처리는 90 / 85 / 80 / 50%)에 맞춘 것이다. 다음 문턱까지 남은 %p 가 곧 다음 0.5점이다.",
		"점수는 매기지 않는다. 이 표는 관측값을 채점기 키에 맞춰 정렬해 둔 것이고, 점수는 채점 플랫폼이 정한다.",
		"서비스 경로: "+strings.Join(config.AppTrafficPaths(), ", "),
	)
	if !p.WafAvailable {
		notes = append(notes, "WAF_LOG_GROUP 이 비어 있어 Exception Handling 의 403 쪽 분자가 0 이다 — 앱 로그만으로는 차단 건수를 볼 수 없다. 설정에서 WAF 로그 그룹을 지정하면 채워진다.")
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
