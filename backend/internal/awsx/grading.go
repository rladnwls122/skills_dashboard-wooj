package awsx

// The grader's view of this environment, ported from grading.ts. The scoring
// itself is pure; the one AWS-touching function runs the Insights query and
// hands rows to the builder.

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

const AvailDeadlineMs = 5_000

var SloMs = map[string]int{"user": 200, "product": 200, "stress": 1_000}

var GradingAPIs = []string{"user", "product", "stress"}

// measure: observed value for one grading key. No points are assigned here —
// the score is the grader's to compute from its own run.
func measure(label string, okCount, total int) types.GradingScore {
	pct := 0.0
	if total > 0 {
		pct = math.Round(float64(okCount)/float64(total)*1000) / 10
	}
	return types.GradingScore{Label: label, Pct: pct, OkCount: okCount, Total: total}
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

func IsImagePath(path string) bool {
	p := path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return strings.HasPrefix(p, "/images/")
}

// BuildGradingQuery counts availability and both SLO tiers in the query rather
// than pulling rows back — the rows would be the whole traffic volume.
func BuildGradingQuery() string {
	return strings.Join([]string{
		analysis.ParseFields,
		"filter ispresent(status) and ispresent(path)",
		"stats count(*) as total," +
			fmt.Sprintf(" sum(status >= 200 and status < 300 and latency_ms <= %d) as availOk,", AvailDeadlineMs) +
			fmt.Sprintf(" sum(status >= 200 and status < 300 and latency_ms <= %d) as fastOk,", SloMs["user"]) +
			fmt.Sprintf(" sum(status >= 200 and status < 300 and latency_ms <= %d) as slowOk,", SloMs["stress"]) +
			" sum(status = 404 or status = 403) as handledOk" +
			" by path",
		"sort total desc",
		"limit 200",
	}, " | ")
}

type PathRow struct {
	Path      string
	Total     int
	AvailOk   int
	FastOk    int
	SlowOk    int
	HandledOk int
}

func ToPathRow(row InsightsRow) PathRow {
	num := func(k string) int {
		n, err := strconv.ParseFloat(row[k], 64)
		if err != nil {
			return 0
		}
		return int(n)
	}
	return PathRow{
		Path:      row["path"],
		Total:     num("total"),
		AvailOk:   num("availOk"),
		FastOk:    num("fastOk"),
		SlowOk:    num("slowOk"),
		HandledOk: num("handledOk"),
	}
}

type GradingParams struct {
	Rows []PathRow
	// Requests the firewall blocked outright. They never reach the app, so
	// they are not in Rows — reported next to the exception figure.
	WafBlocked   int
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
	imgTotal, imgOk := 0, 0
	// Off-surface requests — the shape the grader sends as "abnormal" — and how
	// many the app ended with 404/403 as the contract requires.
	excTotal, excOk := 0, 0

	for _, r := range p.Rows {
		if IsImagePath(r.Path) {
			imgTotal += r.Total
			imgOk += r.AvailOk
			continue
		}
		api := APIOf(r.Path)
		if api == "" {
			if !config.IsLowPriorityPath(r.Path) && !config.IsAppTrafficPath(r.Path) {
				excTotal += r.Total
				excOk += r.HandledOk
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

	// Ordered by the grader's own key order so the two read side by side.
	lines := []types.GradingScore{}
	for _, api := range GradingAPIs {
		a := perAPI[api]
		lines = append(lines, measure(fmt.Sprintf("(%s) availability", api), a.availOk, a.total))
	}
	for _, api := range GradingAPIs {
		a := perAPI[api]
		lines = append(lines, measure(fmt.Sprintf("(%s) performance", api), a.sloOk, a.total))
	}
	lines = append(lines, measure("image download", imgOk, imgTotal))
	lines = append(lines, measure("Exception Handling", excOk, excTotal))

	notes := append([]string{}, p.Notes...)
	notes = append(notes,
		fmt.Sprintf("Exception Handling 은 앱 로그에 남은 미지정 경로 요청 기준 — WAF 가 차단한 요청은 앱에 도달하지 않아 이 분모에 없다. 같은 구간 WAF 차단 %d건은 별도 집계.", p.WafBlocked),
		fmt.Sprintf("가용성은 2xx && %ds 이내, 성능은 그중 SLO(user·product %dms / stress %dms) 이내 비율", AvailDeadlineMs/1000, SloMs["user"], SloMs["stress"]),
		"채점기는 요청마다 기대 코드(생성 201·조회 200)를 알고 비교하지만 로그에는 그 의도가 없어 2xx 로 근사함 — 채점기 값과 다를 수 있음",
		"점수는 매기지 않는다. 이 표는 관측값을 채점기 키에 맞춰 정렬해 둔 것이고, 점수는 채점기 실행 결과(results_<비번호>.log)가 정한다.",
		"서비스 경로: "+strings.Join(config.AppTrafficPaths(), ", "),
	)

	return types.GradingPanel{
		Lines:        lines,
		Window:       p.Window,
		Source:       p.Source,
		ScannedBytes: p.ScannedBytes,
		Notes:        notes,
	}
}

// FetchGradingPanel is the one AWS-touching function here.
func (a *AWS) FetchGradingPanel(ctx context.Context, win types.ResolvedWindow, wafBlocked int) (types.GradingPanel, error) {
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
	return BuildGradingPanel(GradingParams{
		Rows:         rows,
		WafBlocked:   wafBlocked,
		Window:       win,
		Source:       fmt.Sprintf("앱 로그 Logs Insights(%s)", logGroup),
		ScannedBytes: res.BytesScanned,
		Notes:        []string{},
	}), nil
}
