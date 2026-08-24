package awsx

import (
	"strings"
	"testing"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func lineByLabel(p types.GradingPanel, label string) types.GradingScore {
	for _, l := range p.Lines {
		if l.Label == label {
			return l
		}
	}
	return types.GradingScore{Label: "(missing) " + label}
}

// The keys are the ones the grader's own results_<비번호>.log carries — image
// download, Exception Handling, (api) availability, (api) performance — because
// the operator reads the two side by side and a renamed key costs them the
// comparison. Each is fed from the source that can actually see it.
func TestBuildGradingPanelKeys(t *testing.T) {
	panel := BuildGradingPanel(GradingParams{
		Rows: []PathRow{
			// 100 user requests: 90 served fast, 5 served slow (>200ms but <5s), 3 app 403 (duplicate), 2 500.
			{Path: "/v1/user", Total: 100, AvailOk: 95, FastOk: 90, SlowOk: 95, Forbidden: 3, ServerErr: 2},
			{Path: "/v1/product", Total: 50, AvailOk: 50, FastOk: 50, SlowOk: 50},
			// stress: 20 served, 15 of them inside 1s; the fast column would undercount it.
			{Path: "/v1/stress", Total: 20, AvailOk: 20, FastOk: 2, SlowOk: 15},
			// Image delivery is its own key and must not fall into any API's numbers.
			{Path: "/images/product50001.jpg", Total: 40, AvailOk: 36, FastOk: 30, SlowOk: 34},
			{Path: "/healthcheck", Total: 500, AvailOk: 500, FastOk: 500, SlowOk: 500},
			// undefined paths the app answered: 8 with 404 (the contract), 2 with 200.
			{Path: "/v1/none", Total: 8, NotFound: 8},
			{Path: "/admin", Total: 2, AvailOk: 2, FastOk: 2, SlowOk: 2},
		},
		WafAvailable: true,
		WafRows: []WafRow{
			{URI: "/v1/user", Method: "POST", Action: "BLOCK", Count: 30},
			{URI: "/v1/product", Method: "POST", Action: "BLOCK", Count: 10},
			{URI: "/v1/user", Method: "GET", Action: "ALLOW", Count: 1000},
			{URI: "/.env", Method: "GET", Action: "BLOCK", Count: 5}, // a 404 that became a 403
			{URI: "/healthcheck", Method: "GET", Action: "BLOCK", Count: 1},
			// A block on the image surface would cost image download points; it is
			// neither an abnormal-request success nor an undefined-path violation.
			{URI: "/images/x.jpg", Method: "GET", Action: "BLOCK", Count: 7},
		},
		TrapLeaked: 4,
		Window:     types.ResolvedWindow{Label: "60m"},
	})

	check := func(label string, ok, total int, approx bool) {
		t.Helper()
		l := lineByLabel(panel, label)
		if l.OkCount != ok || l.Total != total || l.Approximate != approx {
			t.Errorf("%s: got ok=%d total=%d approx=%v want ok=%d total=%d approx=%v", label, l.OkCount, l.Total, l.Approximate, ok, total, approx)
		}
		if l.Source == "" {
			t.Errorf("%s: source must be stated", label)
		}
	}
	check("image download", 36, 40, false)
	// Exception Handling: WAF blocks on the served surface (40 — the image block
	// is excluded) plus the 8 undefined paths the app ended as 404. The
	// denominator adds the 4 that leaked to the app, the 2 undefined paths that
	// answered 200, and the 5 undefined paths the WAF wrongly turned into 403.
	check("Exception Handling", 48, 59, true)
	check("(user) availability", 95, 100, false)
	check("(product) availability", 50, 50, false)
	check("(stress) availability", 20, 20, false)
	check("(user) performance ≤ 0.2s", 90, 100, false)
	check("(stress) performance ≤ 1.0s", 15, 20, false)

	if len(panel.Lines) != 8 {
		t.Fatalf("lines=%d", len(panel.Lines))
	}
	if lineByLabel(panel, "(user) availability").Pct != 95 {
		t.Errorf("pct=%v", lineByLabel(panel, "(user) availability").Pct)
	}
	joined := strings.Join(panel.Notes, "\n")
	if !strings.Contains(joined, "results_") {
		t.Error("notes must name the grader's own log")
	}
	if !strings.Contains(joined, "클라이언트 도착 기준") {
		t.Error("notes must state the latency is optimistic")
	}
	if !strings.Contains(joined, "4건") {
		t.Error("notes must say how many abnormal requests leaked")
	}
}

// The sheet pays per threshold crossed, so a bare percentage does not tell the
// operator whether the next point is reachable. Each line carries the band it
// has earned and the gap to the next one.
func TestBuildGradingPanelScoreBands(t *testing.T) {
	panel := BuildGradingPanel(GradingParams{
		// 86% availability: past the 85 rung, short of 87.5.
		Rows:   []PathRow{{Path: "/v1/user", Total: 100, AvailOk: 86, FastOk: 86, SlowOk: 86}},
		Window: types.ResolvedWindow{Label: "60m"},
	})
	avail := lineByLabel(panel, "(user) availability")
	if avail.Pct != 86 {
		t.Fatalf("pct=%v", avail.Pct)
	}
	if avail.Tier == nil || *avail.Tier != "85% 구간" {
		t.Errorf("tier=%v want 85%% 구간", avail.Tier)
	}
	if avail.NextTier == nil || *avail.NextTier != "87.5% 까지 1.5%p" {
		t.Errorf("nextTier=%v want 87.5%% 까지 1.5%%p", avail.NextTier)
	}

	// Nothing observed: a band would be a claim about data that does not exist.
	idle := BuildGradingPanel(GradingParams{Rows: []PathRow{}, Window: types.ResolvedWindow{Label: "60m"}})
	il := lineByLabel(idle, "(user) availability")
	if il.Tier != nil || il.NextTier != nil {
		t.Errorf("idle tier/nextTier must be nil, got %v / %v", il.Tier, il.NextTier)
	}
}

// 비정상 요청 처리 pays on four rungs, not the eight the availability keys use.
func TestBuildGradingPanelAbnormalLadder(t *testing.T) {
	panel := BuildGradingPanel(GradingParams{
		Rows:   []PathRow{{Path: "/images/a.jpg", Total: 100, AvailOk: 86}},
		Window: types.ResolvedWindow{Label: "60m"},
	})
	image := lineByLabel(panel, "image download")
	if image.Pct != 86 {
		t.Fatalf("pct=%v", image.Pct)
	}
	// 87.5 is not a rung here — the next one up is 90.
	if image.Tier == nil || *image.Tier != "85% 구간" {
		t.Errorf("tier=%v want 85%% 구간", image.Tier)
	}
	if image.NextTier == nil || *image.NextTier != "90% 까지 4%p" {
		t.Errorf("nextTier=%v want 90%% 까지 4%%p", image.NextTier)
	}
}

// Without a WAF log group the 403 side of Exception Handling is invisible, and
// the panel has to say so rather than show a clean number.
func TestBuildGradingPanelWithoutWaf(t *testing.T) {
	panel := BuildGradingPanel(GradingParams{
		Rows:       []PathRow{{Path: "/v1/product", Total: 10, AvailOk: 10, FastOk: 10, SlowOk: 10}},
		TrapLeaked: 2,
	})
	l := lineByLabel(panel, "Exception Handling")
	if l.OkCount != 0 || l.Total != 2 {
		t.Errorf("got ok=%d total=%d", l.OkCount, l.Total)
	}
	if !strings.Contains(strings.Join(panel.Notes, "\n"), "WAF_LOG_GROUP") {
		t.Error("must tell the operator the WAF log group is missing")
	}
}

func TestIsImagePath(t *testing.T) {
	cases := map[string]bool{
		"/images/product50001.jpg": true,
		"/images":                  true,
		"/images/a/b.png?x=1":      true,
		"/v1/product":              false,
		// Prefix collision: a route that merely starts with the same letters.
		"/imagesearch": false,
	}
	for in, want := range cases {
		if got := IsImagePath(in); got != want {
			t.Errorf("IsImagePath(%q) = %v want %v", in, got, want)
		}
	}
}

func TestAPIOf(t *testing.T) {
	cases := map[string]string{
		"/v1/user": "user", "/v1/user?email=x&requestid=1": "user", "/v1/product/": "product",
		"/v1/stress": "stress", "/v1/users": "", "/healthcheck": "", "/v1/none": "",
	}
	for in, want := range cases {
		if got := APIOf(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestBuildGradingQueryGroupsByRoute(t *testing.T) {
	q := BuildGradingQuery()
	if !strings.Contains(q, "by path") || !strings.Contains(q, "parse @message /") || !strings.Contains(q, "latency_ms <= 5000") {
		t.Errorf("unexpected query: %s", q)
	}
	if strings.Contains(q, `"latency_ms":`) {
		t.Error("query still parses the old JSON log shape")
	}
}
