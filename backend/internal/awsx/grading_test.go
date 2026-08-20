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

// The keys follow the 2025 task-3 scoring sheet; each is fed from the source
// that can actually see it.
func TestBuildGradingPanelKeys(t *testing.T) {
	panel := BuildGradingPanel(GradingParams{
		Rows: []PathRow{
			// 100 user requests: 90 served fast, 5 served slow (>200ms but <5s), 3 app 403 (duplicate), 2 500.
			{Path: "/v1/user", Total: 100, AvailOk: 95, FastOk: 90, SlowOk: 95, Forbidden: 3, ServerErr: 2},
			{Path: "/v1/product", Total: 50, AvailOk: 50, FastOk: 50, SlowOk: 50},
			// stress: 20 served, 15 of them inside 1s; the fast column would undercount it.
			{Path: "/v1/stress", Total: 20, AvailOk: 20, FastOk: 2, SlowOk: 15},
			{Path: "/healthcheck", Total: 500, AvailOk: 500, FastOk: 500, SlowOk: 500},
			// undefined paths the app answered: 8 with 404 (gin's default), 2 with 200 (a misrouted catch-all).
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
	check("user API 로드 처리", 95, 100, false)
	check("product API 로드 처리", 50, 50, false)
	check("stress API 로드 처리", 20, 20, false)
	check("user API 로드 처리 ≤ 0.2s", 90, 100, false)
	check("stress API 로드 처리 ≤ 1.0s", 15, 20, false)
	// Email validation: only the WAF's POST /v1/user blocks are visible.
	check("Email Request Validation (403)", 30, 30, true)
	// Abnormal handling: served-surface blocks over blocks + what leaked to the app.
	check("비정상 요청 처리율 (403)", 40, 44, true)
	// Undefined paths: app 404s over app-seen undefined + WAF-blocked undefined (not the health check).
	check("미지정 경로 404", 8, 15, false)

	if len(panel.Lines) != 9 {
		t.Fatalf("lines=%d", len(panel.Lines))
	}
	if lineByLabel(panel, "user API 로드 처리").Pct != 95 {
		t.Errorf("pct=%v", lineByLabel(panel, "user API 로드 처리").Pct)
	}
	joined := strings.Join(panel.Notes, "\n")
	if !strings.Contains(joined, "Attacker-Bot") || !strings.Contains(joined, "4건") {
		t.Errorf("notes must say how many abnormal requests leaked: %s", joined)
	}
}

// Without a WAF log group the 403 keys fall back to app-side evidence only,
// and the panel has to say so rather than show a clean 0.
func TestBuildGradingPanelWithoutWaf(t *testing.T) {
	panel := BuildGradingPanel(GradingParams{
		Rows:       []PathRow{{Path: "/v1/product", Total: 10, AvailOk: 10, FastOk: 10, SlowOk: 10}},
		TrapLeaked: 2,
	})
	l := lineByLabel(panel, "비정상 요청 처리율 (403)")
	if l.OkCount != 0 || l.Total != 2 {
		t.Errorf("got ok=%d total=%d", l.OkCount, l.Total)
	}
	if !strings.Contains(strings.Join(panel.Notes, "\n"), "WAF_LOG_GROUP") {
		t.Error("must tell the operator the WAF log group is missing")
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
