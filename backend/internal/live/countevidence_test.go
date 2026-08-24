package live

// The pure halves of the COUNT-evidence join and the WAF log query builder,
// pinned the way scripts covered them in the TS backend.

import (
	"strings"
	"testing"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func TestBuildCountQuery(t *testing.T) {
	q := buildCountQuery("sqli-block")
	if !strings.Contains(q, `filter @message like /"ruleId":"sqli\-block"/`) &&
		!strings.Contains(q, `filter @message like /"ruleId":"sqli-block"/`) {
		t.Errorf("rule name not embedded: %s", q)
	}
	// A counting rule never terminates, so the action filter must exclude
	// BLOCK, not require COUNT.
	if !strings.Contains(q, `filter action != "BLOCK"`) {
		t.Errorf("missing action filter: %s", q)
	}
	// Regex metacharacters in a rule name must not escape the literal.
	esc := buildCountQuery("a.b(c)")
	if !strings.Contains(esc, `a\.b\(c\)`) {
		t.Errorf("metacharacters not escaped: %s", esc)
	}
}

func TestExtractRequestID(t *testing.T) {
	cases := []struct {
		args string
		want string
		nil_ bool
	}{
		{"requestid=abc-123", "abc-123", false},
		{"?uuid=u-9", "u-9", false},
		{"a=1&requestid=x%2Fy", "x/y", false},
		{"a=1&b=2", "", true},
		{"", "", true},
		{"requestid=", "", true},
	}
	for _, tc := range cases {
		got := extractRequestID(tc.args)
		if tc.nil_ {
			if got != nil {
				t.Errorf("%q: want nil, got %q", tc.args, *got)
			}
			continue
		}
		if got == nil || *got != tc.want {
			t.Errorf("%q: want %q, got %v", tc.args, tc.want, got)
		}
	}
}

func TestVerdictFor(t *testing.T) {
	if verdictFor(nil) != "unjoinable" {
		t.Error("nil status must be unjoinable")
	}
	if verdictFor(types.Ptr(200)) != "normal" || verdictFor(types.Ptr(299)) != "normal" {
		t.Error("2xx must be normal")
	}
	if verdictFor(types.Ptr(403)) != "abnormal" || verdictFor(types.Ptr(302)) != "abnormal" {
		t.Error("non-2xx must be abnormal")
	}
}

func TestPromotionNote(t *testing.T) {
	if note := promotionNote(types.CountEvidence{Total: 30, Normal: 2}); !strings.Contains(note, "2건") {
		t.Errorf("normal traffic must be named: %s", note)
	}
	if note := promotionNote(types.CountEvidence{Total: 5}); !strings.Contains(note, "표본 부족") {
		t.Errorf("small sample must warn: %s", note)
	}
	if note := promotionNote(types.CountEvidence{Total: 40}); !strings.Contains(note, "정상 응답 0건") {
		t.Errorf("clean sample reads as safe: %s", note)
	}
}

func TestBuildWafLogQuery(t *testing.T) {
	q, err := buildWafLogQuery("BLOCK", "v1/user")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, `filter action = "BLOCK"`) || !strings.Contains(q, `filter uri like "v1/user"`) {
		t.Errorf("filters missing: %s", q)
	}
	// ALL adds no action filter.
	q, err = buildWafLogQuery("ALL", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(q, `filter action =`) {
		t.Errorf("ALL must not filter action: %s", q)
	}
	// The path filter is interpolated into the query, so the validator is the
	// whole injection guarantee.
	if _, err := buildWafLogQuery("ALL", `x" or 1=1`); err == nil {
		t.Error("quote in path filter must be rejected")
	}
	if _, err := buildWafLogQuery("DROP", ""); err == nil {
		t.Error("unknown action must be rejected")
	}
}

// Every stage of a Logs Insights pipeline has to begin with a command. A bare
// field expression after a pipe is a MalformedQueryException, which meant this
// query had never once returned a row and the panel read as "잡힌 것 없음".
func TestBuildCountQueryEveryStageBeginsWithACommand(t *testing.T) {
	commands := map[string]bool{
		"fields": true, "filter": true, "stats": true, "sort": true,
		"limit": true, "parse": true, "display": true, "dedup": true,
	}
	q := buildCountQuery("sqli-block")
	for _, stage := range strings.Split(q, "|") {
		stage = strings.TrimSpace(stage)
		if stage == "" {
			t.Fatalf("empty pipeline stage in %q", q)
		}
		command, _, _ := strings.Cut(stage, " ")
		if !commands[command] {
			t.Errorf("stage %q does not begin with a command (query: %s)", stage, q)
		}
	}
	// The method is still asked for — it is a column of the evidence table.
	if !strings.Contains(q, "httpRequest.httpMethod as method") {
		t.Errorf("method field dropped: %s", q)
	}
}
