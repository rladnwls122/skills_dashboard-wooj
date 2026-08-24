package rules

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

var scannerSummary = types.HttpSummary{
	TotalSampled: 12,
	ByUa: []types.KeyCount{
		{Key: "sqlmap/1.7", Count: 6},
		{Key: "Attacker-Bot", Count: 4},
		// A real browser must not become a pattern, or the rule blocks the grader.
		{Key: "Mozilla/5.0 (X11) AppleWebKit/537.36", Count: 2},
	},
}

// refOf pulls the reference statement out of one arm. An arm with a single
// (set × field) ref is bare; several are wrapped in an OrStatement — the TS
// test navigates the same `arm.OrStatement?.Statements[0] ?? arm`.
func refOf(t *testing.T, arm map[string]any) map[string]any {
	t.Helper()
	if or, ok := arm["OrStatement"].(map[string]any); ok {
		stmts := or["Statements"].([]any)
		return stmts[0].(map[string]any)
	}
	return arm
}

func transformTypes(ref map[string]any) []string {
	stmt := ref["RegexPatternSetReferenceStatement"].(map[string]any)
	raw := stmt["TextTransformations"].([]any)
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		out = append(out, t.(map[string]any)["Type"].(string))
	}
	return out
}

// The rule is two arms AND'd: "the request is on a served API path" and "the
// client is a known scanner". Each arm references its own pattern set on its
// own field under its own transform pipeline.
func TestAssembleScannerUaAndsPathAndUserAgent(t *testing.T) {
	assembled, err := AssembleRule("ua", scannerSummary, AssembleEnv{WafScope: "CLOUDFRONT", WafRegion: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if assembled.Name != "scanner-ua" {
		t.Fatalf("name=%q", assembled.Name)
	}

	// Two sets, each with its own ARN placeholder and its own transforms.
	setNames := []string{}
	for _, s := range assembled.Sets {
		setNames = append(setNames, s.Name)
	}
	if !reflect.DeepEqual(setNames, []string{"waf-api-paths", "waf-scanner-uas"}) {
		t.Fatalf("sets=%v", setNames)
	}

	var rule map[string]any
	if err := json.Unmarshal([]byte(assembled.RuleJson), &rule); err != nil {
		t.Fatal(err)
	}
	if rule["Priority"].(float64) != 30 {
		t.Errorf("priority=%v want 30", rule["Priority"])
	}
	if _, ok := rule["Action"].(map[string]any)["Block"]; !ok {
		t.Error("the scanner rule blocks")
	}
	arms := rule["Statement"].(map[string]any)["AndStatement"].(map[string]any)["Statements"].([]any)
	if len(arms) != 2 {
		t.Fatalf("arms=%d want 2 (path AND user-agent)", len(arms))
	}

	pathRef := refOf(t, arms[0].(map[string]any))["RegexPatternSetReferenceStatement"].(map[string]any)
	if !reflect.DeepEqual(pathRef["FieldToMatch"], map[string]any{"UriPath": map[string]any{}}) {
		t.Errorf("path field=%v", pathRef["FieldToMatch"])
	}
	if pathRef["ARN"] != "<waf-api-paths-ARN>" {
		t.Errorf("path arn=%v", pathRef["ARN"])
	}
	if got := transformTypes(refOf(t, arms[0].(map[string]any))); !reflect.DeepEqual(got, []string{"URL_DECODE", "NORMALIZE_PATH"}) {
		t.Errorf("path transforms=%v", got)
	}

	uaRef := refOf(t, arms[1].(map[string]any))["RegexPatternSetReferenceStatement"].(map[string]any)
	if !reflect.DeepEqual(uaRef["FieldToMatch"], map[string]any{"SingleHeader": map[string]any{"Name": "user-agent"}}) {
		t.Errorf("ua field=%v", uaRef["FieldToMatch"])
	}
	if uaRef["ARN"] != "<waf-scanner-uas-ARN>" {
		t.Errorf("ua arn=%v", uaRef["ARN"])
	}
	if got := transformTypes(refOf(t, arms[1].(map[string]any))); !reflect.DeepEqual(got, []string{"COMPRESS_WHITE_SPACE", "LOWERCASE"}) {
		t.Errorf("ua transforms=%v", got)
	}
}

// The whole point of the second arm: a scanner off the served surface must be
// left to the app's 404, because a WAF block there answers 403 and breaks the
// task's undefined-path contract.
func TestAssembleScannerUaCatchesOnApiSurfaceOnly(t *testing.T) {
	assembled, err := AssembleRule("ua", scannerSummary, AssembleEnv{WafScope: "CLOUDFRONT", WafRegion: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := TestRule(assembled.SandboxRuleJson, []types.TestRequest{
		// Scanner on a served path — the request the rule exists for.
		{ID: "scanner-on-api", Method: "GET", Path: "/v1/user", UserAgent: "sqlmap/1.7", IP: "203.0.113.8", Country: "RU", Benign: false},
		// Same scanner on an undefined path — must NOT be blocked (404 is the contract).
		{ID: "scanner-off-api", Method: "GET", Path: "/admin", UserAgent: "sqlmap/1.7", IP: "203.0.113.8", Country: "RU", Benign: false},
		// The product binary's own trap UA, on a served path.
		{ID: "attacker-bot", Method: "POST", Path: "/v1/product", UserAgent: "Attacker-Bot", IP: "203.0.113.17", Benign: false},
		// Real traffic on a served path — the false positive that would cost score.
		{ID: "browser", Method: "GET", Path: "/v1/user", UserAgent: "Mozilla/5.0 (X11) AppleWebKit/537.36", IP: "10.0.2.88", Benign: true},
		// The load generator, which must never be touched.
		{ID: "loadgen", Method: "GET", Path: "/v1/user", UserAgent: "Go-http-client/2.0", IP: "10.0.2.23", Benign: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome := func(id string) string {
		for _, r := range res.Rows {
			if r.RequestID == id {
				return r.Outcome
			}
		}
		t.Fatalf("no row for %q", id)
		return ""
	}

	// CAUGHT = matched a Block rule and the request was malicious; BLOCKED is the
	// same match on a benign one, which is the false positive that costs score.
	if outcome("scanner-on-api") != "CAUGHT" {
		t.Errorf("scanner-on-api=%s want CAUGHT", outcome("scanner-on-api"))
	}
	if outcome("scanner-off-api") != "PASS" {
		t.Errorf("scanner-off-api=%s want PASS (an undefined path must be left to the app's 404)", outcome("scanner-off-api"))
	}
	if outcome("attacker-bot") != "CAUGHT" {
		t.Errorf("attacker-bot=%s want CAUGHT", outcome("attacker-bot"))
	}
	if outcome("browser") != "PASS" {
		t.Errorf("browser=%s want PASS", outcome("browser"))
	}
	if outcome("loadgen") != "PASS" {
		t.Errorf("loadgen=%s want PASS", outcome("loadgen"))
	}
	if res.Blocked != 0 {
		t.Errorf("blocked=%d, no benign request may be blocked", res.Blocked)
	}
}

// The product binary answers 500 to this User-Agent itself; the WAF has to turn
// it into a 403 first, so the assembler must recognise it as an attack.
func TestAttackerBotIsScanner(t *testing.T) {
	hit := ClassifyUa("Attacker-Bot")
	if hit == nil || hit.Category != CategoryScanner {
		t.Fatalf("Attacker-Bot classified as %+v, want SCANNER", hit)
	}
}
