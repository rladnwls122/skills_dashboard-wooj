package rules

// The rule sandbox evaluator, ported from src/lib/server/rulesim.ts.
// User-supplied regex runs here, so every input is bounded (spec B5).

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

const (
	RuleJSONMax = 65_536 // covers a whole WebACL export, not just one rule
	MaxRequests = 50
	MaxRules    = 40
	FieldMax    = 500
	BodyMax     = 4_096
)

type parsedRule struct {
	name      string
	action    string
	priority  float64
	statement any
	labels    []string
}

func readAction(rule map[string]any) string {
	pick := func(v any) string {
		o := asRecord(v)
		if o == nil {
			return ""
		}
		for _, a := range []string{"Block", "Count", "Allow", "Captcha", "Challenge"} {
			if _, ok := o[a]; ok {
				return a
			}
		}
		// OverrideAction: { None: {} } leaves the group's own actions in force,
		// which for a blocking managed group means Block.
		if _, ok := o["None"]; ok {
			return "Block"
		}
		return ""
	}
	if a := pick(rule["Action"]); a != "" {
		return a
	}
	if a := pick(rule["OverrideAction"]); a != "" {
		return a
	}
	return "(none)"
}

func looksLikeStatement(v map[string]any) bool {
	for k := range v {
		if strings.HasSuffix(k, "Statement") {
			return true
		}
	}
	return false
}

func toRule(value any, index int) *parsedRule {
	r := asRecord(value)
	if r == nil {
		return nil
	}

	// A bare Statement body, pasted without the surrounding Rule wrapper.
	if _, ok := r["Statement"]; !ok {
		if looksLikeStatement(r) {
			return &parsedRule{name: "(문장만 붙여넣음)", action: "(none)", priority: float64(index), statement: r}
		}
		return nil
	}

	name, ok := str(r["Name"])
	if !ok {
		name = fmt.Sprintf("(이름 없음 #%d)", index+1)
	}
	priority := float64(index)
	if p, ok := r["Priority"].(float64); ok {
		priority = p
	}
	labels := []string{}
	if list, ok := r["RuleLabels"].([]any); ok {
		for _, l := range list {
			if n, ok := str(asRecord(l)["Name"]); ok {
				labels = append(labels, n)
			}
		}
	}
	return &parsedRule{name: name, action: readAction(r), priority: priority, statement: r["Statement"], labels: labels}
}

func readSetMap(value any, target map[string][]string) {
	rec := asRecord(value)
	if rec == nil {
		return
	}
	for key, entries := range rec {
		list := strList(entries)
		if len(list) == 0 {
			continue
		}
		lower := strings.ToLower(key)
		target[lower] = list
		// Also key by the ARN tail so "…/ipset/office-ips/abcd" resolves by name.
		for _, part := range strings.Split(lower, "/") {
			if part != "" {
				if _, ok := target[part]; !ok {
					target[part] = list
				}
			}
		}
	}
}

// documentEntries pulls the rule-shaped entries out of one pasted document: an
// array of Rules, a WebACL (wrapped or not), or a single Rule / bare Statement.
func documentEntries(doc any, ipSets, regexSets map[string][]string, notes *[]string) ([]any, error) {
	top := asRecord(doc)
	if top != nil {
		readSetMap(top["IPSets"], ipSets)
		readSetMap(top["RegexPatternSets"], regexSets)
	}

	if arr, ok := doc.([]any); ok {
		return arr, nil
	}

	acl := asRecord(top["WebACL"])
	if acl == nil {
		acl = top
	}
	if acl != nil {
		if list, ok := acl["Rules"].([]any); ok {
			if aclName, ok := str(acl["Name"]); ok {
				*notes = append(*notes, fmt.Sprintf(`WebACL "%s"에서 규칙 %d건을 읽음`, aclName, len(list)))
			}
			return list, nil
		}
	}
	if top != nil {
		return []any{top}, nil
	}
	return nil, fmt.Errorf("규칙 JSON이 객체나 배열이 아님 — WAFv2 Rule/WebACL JSON을 붙여넣어야 함")
}

type parsedInput struct {
	rules     []*parsedRule
	ipSets    map[string][]string
	regexSets map[string][]string
	notes     []string
}

func parseInput(ruleJSON string) (*parsedInput, error) {
	if len(ruleJSON) > RuleJSONMax {
		return nil, fmt.Errorf("규칙 JSON이 너무 큼 (최대 %dKB)", RuleJSONMax/1024)
	}

	notes := []string{}
	ipSets := map[string][]string{}
	regexSets := map[string][]string{}

	documents, err := ParseJsonDocuments(ruleJSON)
	if err != nil {
		return nil, err
	}
	raw := []any{}
	for _, doc := range documents {
		entries, err := documentEntries(doc, ipSets, regexSets, &notes)
		if err != nil {
			return nil, err
		}
		raw = append(raw, entries...)
	}

	if len(raw) > MaxRules {
		return nil, fmt.Errorf("규칙이 너무 많음 (최대 %d건)", MaxRules)
	}

	parsed := []*parsedRule{}
	for i, r := range raw {
		if rule := toRule(r, i); rule != nil {
			parsed = append(parsed, rule)
		}
	}
	if len(parsed) > 1 {
		if len(documents) > 1 {
			notes = append(notes, fmt.Sprintf("붙여넣은 JSON %d덩어리에서 규칙 %d건을 읽어 우선순위 순서로 평가함", len(documents), len(parsed)))
		} else {
			notes = append(notes, fmt.Sprintf("규칙 %d건을 우선순위 순서로 평가함", len(parsed)))
		}
	}

	if len(parsed) == 0 {
		return nil, fmt.Errorf("평가할 규칙을 찾지 못함 — WAFv2 Rule 하나, Rule 배열, WebACL JSON, 또는 Statement 본문을 붙여넣어야 함")
	}
	if len(parsed) < len(raw) {
		notes = append(notes, fmt.Sprintf("Statement가 없는 항목 %d건은 건너뜀", len(raw)-len(parsed)))
	}

	sort.SliceStable(parsed, func(i, j int) bool { return parsed[i].priority < parsed[j].priority })
	return &parsedInput{rules: parsed, ipSets: ipSets, regexSets: regexSets, notes: notes}, nil
}

func validateRequests(requests []types.TestRequest) error {
	if len(requests) == 0 {
		return fmt.Errorf("시험할 요청이 없음 — 최소 1건 필요")
	}
	if len(requests) > MaxRequests {
		return fmt.Errorf("요청이 너무 많음 (최대 %d건)", MaxRequests)
	}
	for _, r := range requests {
		fields := [][2]string{
			{"method", r.Method}, {"path", r.Path}, {"query", r.Query},
			{"userAgent", r.UserAgent}, {"ip", r.IP}, {"country", r.Country},
		}
		for _, f := range fields {
			if len(f[1]) > FieldMax {
				return fmt.Errorf("요청 %s의 %s가 너무 김 (최대 %d자)", r.ID, f[0], FieldMax)
			}
		}
		for name, value := range r.Headers {
			if len(value) > FieldMax {
				return fmt.Errorf("요청 %s의 헤더 %s가 너무 김 (최대 %d자)", r.ID, name, FieldMax)
			}
		}
		if len(r.Body) > BodyMax {
			return fmt.Errorf("요청 %s의 바디가 너무 김 (최대 %d자)", r.ID, BodyMax)
		}
	}
	return nil
}

// --- evaluation --------------------------------------------------------------

// Block / Allow / Captcha / Challenge end the WebACL walk for that request;
// Count only records and evaluation continues to the next rule.
func isTerminating(action string) bool {
	return action == "Block" || action == "Allow" || action == "Captcha" || action == "Challenge"
}

func outcomeFor(action string, benign bool) (outcome, reason string) {
	switch action {
	case "Block":
		if benign {
			return "BLOCKED", "정상 요청이 매칭되고 Block — 오탐 위험"
		}
		return "CAUGHT", "악성 예시가 매칭되고 Block — 정탐(차단)"
	case "Count":
		return "COUNTED", "매칭되지만 Action이 Count — 차단되지 않고 계측만"
	case "Allow":
		return "PASS", "규칙에 매칭되고 Action이 Allow — 통과"
	case "Captcha":
		if benign {
			return "CHALLENGED", "정상 요청이 CAPTCHA 대상 — 사용자에게 퍼즐이 뜸"
		}
		return "CHALLENGED", "악성 예시가 CAPTCHA 대상 — 자동화 도구는 대개 여기서 멈춤"
	case "Challenge":
		if benign {
			return "CHALLENGED", "정상 요청이 Challenge 대상 — 브라우저 검증 후 통과"
		}
		return "CHALLENGED", "악성 예시가 Challenge 대상 — 스크립트는 대개 통과하지 못함"
	default:
		return "MATCHED", "매칭되지만 규칙에 Action이 없음 — 차단 여부 판단 불가"
	}
}

func evaluateRequest(req types.TestRequest, ruleList []*parsedRule, ctx *EvalContext) types.RuleTestRow {
	// Labels are per request: a rule only sees what earlier rules added to
	// *this* request.
	ctx.Emitted = map[string]struct{}{}
	normalized := NormalizeRequest(req)

	var counted, matchedNoAction *parsedRule

	for _, rule := range ruleList {
		verdict := EvalStatement(rule.statement, normalized, ctx)
		if verdict == VerdictUnknown {
			return types.RuleTestRow{
				RequestID: req.ID,
				Matched:   nil,
				Outcome:   "UNKNOWN",
				Reason:    fmt.Sprintf(`"%s"을 로컬에서 평가할 수 없음 — 이후 규칙 판정도 신뢰할 수 없어 중단`, rule.name),
				RuleName:  types.Ptr(rule.name),
			}
		}
		if verdict != VerdictTrue {
			continue
		}

		for _, l := range rule.labels {
			ctx.Emitted[l] = struct{}{}
		}

		if isTerminating(rule.action) {
			outcome, reason := outcomeFor(rule.action, req.Benign)
			return types.RuleTestRow{RequestID: req.ID, Matched: types.Ptr(true), Outcome: outcome, Reason: reason, RuleName: types.Ptr(rule.name)}
		}
		if rule.action == "Count" {
			if counted == nil {
				counted = rule
			}
		} else if matchedNoAction == nil {
			matchedNoAction = rule
		}
	}

	if counted != nil {
		outcome, reason := outcomeFor("Count", req.Benign)
		return types.RuleTestRow{RequestID: req.ID, Matched: types.Ptr(true), Outcome: outcome, Reason: reason, RuleName: types.Ptr(counted.name)}
	}
	if matchedNoAction != nil {
		outcome, reason := outcomeFor("(none)", req.Benign)
		return types.RuleTestRow{RequestID: req.ID, Matched: types.Ptr(true), Outcome: outcome, Reason: reason, RuleName: types.Ptr(matchedNoAction.name)}
	}
	reason := "악성 예시가 어떤 규칙에도 걸리지 않음 — 미탐(놓침)"
	if req.Benign {
		reason = "정상 요청이 어떤 규칙에도 매칭되지 않음 — 통과"
	}
	return types.RuleTestRow{RequestID: req.ID, Matched: types.Ptr(false), Outcome: "PASS", Reason: reason, RuleName: nil}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestRule(ruleJSON string, requests []types.TestRequest) (types.RuleTestResult, error) {
	if err := validateRequests(requests); err != nil {
		return types.RuleTestResult{}, err
	}
	input, err := parseInput(ruleJSON)
	if err != nil {
		return types.RuleTestResult{}, err
	}

	ctx := NewEvalContext()
	ctx.IPSets = input.ipSets
	ctx.RegexSets = input.regexSets

	rows := make([]types.RuleTestRow, 0, len(requests))
	for _, req := range requests {
		rows = append(rows, evaluateRequest(req, input.rules, ctx))
	}

	count := func(o string) int {
		n := 0
		for _, r := range rows {
			if r.Outcome == o {
				n++
			}
		}
		return n
	}
	blocked := count("BLOCKED")
	unknown := count("UNKNOWN")
	caught := count("CAUGHT")
	challenged := count("CHALLENGED")

	byID := map[string]types.TestRequest{}
	for _, r := range requests {
		byID[r.ID] = r
	}
	missed := 0
	challengedBenign := 0
	for _, r := range rows {
		req, ok := byID[r.RequestID]
		if ok && !req.Benign && r.Outcome != "CAUGHT" && r.Outcome != "CHALLENGED" && r.Outcome != "UNKNOWN" {
			missed++
		}
		if r.Outcome == "CHALLENGED" && (!ok || req.Benign) {
			challengedBenign++
		}
	}

	notes := append([]string{}, input.notes...)
	notes = append(notes, sortedKeys(ctx.Notes)...)
	if len(ctx.Unsupported) > 0 {
		notes = append(notes, fmt.Sprintf("로컬에서 평가할 수 없는 문법: %s — 해당 요청은 판정 불가로 표시됨", strings.Join(sortedKeys(ctx.Unsupported), ", ")))
	}
	if len(ctx.Approximated) > 0 {
		notes = append(notes, fmt.Sprintf("근사 평가된 문법: %s — 로컬 판정과 실제 WAF 판정이 다를 수 있으므로 COUNT 검증 필수", strings.Join(sortedKeys(ctx.Approximated), ", ")))
	}
	allCount := true
	for _, r := range input.rules {
		if r.action != "Count" {
			allCount = false
			break
		}
	}
	if allCount {
		notes = append(notes, "전부 COUNT 모드 — 매칭돼도 실제 차단은 발생하지 않음")
	}
	notes = append(notes, "합성 요청에 대한 로컬 평가 결과 — 실제 적용 전 COUNT로 검증 필요")
	if caught > 0 {
		notes = append(notes, fmt.Sprintf("악성 예시 %d건 차단(정탐)", caught))
	}
	if challengedBenign > 0 {
		notes = append(notes, fmt.Sprintf("정상 요청 %d건이 CAPTCHA/Challenge 대상 — 사용자 마찰 발생", challengedBenign))
	}
	if missed > 0 {
		notes = append(notes, fmt.Sprintf("악성 예시 %d건이 규칙을 통과함(미탐) — 규칙이 공격을 놓침", missed))
	}

	ruleName := fmt.Sprintf("규칙 %d건", len(input.rules))
	action := "(none)"
	if len(input.rules) == 1 {
		ruleName = input.rules[0].name
		action = input.rules[0].action
	}
	verdict := "SAFE"
	// Only a blocked *benign* request is a false positive; caught malicious
	// traffic is the goal, not a risk.
	if blocked > 0 {
		verdict = "FALSE_POSITIVE_RISK"
	} else if unknown > 0 {
		verdict = "INCONCLUSIVE"
	}
	return types.RuleTestResult{
		RuleName:     ruleName,
		Action:       action,
		RuleCount:    len(input.rules),
		Unsupported:  sortedKeys(ctx.Unsupported),
		Approximated: sortedKeys(ctx.Approximated),
		Rows:         rows,
		Passed:       count("PASS"),
		Blocked:      blocked,
		Counted:      count("COUNTED"),
		Challenged:   challenged,
		Matched:      count("MATCHED"),
		Caught:       caught,
		Missed:       missed,
		Unknown:      unknown,
		Verdict:      verdict,
		Notes:        notes,
	}, nil
}
