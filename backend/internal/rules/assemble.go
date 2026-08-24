package rules

// Assembles a WAFv2 RegexPatternSet rule for one purpose out of what the
// environment is actually seeing. Ported from src/lib/server/ruleassemble.ts;
// the pattern conventions (one regex per line, lowercase only, RE2, literals
// escaped) are AWS's, not ours.
//
// A rule is one or more *arms*, AND'd together. An arm is a pattern set matched
// against one or more fields under its own transform pipeline. Two arms is what
// the scanner rule needs: the User-Agent set alone would block a scanner
// anywhere on the site, including paths the task never serves, where the
// contract says the answer must be 404 rather than 403. Pairing "the request is
// on a served API path" with "the client is a known scanner" keeps the block
// exactly where a 403 is the wanted answer.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// Fixed AWS WAF quotas (not adjustable).
const (
	MaxPatternsPerSet = 10
	MaxPatternChars   = 200
)

var literalMetaRe = mustAll(`[.*+?^${}()|[\]\\/]`)[0]

// EscapeLiteral escapes every regex metacharacter so a literal is matched as
// text.
func EscapeLiteral(s string) string {
	return literalMetaRe.ReplaceAllString(s, `\$0`)
}

// PathPattern is anchored at the start and ends at a segment boundary, so
// "/admin" matches /admin and /admin/x but never /administration.
func PathPattern(path string) string {
	// NORMALIZE_PATH runs before the match, so the pattern has to describe the
	// resolved path — "/v1/image/../../etc/passwd" is matched as "/etc/passwd".
	clean := strings.ToLower(config.NormalizePath(path))
	trimmed := clean
	if strings.HasSuffix(clean, "/") && len(clean) > 1 {
		trimmed = clean[:len(clean)-1]
	}
	return "^" + EscapeLiteral(trimmed) + "(/|$)"
}

// UaPattern matches anywhere in the header, with tool names held to a word-ish
// boundary so "nmap" does not fire inside "nmapper-client".
func UaPattern(needle string) string {
	return "(^|[^a-z0-9])" + EscapeLiteral(strings.ToLower(needle)) + "([^a-z0-9]|$)"
}

// Tokens every real browser also leads with. An UNKNOWN client whose first
// token is one of these gets matched on the whole string instead — a forged UA
// is a fixed string anyway, and the alternative is an outage.
var browserishTokens = map[string]struct{}{
	"mozilla": {}, "chrome": {}, "safari": {}, "firefox": {}, "opera": {},
	"edge": {}, "edg": {}, "msie": {}, "webkit": {},
}

// UaPatternsFor: the regexes that express one UA classification. A
// SCANNER/RECON/AUTOMATION label is the tool name as it literally appears in
// the header, a SPOOFED label is a category name that appears nowhere in it,
// and an UNKNOWN label is the client's own leading token.
func UaPatternsFor(category ThreatCategory, label, rawUa string) []string {
	if category == CategorySpoofed {
		return SpoofedUaPatterns(label)
	}
	// A request that sent no User-Agent at all. WAF only evaluates this when
	// the header is present-but-empty.
	if label == "" || strings.HasPrefix(label, "(") {
		return []string{"^$"}
	}
	if category == CategoryUnknown {
		if _, ok := browserishTokens[label]; ok {
			return []string{"^" + EscapeLiteral(strings.ToLower(strings.TrimSpace(rawUa))) + "$"}
		}
	}
	return []string{UaPattern(label)}
}

// armSource says how an arm's patterns are produced.
type armSource string

const (
	sourceServedPaths   armSource = "servedPaths"
	sourceObservedPaths armSource = "observedPaths"
	sourceScannerUas    armSource = "scannerUas"
)

// matchArm is one AND-ed condition: a pattern set matched against one or more
// fields, under its own transform pipeline. Several fields inside one arm are
// OR'd — a match on any of them is the same finding.
type matchArm struct {
	setName string
	source  armSource
	fields  []map[string]any
	// Applied in Priority order before the match.
	transforms []string
}

type kindSpec struct {
	name     string
	priority int
	action   string // "COUNT" or "BLOCK"
	// AND'd together.
	arms  []matchArm
	notes []string
}

var assembleSpecs = map[string]kindSpec{
	"path": {
		name:     "dash-regex-path",
		priority: 100,
		// The path list is a sample and a path that merely looks odd is not proof.
		action: "COUNT",
		arms: []matchArm{
			{
				setName:    "dash-suspicious-paths",
				source:     sourceObservedPaths,
				fields:     []map[string]any{{"UriPath": map[string]any{}}},
				transforms: []string{"URL_DECODE", "NORMALIZE_PATH", "LOWERCASE"},
			},
		},
		notes: []string{
			"관측된 경로 중 서비스 경로(APP_TRAFFIC_PATHS)와 헬스체크를 뺀 것만 패턴화 — 정상 트래픽은 매칭되지 않음",
			"URL_DECODE + NORMALIZE_PATH 를 먼저 적용해 %2f·/./ 인코딩 우회를 정규화한 뒤 매칭",
			"^/경로(/|$) 형태라 하위 경로는 잡고 접두어가 같은 다른 경로(/admin 대 /administration)는 잡지 않음",
		},
	},
	"ua": {
		name:     "scanner-ua",
		priority: 30,
		action:   "BLOCK",
		arms: []matchArm{
			{
				// Arm 1 — where. The served API surface, so the block cannot reach
				// a path whose contract answer is 404.
				setName:    "waf-api-paths",
				source:     sourceServedPaths,
				fields:     []map[string]any{{"UriPath": map[string]any{}}},
				transforms: []string{"URL_DECODE", "NORMALIZE_PATH"},
			},
			{
				// Arm 2 — who. The scanner/spoofed User-Agents actually observed.
				setName:    "waf-scanner-uas",
				source:     sourceScannerUas,
				fields:     []map[string]any{{"SingleHeader": map[string]any{"Name": "user-agent"}}},
				transforms: []string{"COMPRESS_WHITE_SPACE", "LOWERCASE"},
			},
		},
		notes: []string{
			"두 조건의 AND — ①서비스 경로(APP_TRAFFIC_PATHS)로 들어온 요청이면서 ②User-Agent 가 스캐너로 분류된 경우에만 차단합니다.",
			"경로 조건을 붙이는 이유: UA 만으로 막으면 미지정 경로에도 403 이 나갑니다. 과제 계약은 미지정 경로에 404 를 요구하므로 그 자체가 위반입니다. 403 이 정답인 곳에서만 차단합니다.",
			"알려진 정상 클라이언트(렌더링 엔진을 밝힌 실제 브라우저 · Go 부하생성기 · ELB/Route53/kube 헬스체크 · 이 대시보드의 점검 요청)를 뺀 관측 User-Agent 전부를 패턴화",
			"허용 목록 방식 — 이름 붙은 공격 도구만 막으면 UA 를 위조한 쪽은 그대로 통과한다. \"Mozilla/5.0 (compatible)\" 처럼 아무 엔진도 밝히지 않는 문자열이 대표적",
			"SCANNER·RECON·AUTOMATION 은 도구 이름을, SPOOFED 는 페이로드 형태를, UNKNOWN 은 UA 의 첫 토큰(버전 앞부분)을 매칭 — 버전이 올라가도 계속 걸린다",
			"product 바이너리가 스스로 500 으로 응답하는 Attacker-Bot 도 SCANNER 로 분류되어 여기 포함됩니다 — WAF 가 먼저 403 으로 끊어야 하는 요청입니다.",
			"빈 User-Agent 는 ^$ 로 잡는다. 헤더 자체가 없는 요청은 SingleHeader 문장이 평가되지 않으므로 이 규칙으로는 잡히지 않는다 — 필요하면 별도 규칙이 필요",
			"경로 세트에는 NORMALIZE_PATH 만 걸고 LOWERCASE 는 걸지 않습니다 — 서비스 경로가 전부 소문자라 불필요하고, UA 쪽 파이프라인과 섞이지 않습니다.",
			"정규식 패턴 세트를 2개 만들어야 합니다 — 경로용·UA용 각각의 ARN 을 규칙 JSON 에 넣으세요.",
			"과제에서 제공한 terraform 으로 구축했다면 두 세트는 이미 있습니다. ARN 은 `terraform output waf_api_paths_arn` 과 `terraform output waf_scanner_uas_arn` 이고, 위 패턴을 그 세트에 넣으면 됩니다 — 세트를 새로 만들 필요는 없습니다.",
			"제공된 waf/scanner-ua.json 과 같은 모양입니다: Priority 30, sqli(10)·known-bad-inputs(20) 뒤, base64-sqli(40) 앞.",
			"적용 전 반드시 판정해 볼 것 — 허용 목록에 없는 정상 클라이언트가 이 환경에 있다면 함께 차단된다",
		},
	},
}

type patternSet struct {
	name     string
	patterns []string
}

// builtArm is one arm resolved against the observed traffic: the arm and the
// pattern sets its source produced.
type builtArm struct {
	arm  matchArm
	sets []patternSet
}

func chunkSets(setName string, patterns []string) []patternSet {
	chunks := [][]string{}
	for i := 0; i < len(patterns); i += MaxPatternsPerSet {
		end := i + MaxPatternsPerSet
		if end > len(patterns) {
			end = len(patterns)
		}
		chunks = append(chunks, patterns[i:end])
	}
	out := make([]patternSet, 0, len(chunks))
	for i, pats := range chunks {
		name := setName
		if len(chunks) > 1 {
			name = fmt.Sprintf("%s-%d", setName, i+1)
		}
		out = append(out, patternSet{name: name, patterns: pats})
	}
	return out
}

// Placeholder stands in for a set's ARN until the operator creates it and
// pastes the real one back.
func Placeholder(setName string) string {
	return "<" + setName + "-ARN>"
}

// AssembleEnv carries the two settings the generated CLI needs. Kept as plain
// values so this package stays pure.
type AssembleEnv struct {
	WafScope  string
	WafRegion string
}

// createSetCli is printed rather than run: creating resources is the
// operator's call, and the command is reviewable before it happens.
func createSetCli(env AssembleEnv, setName string, patterns []string) string {
	type entry struct {
		RegexString string
	}
	list := make([]entry, 0, len(patterns))
	for _, p := range patterns {
		list = append(list, entry{p})
	}
	raw, _ := json.Marshal(list)
	return strings.Join([]string{
		"aws wafv2 create-regex-pattern-set",
		"--name " + setName,
		"--scope " + env.WafScope,
		"--region " + env.WafRegion,
		"--regular-expression-list '" + string(raw) + "'",
	}, " ")
}

// buildRule renders the rule JSON. arnFor decides what goes in the ARN field:
// a placeholder for the console copy, the bare set name for the sandbox.
func buildRule(spec kindSpec, built []builtArm, action string, arnFor func(string) string, inlineSets bool) string {
	// Within an arm, every (set × field) pair is its own reference statement and
	// they are OR'd — a match in any set on any field is the same finding. The
	// arms themselves are AND'd: each is a separate condition on the request.
	armStatements := make([]any, 0, len(built))
	for _, b := range built {
		transforms := make([]map[string]any, 0, len(b.arm.transforms))
		for i, t := range b.arm.transforms {
			transforms = append(transforms, map[string]any{"Priority": i, "Type": t})
		}
		refs := []map[string]any{}
		for _, set := range b.sets {
			for _, field := range b.arm.fields {
				refs = append(refs, map[string]any{
					"RegexPatternSetReferenceStatement": map[string]any{
						"ARN":                 arnFor(set.name),
						"FieldToMatch":        field,
						"TextTransformations": transforms,
					},
				})
			}
		}
		if len(refs) > 1 {
			armStatements = append(armStatements, map[string]any{"OrStatement": map[string]any{"Statements": refs}})
		} else {
			armStatements = append(armStatements, refs[0])
		}
	}

	var statement any = armStatements[0]
	if len(armStatements) > 1 {
		statement = map[string]any{"AndStatement": map[string]any{"Statements": armStatements}}
	}
	actionObj := map[string]any{"Count": map[string]any{}}
	if action == "BLOCK" {
		actionObj = map[string]any{"Block": map[string]any{}}
	}
	rule := map[string]any{
		"Name":      spec.name,
		"Priority":  spec.priority,
		"Statement": statement,
		"Action":    actionObj,
		"VisibilityConfig": map[string]any{
			"SampledRequestsEnabled":   true,
			"CloudWatchMetricsEnabled": true,
			"MetricName":               spec.name,
		},
	}

	var doc any = rule
	if inlineSets {
		// Sandbox-only: the local evaluator reads pattern sets from the top
		// level, which is how a rule can be judged before the set exists.
		setMap := map[string]any{}
		for _, b := range built {
			for _, s := range b.sets {
				setMap[s.name] = s.patterns
			}
		}
		doc = map[string]any{"RegexPatternSets": setMap, "Rules": []any{rule}}
	}
	// No HTML escaping: the ARN placeholder is literally "<name-ARN>", and
	// < in pasted JSON would hide what the operator must replace.
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return ""
	}
	return strings.TrimRight(buf.String(), "\n")
}

// servedPathPatterns is the served API surface, as patterns. Independent of
// observed traffic.
func servedPathPatterns(evidence *[]string) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}
	for _, p := range config.AppTrafficPaths() {
		pattern := PathPattern(p)
		if _, dup := seen[pattern]; dup {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
		*evidence = append(*evidence, fmt.Sprintf("%s — 서비스 경로 (APP_TRAFFIC_PATHS)", p))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("서비스 경로가 비어 있습니다 — APP_TRAFFIC_PATHS 를 설정해야 경로 조건을 만들 수 있습니다.")
	}
	return out, nil
}

// scannerUaPatterns is the observed User-Agents that are not clients this
// environment expects.
func scannerUaPatterns(summary types.HttpSummary, evidence *[]string) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}
	for _, ua := range summary.ByUa {
		hit := ClassifyUa(ua.Key)
		if hit == nil {
			continue
		}
		fresh := UaPatternsFor(hit.Category, hit.Label, ua.Key)
		if len(fresh) == 0 {
			continue
		}
		added := false
		for _, pattern := range fresh {
			if _, dup := seen[pattern]; dup {
				continue
			}
			seen[pattern] = struct{}{}
			out = append(out, pattern)
			added = true
		}
		if added {
			detail := fmt.Sprintf(` %s 시그니처 "%s"`, hit.Category, hit.Label)
			if hit.Category == CategoryUnknown {
				detail = " UNKNOWN (알려진 정상 클라이언트가 아님)"
			}
			*evidence = append(*evidence, fmt.Sprintf(`"%s" — %d건 ·%s`, ua.Key, ua.Count, detail))
		}
	}
	if len(out) == 0 {
		// "Nothing suspicious was seen" and "nothing was seen" need different
		// answers from the operator.
		if len(summary.ByUa) == 0 {
			return nil, fmt.Errorf("User-Agent 통계가 비어 있습니다 — 관측된 UA 가 하나도 없어 규칙을 만들 수 없습니다. WAF GetSampledRequests 는 규칙에 매칭된 요청만 표본으로 남기므로, 아무것도 매칭하지 않는 WebACL 에서는 항상 0건입니다. WAF 로깅을 켜고 WAF_LOG_GROUP 을 지정하거나, 광범위한 COUNT 규칙을 하나 추가해 표본을 만드세요. (바이너리의 [GIN] 액세스 라인에는 User-Agent 가 없어 앱 로그로 대체할 수 없습니다.)")
		}
		return nil, fmt.Errorf("관측된 User-Agent 가 전부 알려진 정상 클라이언트(렌더링 엔진을 밝힌 브라우저 · Go 부하생성기 · AWS 헬스체크)입니다 — 패턴으로 만들 대상이 없습니다.")
	}
	return out, nil
}

// observedPathPatterns is the observed off-surface paths, as patterns.
func observedPathPatterns(summary types.HttpSummary, evidence *[]string) ([]string, error) {
	// Off-surface paths only: anything the environment actually serves, a health
	// check, or image delivery would be a false positive by construction.
	seen := map[string]struct{}{}
	out := []string{}
	for _, p := range summary.ByPath {
		if !strings.HasPrefix(p.Path, "/") {
			continue
		}
		if config.IsBenignPath(p.Path) {
			continue
		}
		pattern := PathPattern(p.Path)
		if _, dup := seen[pattern]; dup {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)

		// Show the resolved path when normalisation changed it.
		resolved := config.NormalizePath(p.Path)
		base := p.Path
		if i := strings.IndexByte(base, '?'); i >= 0 {
			base = base[:i]
		}
		shown := p.Path
		if resolved != base {
			shown = p.Path + " → " + resolved
		}
		line := fmt.Sprintf("%s — %d건", shown, p.Count)
		if p.Blocked > 0 {
			line += fmt.Sprintf(" (차단 %d)", p.Blocked)
		}
		if p.Suspicious {
			line += " · 의심 경로"
		}
		*evidence = append(*evidence, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("서비스 경로 밖에서 관측된 경로가 없음 — 패턴으로 만들 대상이 없습니다.")
	}
	return out, nil
}

// AssembleRule builds the rule for one purpose out of what the environment is
// seeing.
func AssembleRule(kind string, summary types.HttpSummary, env AssembleEnv) (types.AssembledRule, error) {
	spec, ok := assembleSpecs[kind]
	if !ok {
		return types.AssembledRule{}, fmt.Errorf("알 수 없는 규칙 종류: %s", kind)
	}

	patterns := []string{}
	evidence := []string{}
	built := []builtArm{}

	for _, arm := range spec.arms {
		var armPatterns []string
		var err error
		switch arm.source {
		case sourceServedPaths:
			armPatterns, err = servedPathPatterns(&evidence)
		case sourceScannerUas:
			armPatterns, err = scannerUaPatterns(summary, &evidence)
		default:
			armPatterns, err = observedPathPatterns(summary, &evidence)
		}
		if err != nil {
			return types.AssembledRule{}, err
		}

		tooLong := []string{}
		for _, p := range armPatterns {
			if len(p) > MaxPatternChars {
				cut := p
				if len(cut) > 40 {
					cut = cut[:40]
				}
				tooLong = append(tooLong, cut)
			}
		}
		if len(tooLong) > 0 {
			return types.AssembledRule{}, fmt.Errorf("정규식 %d자 한도를 넘는 패턴이 있음: %s", MaxPatternChars, strings.Join(tooLong, ", "))
		}

		patterns = append(patterns, armPatterns...)
		// More patterns than the per-set cap become more sets — nothing is dropped.
		built = append(built, builtArm{arm: arm, sets: chunkSets(arm.setName, armPatterns)})
	}

	notes := append([]string{}, spec.notes...)
	for _, b := range built {
		if len(b.sets) > 1 {
			notes = append(notes, fmt.Sprintf("\"%s\" 패턴을 세트 %d개로 나눠 담음 — 세트당 정규식 %d개가 AWS 고정 한도라, 나머지는 버리지 않고 세트를 늘려 OrStatement 로 묶었습니다. 콘솔에서 세트를 %d개 만들고 각 ARN 을 넣으세요 (계정·리전당 패턴 세트 10개가 기본 한도, 상향 요청 가능).", b.arm.setName, len(b.sets), MaxPatternsPerSet, len(b.sets)))
		}
	}
	if spec.action == "COUNT" {
		notes = append(notes, "Action 은 COUNT — 매칭량을 먼저 확인하고 오탐이 없을 때 Block 으로 바꾸세요.")
	} else {
		notes = append(notes, "Action 은 Block — 정상 트래픽이 매칭되지 않음을 확인한 뒤 적용하세요.")
	}

	specs := []types.RegexSetSpec{}
	for _, b := range built {
		for _, set := range b.sets {
			specs = append(specs, types.RegexSetSpec{
				Name:           set.name,
				Patterns:       set.patterns,
				CreateCli:      createSetCli(env, set.name, set.patterns),
				ArnPlaceholder: Placeholder(set.name),
			})
		}
	}

	return types.AssembledRule{
		Kind:            kind,
		Name:            spec.name,
		Patterns:        patterns,
		Sets:            specs,
		RuleJson:        buildRule(spec, built, spec.action, Placeholder, false),
		SandboxRuleJson: buildRule(spec, built, spec.action, func(n string) string { return n }, true),
		Evidence:        evidence,
		Notes:           notes,
	}, nil
}
