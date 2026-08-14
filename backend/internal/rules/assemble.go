package rules

// Assembles a WAFv2 RegexPatternSet rule for one purpose — suspicious paths,
// suspicious User-Agents, or SQL injection — out of what the environment is
// actually seeing. Ported from src/lib/server/ruleassemble.ts; the pattern
// conventions (one regex per line, lowercase only, RE2, literals escaped)
// carry over unchanged.

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

// SqliPatterns is the fixed SQL-injection signature set, written against a
// URL_DECODE + HTML_ENTITY_DECODE + COMPRESS_WHITE_SPACE + LOWERCASE pipeline.
var SqliPatterns = []string{
	`union\s+(all\s+)?select|select\s+.+\s+from\s+`,
	`insert\s+into\s+|drop\s+table\s+|;\s*(select|insert|update|delete|drop)\b`,
	`\bor\s+1\s*=\s*1\b|\bor\s+'[^']*'\s*=\s*'|(^|[^a-z])(and|or)\s+\d+\s*=\s*\d+`,
	`sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay\s+`,
	`load_file\s*\(|into\s+outfile\s+`,
	`information_schema`,
	`--\s*$|/\*.*\*/`,
}

type kindSpec struct {
	name    string
	setName string
	// Every field the same pattern set is applied to. More than one produces an
	// OrStatement.
	fields []map[string]any
	// Applied in Priority order before the match.
	transforms []string
	notes      []string
}

var assembleSpecs = map[string]kindSpec{
	"path": {
		name:       "dash-regex-path",
		setName:    "dash-suspicious-paths",
		fields:     []map[string]any{{"UriPath": map[string]any{}}},
		transforms: []string{"URL_DECODE", "NORMALIZE_PATH", "LOWERCASE"},
		notes: []string{
			"관측된 경로 중 서비스 경로(APP_TRAFFIC_PATHS)와 헬스체크를 뺀 것만 패턴화 — 정상 트래픽은 매칭되지 않음",
			"URL_DECODE + NORMALIZE_PATH 를 먼저 적용해 %2f·/./ 인코딩 우회를 정규화한 뒤 매칭",
			"^/경로(/|$) 형태라 하위 경로는 잡고 접두어가 같은 다른 경로(/admin 대 /administration)는 잡지 않음",
		},
	},
	"ua": {
		name:       "dash-regex-ua",
		setName:    "dash-threat-uas",
		fields:     []map[string]any{{"SingleHeader": map[string]any{"Name": "user-agent"}}},
		transforms: []string{"URL_DECODE", "COMPRESS_WHITE_SPACE", "LOWERCASE"},
		notes: []string{
			"알려진 정상 클라이언트(렌더링 엔진을 밝힌 실제 브라우저 · Go 부하생성기 · ELB/Route53/kube 헬스체크 · 이 대시보드의 점검 요청)를 뺀 관측 User-Agent 전부를 패턴화",
			"허용 목록 방식 — 이름 붙은 공격 도구만 막으면 UA 를 위조한 쪽은 그대로 통과한다. \"Mozilla/5.0 (compatible)\" 처럼 아무 엔진도 밝히지 않는 문자열이 대표적",
			"SCANNER·RECON·AUTOMATION 은 도구 이름을, SPOOFED 는 페이로드 형태를, UNKNOWN 은 UA 의 첫 토큰(버전 앞부분)을 매칭 — 버전이 올라가도 계속 걸린다",
			"빈 User-Agent 는 ^$ 로 잡는다. 헤더 자체가 없는 요청은 SingleHeader 문장이 평가되지 않으므로 이 규칙으로는 잡히지 않는다 — 필요하면 별도 규칙이 필요",
			"COMPRESS_WHITE_SPACE 로 공백을 정규화한 뒤 소문자 매칭",
			"단어 경계를 둬서 도구 이름이 다른 토큰 안에 포함된 경우는 매칭하지 않음",
			"적용 전 반드시 시험 탭에서 판정해 볼 것 — 허용 목록에 없는 정상 클라이언트가 이 환경에 있다면 함께 차단된다",
		},
	},
	"sqli": {
		name:    "dash-regex-sqli",
		setName: "dash-sqli-signatures",
		// QueryString alone would miss a POST body payload.
		fields:     []map[string]any{{"QueryString": map[string]any{}}, {"Body": map[string]any{}}},
		transforms: []string{"URL_DECODE", "HTML_ENTITY_DECODE", "COMPRESS_WHITE_SPACE", "LOWERCASE"},
		notes: []string{
			"관측과 무관한 고정 시그니처 세트 — 트래픽이 조용해도 항상 같은 패턴을 냄",
			"쿼리 문자열과 요청 본문을 모두 검사 (OrStatement) — POST 본문에 실린 주입도 잡음",
			"URL_DECODE + HTML_ENTITY_DECODE 로 %20·&#x2f; 인코딩 우회를 먼저 풀고, COMPRESS_WHITE_SPACE 로 공백 삽입 우회를 정규화",
			"본문은 WAF 검사 상한까지만 읽힘 — CloudFront 기본 16KB(최대 64KB로 상향 가능), ALB 는 8KB 고정. 그 뒤에 실린 주입은 놓침",
			"AWS 관리형 SQLi 규칙 그룹과 겹칠 수 있음 — 중복 차단이 문제되면 COUNT 로 먼저 확인",
		},
	},
}

type patternSet struct {
	name     string
	patterns []string
}

func chunkSets(spec kindSpec, patterns []string) []patternSet {
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
		name := spec.setName
		if len(chunks) > 1 {
			name = fmt.Sprintf("%s-%d", spec.setName, i+1)
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
func buildRule(spec kindSpec, sets []patternSet, action string, arnFor func(string) string, inlineSets bool) string {
	transforms := make([]map[string]any, 0, len(spec.transforms))
	for i, t := range spec.transforms {
		transforms = append(transforms, map[string]any{"Priority": i, "Type": t})
	}

	// Every (set × field) pair gets its own reference statement; they are OR'd
	// because a match in any set on any field is the same finding.
	refs := []map[string]any{}
	for _, set := range sets {
		for _, field := range spec.fields {
			refs = append(refs, map[string]any{
				"RegexPatternSetReferenceStatement": map[string]any{
					"ARN":                 arnFor(set.name),
					"FieldToMatch":        field,
					"TextTransformations": transforms,
				},
			})
		}
	}

	var statement any = refs[0]
	if len(refs) > 1 {
		statement = map[string]any{"OrStatement": map[string]any{"Statements": refs}}
	}
	actionObj := map[string]any{"Count": map[string]any{}}
	if action == "BLOCK" {
		actionObj = map[string]any{"Block": map[string]any{}}
	}
	rule := map[string]any{
		"Name":      spec.name,
		"Priority":  100,
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
		for _, s := range sets {
			setMap[s.name] = s.patterns
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

// AssembleRule builds the rule for one purpose. summary is only read for the
// observed kinds; "sqli" ignores it entirely.
func AssembleRule(kind string, summary types.HttpSummary, env AssembleEnv) (types.AssembledRule, error) {
	spec, ok := assembleSpecs[kind]
	if !ok {
		return types.AssembledRule{}, fmt.Errorf("알 수 없는 규칙 종류: %s", kind)
	}
	patterns := []string{}
	evidence := []string{}

	switch kind {
	case "path":
		// Off-surface paths only: anything the environment actually serves, a
		// health check, or image delivery would be a false positive by
		// construction.
		seen := map[string]struct{}{}
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
			patterns = append(patterns, pattern)
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
			evidence = append(evidence, line)
		}
		if len(patterns) == 0 {
			return types.AssembledRule{}, fmt.Errorf("서비스 경로 밖에서 관측된 경로가 없음 — 패턴으로 만들 대상이 없습니다. (SQLi 는 관측과 무관하게 생성됩니다)")
		}
	case "ua":
		// Every observed UA that is not a client this environment expects, not
		// just the ones matching a named tool.
		seen := map[string]struct{}{}
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
				patterns = append(patterns, pattern)
				added = true
			}
			if added {
				detail := fmt.Sprintf(` %s 시그니처 "%s"`, hit.Category, hit.Label)
				if hit.Category == CategoryUnknown {
					detail = " UNKNOWN (알려진 정상 클라이언트가 아님)"
				}
				evidence = append(evidence, fmt.Sprintf(`"%s" — %d건 ·%s`, ua.Key, ua.Count, detail))
			}
		}
		if len(patterns) == 0 {
			// "Nothing suspicious was seen" and "nothing was seen" need
			// different answers from the operator.
			if len(summary.ByUa) == 0 {
				return types.AssembledRule{}, fmt.Errorf("User-Agent 통계가 비어 있습니다 — 관측된 UA 가 하나도 없어 규칙을 만들 수 없습니다. WAF GetSampledRequests 는 규칙에 매칭된 요청만 표본으로 남기므로, 아무것도 매칭하지 않는 WebACL 에서는 항상 0건입니다. WAF 로깅을 켜고 WAF_LOG_GROUP 을 지정하거나, 광범위한 COUNT 규칙을 하나 추가해 표본을 만드세요. (이 환경의 앱 로그에는 user_agent 필드가 없어 대체 수집이 불가능합니다.)")
			}
			return types.AssembledRule{}, fmt.Errorf("관측된 User-Agent 가 전부 알려진 정상 클라이언트(렌더링 엔진을 밝힌 브라우저 · Go 부하생성기 · AWS 헬스체크)입니다 — 패턴으로 만들 대상이 없습니다.")
		}
	default: // sqli
		patterns = append(patterns, SqliPatterns...)
		evidence = append(evidence, fmt.Sprintf("고정 시그니처 %d건 (관측 트래픽과 무관)", len(SqliPatterns)))
	}

	tooLong := []string{}
	for _, p := range patterns {
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

	// More patterns than the per-set cap become more sets — nothing is dropped.
	sets := chunkSets(spec, patterns)
	notes := append([]string{}, spec.notes...)
	if len(sets) > 1 {
		notes = append(notes, fmt.Sprintf("패턴 %d개를 세트 %d개로 나눠 담음 — 세트당 정규식 %d개가 AWS 고정 한도라, 나머지는 버리지 않고 세트를 늘려 OrStatement 로 묶었습니다. 콘솔에서는 정규식 패턴 세트를 %d개 만들고 각 ARN 을 넣으세요 (계정·리전당 패턴 세트 10개가 기본 한도, 상향 요청 가능).", len(patterns), len(sets), MaxPatternsPerSet, len(sets)))
	}

	// Observed-path rules stay in COUNT: the path list is a sample, and a path
	// that merely looks odd is not proof. UA and SQLi signatures are never
	// legitimate traffic, so those block outright.
	action := "BLOCK"
	if kind == "path" {
		action = "COUNT"
	}
	if action == "COUNT" {
		notes = append(notes, "Action 은 COUNT — 매칭량을 먼저 확인하고 오탐이 없을 때 Block 으로 바꾸세요.")
	} else {
		notes = append(notes, "Action 은 Block — 정상 트래픽이 매칭되지 않음을 시험 탭에서 확인한 뒤 적용하세요.")
	}

	specs := make([]types.RegexSetSpec, 0, len(sets))
	for _, set := range sets {
		specs = append(specs, types.RegexSetSpec{
			Name:           set.name,
			Patterns:       set.patterns,
			CreateCli:      createSetCli(env, set.name, set.patterns),
			ArnPlaceholder: Placeholder(set.name),
		})
	}

	return types.AssembledRule{
		Kind:            kind,
		Name:            spec.name,
		Patterns:        patterns,
		Sets:            specs,
		RuleJson:        buildRule(spec, sets, action, Placeholder, false),
		SandboxRuleJson: buildRule(spec, sets, action, func(n string) string { return n }, true),
		Evidence:        evidence,
		Notes:           notes,
	}, nil
}
