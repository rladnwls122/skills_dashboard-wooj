package rules

// The WAFv2 statement evaluator, ported from src/lib/server/rulestatement.ts.
// Three-valued: UNKNOWN means "this cannot be decided locally" and is never
// collapsed into a yes or no — a rule tester that guesses is worse than none.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Verdict3 int

const (
	VerdictFalse Verdict3 = iota
	VerdictTrue
	VerdictUnknown
)

func fromBool(b bool) Verdict3 {
	if b {
		return VerdictTrue
	}
	return VerdictFalse
}

type EvalContext struct {
	// statement types encountered that cannot be evaluated locally
	Unsupported map[string]struct{}
	// operator-facing explanations
	Notes map[string]struct{}
	// statement types answered by a local approximation — usable, not authoritative
	Approximated map[string]struct{}
	// referenced sets resolved from the pasted JSON, keyed by ARN, ARN tail and
	// bare name (all lower-cased)
	IPSets    map[string][]string
	RegexSets map[string][]string
	// labels a matching rule would add, collected for later LabelMatchStatements
	Emitted map[string]struct{}
}

const RegexMax = 200

func NewEvalContext() *EvalContext {
	return &EvalContext{
		Unsupported:  map[string]struct{}{},
		Notes:        map[string]struct{}{},
		Approximated: map[string]struct{}{},
		IPSets:       map[string][]string{},
		RegexSets:    map[string][]string{},
		Emitted:      map[string]struct{}{},
	}
}

func (c *EvalContext) note(s string)   { c.Notes[s] = struct{}{} }
func (c *EvalContext) unsup(s string)  { c.Unsupported[s] = struct{}{} }
func (c *EvalContext) approx(s string) { c.Approximated[s] = struct{}{} }

func asRecord(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func str(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func strList(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	default:
		return 0
	}
}

// --- FieldToMatch ------------------------------------------------------------

// scoped: MatchScope on a multi-value field selects keys, values, or both.
func scoped(entries [][2]string, scope string) []string {
	switch strings.ToUpper(scope) {
	case "KEY":
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e[0])
		}
		return out
	case "ALL":
		out := make([]string, 0, 2*len(entries))
		for _, e := range entries {
			out = append(out, e[0], e[1])
		}
		return out
	default:
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e[1])
		}
		return out
	}
}

// patternFilter: MatchPattern narrows which keys of a multi-value field are
// inspected.
func patternFilter(entries [][2]string, pattern any) [][2]string {
	p := asRecord(pattern)
	if p == nil {
		return entries
	}
	if _, ok := p["All"]; ok {
		return entries
	}
	lower := func(list []string) map[string]struct{} {
		out := map[string]struct{}{}
		for _, s := range list {
			out[strings.ToLower(s)] = struct{}{}
		}
		return out
	}
	included := strList(p["IncludedHeaders"])
	if len(included) == 0 {
		included = strList(p["IncludedCookies"])
	}
	if len(included) > 0 {
		set := lower(included)
		out := [][2]string{}
		for _, e := range entries {
			if _, ok := set[strings.ToLower(e[0])]; ok {
				out = append(out, e)
			}
		}
		return out
	}
	excluded := strList(p["ExcludedHeaders"])
	if len(excluded) == 0 {
		excluded = strList(p["ExcludedCookies"])
	}
	if len(excluded) > 0 {
		set := lower(excluded)
		out := [][2]string{}
		for _, e := range entries {
			if _, ok := set[strings.ToLower(e[0])]; !ok {
				out = append(out, e)
			}
		}
		return out
	}
	return entries
}

// flattenJson flattens a parsed JSON body into "leaf key -> value" pairs so
// JsonBody's MatchScope has something to select from.
func flattenJson(value any, prefix string, out *[][2]string) {
	switch v := value.(type) {
	case []any:
		for i, item := range v {
			flattenJson(item, fmt.Sprintf("%s/%d", prefix, i), out)
		}
	case map[string]any:
		for k, item := range v {
			flattenJson(item, prefix+"/"+k, out)
		}
	default:
		key := prefix
		if i := strings.LastIndexByte(prefix, '/'); i >= 0 {
			key = prefix[i+1:]
		}
		var s string
		switch t := v.(type) {
		case nil:
			s = "null"
		case string:
			s = t
		case bool:
			s = strconv.FormatBool(t)
		case float64:
			s = strconv.FormatFloat(t, 'f', -1, 64)
		default:
			s = fmt.Sprint(t)
		}
		*out = append(*out, [2]string{key, s})
	}
}

// fieldValues returns the strings a matcher should be run against — a match on
// any of them is a match — or nil (with unknown=true) when the field cannot be
// modelled. An empty slice is a definite "no match".
func fieldValues(req *NormalizedRequest, field any, ctx *EvalContext) ([]string, bool) {
	f := asRecord(field)
	if f == nil {
		return nil, true
	}

	if _, ok := f["UriPath"]; ok {
		return []string{req.Path}, false
	}
	if _, ok := f["QueryString"]; ok {
		return []string{req.Query}, false
	}
	if _, ok := f["Method"]; ok {
		return []string{req.Method}, false
	}
	if _, ok := f["Body"]; ok {
		return []string{req.Body}, false
	}
	if _, ok := f["UriFragment"]; ok {
		// The fragment never leaves the browser, so it is empty for every
		// request that reaches a WAF.
		ctx.note("UriFragment는 서버로 전송되지 않는 필드 — 항상 빈 값으로 평가함")
		return []string{""}, false
	}
	if _, ok := f["HeaderOrder"]; ok {
		return []string{strings.Join(req.Headers.Keys(), ",")}, false
	}
	if _, ok := f["AllQueryArguments"]; ok {
		return argValues(req), false
	}
	if v, ok := f["SingleQueryArgument"]; ok {
		name, _ := str(asRecord(v)["Name"])
		name = strings.ToLower(name)
		out := []string{}
		for _, a := range req.Args {
			if a.Name == name {
				out = append(out, a.Value)
			}
		}
		return out, false
	}
	if v, ok := f["SingleHeader"]; ok {
		name, _ := str(asRecord(v)["Name"])
		name = strings.ToLower(name)
		value, ok := req.Headers.Get(name)
		if !ok {
			ctx.note(fmt.Sprintf(`요청에 "%s" 헤더가 없어 미매칭으로 평가함 — 필요하면 요청 행의 헤더란에 추가`, name))
			return []string{}, false
		}
		return []string{value}, false
	}
	if v, ok := f["Headers"]; ok {
		h := asRecord(v)
		if h == nil {
			h = map[string]any{}
		}
		entries := patternFilter(req.Headers.Entries(), h["MatchPattern"])
		s, _ := str(h["MatchScope"])
		if s == "" {
			s = "VALUE"
		}
		return scoped(entries, s), false
	}
	if v, ok := f["Cookies"]; ok {
		c := asRecord(v)
		if c == nil {
			c = map[string]any{}
		}
		entries := patternFilter(req.Cookies.Entries(), c["MatchPattern"])
		s, _ := str(c["MatchScope"])
		if s == "" {
			s = "VALUE"
		}
		return scoped(entries, s), false
	}
	if v, ok := f["JsonBody"]; ok {
		j := asRecord(v)
		if j == nil {
			j = map[string]any{}
		}
		if req.Body == "" {
			return []string{}, false
		}
		var parsed any
		if err := json.Unmarshal([]byte(req.Body), &parsed); err != nil {
			// InvalidFallbackBehavior: EVALUATE_AS_STRING inspects the raw body,
			// MATCH / NO_MATCH short-circuit the whole statement upstream.
			fallback, _ := str(j["InvalidFallbackBehavior"])
			fallback = strings.ToUpper(fallback)
			if fallback == "" || fallback == "EVALUATE_AS_STRING" {
				return []string{req.Body}, false
			}
			ctx.note(fmt.Sprintf("바디가 JSON이 아니어서 JsonBody의 InvalidFallbackBehavior=%s 적용", fallback))
			if fallback == "MATCH" {
				return nil, true
			}
			return []string{}, false
		}
		flat := [][2]string{}
		flattenJson(parsed, "", &flat)
		s, _ := str(j["MatchScope"])
		if s == "" {
			s = "VALUE"
		}
		return scoped(patternFilter(flat, j["MatchPattern"]), s), false
	}

	key := "(empty)"
	for k := range f {
		key = k
		break
	}
	ctx.unsup("FieldToMatch:" + key)
	return nil, true
}

// preparedValues runs FieldToMatch + TextTransformations. Returns unknown when
// either is unsupported, after naming the culprit in the context.
func preparedValues(req *NormalizedRequest, body map[string]any, ctx *EvalContext, what string) ([]string, bool) {
	raw, unknown := fieldValues(req, body["FieldToMatch"], ctx)
	if unknown {
		return nil, true
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		t := ApplyTransforms(v, body["TextTransformations"])
		if !t.OK {
			ctx.unsup("TextTransformation:" + t.Type)
			ctx.note(fmt.Sprintf(`%s의 TextTransformation "%s"은 로컬에서 재현할 수 없음 — 평가 불가`, what, t.Type))
			return nil, true
		}
		out = append(out, t.Value)
	}
	return out, false
}

func decodeBase64Str(s string) string {
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(d)
	}
	if d, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(d)
	}
	return ""
}

var (
	b64ExactRe    = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	printableRe   = regexp.MustCompile(`^[\x20-\x7e]+$`)
	digitPadRe    = regexp.MustCompile(`[0-9+/=]`)
	lowerLetterRe = regexp.MustCompile(`[a-z]`)
	upperLetterRe = regexp.MustCompile(`[A-Z]`)
)

// looksBase64Encoded distinguishes an actual base64 blob from an ordinary word
// that happens to fit the alphabet — see the TS original for the reasoning.
func looksBase64Encoded(s string) bool {
	if len(s) < 8 || len(s)%4 != 0 {
		return false
	}
	if !b64ExactRe.MatchString(s) {
		return false
	}
	if strings.HasPrefix(s, "/") {
		return false
	}
	mixedCase := lowerLetterRe.MatchString(s) && upperLetterRe.MatchString(s)
	if !mixedCase && !digitPadRe.MatchString(s) {
		return false
	}
	decoded := decodeBase64Str(s)
	return len(decoded) >= 3 && printableRe.MatchString(decoded)
}

// --- matchers ----------------------------------------------------------------

var metaRe = regexp.MustCompile(`[.*+?^${}()|[\]\\]`)

func escapeRe(s string) string {
	return metaRe.ReplaceAllString(s, `\$0`)
}

func positional(haystack, needle, constraint string) Verdict3 {
	switch constraint {
	case "EXACTLY":
		return fromBool(haystack == needle)
	case "STARTS_WITH":
		return fromBool(strings.HasPrefix(haystack, needle))
	case "ENDS_WITH":
		return fromBool(strings.HasSuffix(haystack, needle))
	case "CONTAINS":
		return fromBool(strings.Contains(haystack, needle))
	case "CONTAINS_WORD":
		// WAF: the search string must appear delimited by characters outside
		// [A-Za-z0-9_].
		if needle == "" {
			return VerdictFalse
		}
		re, err := regexp.Compile(`(^|[^A-Za-z0-9_])` + escapeRe(needle) + `($|[^A-Za-z0-9_])`)
		if err != nil {
			return VerdictUnknown
		}
		return fromBool(re.MatchString(haystack))
	default:
		return VerdictUnknown
	}
}

func compare(actual float64, op string, size float64) Verdict3 {
	switch op {
	case "EQ":
		return fromBool(actual == size)
	case "NE":
		return fromBool(actual != size)
	case "LE":
		return fromBool(actual <= size)
	case "LT":
		return fromBool(actual < size)
	case "GE":
		return fromBool(actual >= size)
	case "GT":
		return fromBool(actual > size)
	default:
		return VerdictUnknown
	}
}

// anyOf: any-of over a multi-valued field, keeping the three-valued semantics.
func anyOf(values []string, test func(v string) Verdict3) Verdict3 {
	sawUnknown := false
	for _, v := range values {
		switch test(v) {
		case VerdictTrue:
			return VerdictTrue
		case VerdictUnknown:
			sawUnknown = true
		}
	}
	if sawUnknown {
		return VerdictUnknown
	}
	return VerdictFalse
}

// safeRegex: a user regex is bounded in length; the compile itself is guarded.
// Go's regexp is RE2 — the same engine family WAF itself runs.
func safeRegex(pattern string, ctx *EvalContext) *regexp.Regexp {
	if len(pattern) > RegexMax {
		ctx.note(fmt.Sprintf("RegexString이 상한 %d자를 초과 — 평가 불가", RegexMax))
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		ctx.note("RegexString을 컴파일할 수 없음: " + pattern)
		return nil
	}
	return re
}

// --- referenced sets ---------------------------------------------------------

// resolveSet: a reference can be resolved from an inline list on the statement
// itself or from the top-level "IPSets" / "RegexPatternSets" block, matched by
// full ARN, by ARN tail, or by bare name.
func resolveSet(store map[string][]string, arn string, hasArn bool, inline []string) ([]string, bool) {
	if len(inline) > 0 {
		return inline, true
	}
	if !hasArn {
		return nil, false
	}
	key := strings.ToLower(arn)
	if v, ok := store[key]; ok {
		return v, true
	}
	parts := strings.Split(key, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if v, ok := store[parts[i]]; ok {
			return v, true
		}
	}
	return nil, false
}

// inlineRegexStrings: the console exports a regex pattern set three different
// ways depending on the command used; accept all of them.
func inlineRegexStrings(stmt map[string]any) []string {
	if direct := strList(stmt["RegexStrings"]); len(direct) > 0 {
		return direct
	}
	nestedSet := asRecord(stmt["RegexPatternSet"])
	if nestedSet != nil {
		if nested := strList(nestedSet["RegularExpressionList"]); len(nested) > 0 {
			return nested
		}
	}
	objects := []any{}
	if list, ok := stmt["RegularExpressionList"].([]any); ok {
		objects = append(objects, list...)
	}
	if nestedSet != nil {
		if list, ok := nestedSet["RegularExpressionList"].([]any); ok {
			objects = append(objects, list...)
		}
	}
	out := []string{}
	for _, e := range objects {
		if s, ok := str(asRecord(e)["RegexString"]); ok {
			out = append(out, s)
		}
	}
	return out
}

// forwardedIp: Forwarded-IP handling for IPSetReferenceStatement.
func forwardedIp(req *NormalizedRequest, config any) (ips []string, fallbackMatch bool, present bool) {
	c := asRecord(config)
	if c == nil {
		return nil, false, false
	}
	header, _ := str(c["HeaderName"])
	if header == "" {
		header = "x-forwarded-for"
	}
	fb, _ := str(c["FallbackBehavior"])
	fallbackMatch = strings.ToUpper(fb) == "MATCH"
	raw, ok := req.Headers.Get(strings.ToLower(header))
	if !ok || strings.TrimSpace(raw) == "" {
		return []string{}, fallbackMatch, true
	}
	list := []string{}
	for _, s := range strings.Split(raw, ",") {
		if t := strings.TrimSpace(s); t != "" {
			list = append(list, t)
		}
	}
	pos, _ := str(c["Position"])
	switch strings.ToUpper(pos) {
	case "", "FIRST":
		list = list[:1]
	case "LAST":
		list = list[len(list)-1:]
	}
	return list, fallbackMatch, true
}

// --- evaluator ---------------------------------------------------------------

var unsupportedStatements = []string{"ASNMatchStatement"}

func EvalStatement(stmt any, req *NormalizedRequest, ctx *EvalContext) Verdict3 {
	s := asRecord(stmt)
	if s == nil {
		return VerdictUnknown
	}

	if and := asRecord(s["AndStatement"]); and != nil {
		parts, _ := and["Statements"].([]any)
		sawUnknown := false
		for _, p := range parts {
			switch EvalStatement(p, req, ctx) {
			case VerdictFalse:
				return VerdictFalse
			case VerdictUnknown:
				sawUnknown = true
			}
		}
		if sawUnknown {
			return VerdictUnknown
		}
		return fromBool(len(parts) > 0)
	}

	if or := asRecord(s["OrStatement"]); or != nil {
		parts, _ := or["Statements"].([]any)
		sawUnknown := false
		for _, p := range parts {
			switch EvalStatement(p, req, ctx) {
			case VerdictTrue:
				return VerdictTrue
			case VerdictUnknown:
				sawUnknown = true
			}
		}
		if sawUnknown {
			return VerdictUnknown
		}
		return VerdictFalse
	}

	if not := asRecord(s["NotStatement"]); not != nil {
		switch EvalStatement(not["Statement"], req, ctx) {
		case VerdictUnknown:
			return VerdictUnknown
		case VerdictTrue:
			return VerdictFalse
		default:
			return VerdictTrue
		}
	}

	if byte_ := asRecord(s["ByteMatchStatement"]); byte_ != nil {
		search, ok := str(byte_["SearchString"])
		if !ok {
			ctx.note("ByteMatchStatement의 SearchString이 문자열이 아님 — 평가 불가")
			return VerdictUnknown
		}
		// `aws wafv2 get-web-acl` emits SearchString base64-encoded, so a pasted
		// rule may carry a blob where the author expects plain text.
		if looksBase64Encoded(search) {
			ctx.note(fmt.Sprintf(`SearchString "%s"은 base64로 인코딩된 값으로 보임 (디코딩하면 "%s") — 평문으로 간주해 평가했으므로 의도한 값인지 확인 필요`, search, decodeBase64Str(search)))
		}
		values, unknown := preparedValues(req, byte_, ctx, "ByteMatchStatement")
		if unknown {
			return VerdictUnknown
		}
		// WAF applies TextTransformations to the inspected field only — the
		// SearchString you author is compared as-is.
		constraint, _ := str(byte_["PositionalConstraint"])
		return anyOf(values, func(v string) Verdict3 { return positional(v, search, constraint) })
	}

	if re := asRecord(s["RegexMatchStatement"]); re != nil {
		pattern, ok := str(re["RegexString"])
		if !ok {
			return VerdictUnknown
		}
		compiled := safeRegex(pattern, ctx)
		if compiled == nil {
			return VerdictUnknown
		}
		values, unknown := preparedValues(req, re, ctx, "RegexMatchStatement")
		if unknown {
			return VerdictUnknown
		}
		for _, v := range values {
			if compiled.MatchString(v) {
				return VerdictTrue
			}
		}
		return VerdictFalse
	}

	if regexSet := asRecord(s["RegexPatternSetReferenceStatement"]); regexSet != nil {
		arn, hasArn := str(regexSet["ARN"])
		patterns, ok := resolveSet(ctx.RegexSets, arn, hasArn, inlineRegexStrings(regexSet))
		if !ok {
			ctx.unsup("RegexPatternSetReferenceStatement")
			ctx.note(`정규식 패턴 세트를 로컬에서 알 수 없음 — 붙여넣은 JSON 최상위에 "RegexPatternSets": { "<세트이름 또는 ARN>": ["정규식", …] } 을 추가하면 평가함`)
			return VerdictUnknown
		}
		compiled := make([]*regexp.Regexp, 0, len(patterns))
		for _, p := range patterns {
			c := safeRegex(p, ctx)
			if c == nil {
				return VerdictUnknown
			}
			compiled = append(compiled, c)
		}
		values, unknown := preparedValues(req, regexSet, ctx, "RegexPatternSetReferenceStatement")
		if unknown {
			return VerdictUnknown
		}
		for _, v := range values {
			for _, c := range compiled {
				if c.MatchString(v) {
					return VerdictTrue
				}
			}
		}
		return VerdictFalse
	}

	if ipSet := asRecord(s["IPSetReferenceStatement"]); ipSet != nil {
		inline := strList(ipSet["Addresses"])
		if len(inline) == 0 {
			inline = strList(asRecord(ipSet["IPSet"])["Addresses"])
		}
		arn, hasArn := str(ipSet["ARN"])
		cidrs, ok := resolveSet(ctx.IPSets, arn, hasArn, inline)
		if !ok {
			ctx.unsup("IPSetReferenceStatement")
			ctx.note(`IP 세트 내용을 로컬에서 알 수 없음 — 붙여넣은 JSON 최상위에 "IPSets": { "<세트이름 또는 ARN>": ["10.0.0.0/8", …] } 을 추가하면 평가함`)
			return VerdictUnknown
		}
		if ips, fallbackMatch, present := forwardedIp(req, ipSet["IPSetForwardedIPConfig"]); present {
			if len(ips) == 0 {
				return fromBool(fallbackMatch)
			}
			for _, ip := range ips {
				for _, c := range cidrs {
					if IPInCidr(ip, c) {
						return VerdictTrue
					}
				}
			}
			return VerdictFalse
		}
		for _, c := range cidrs {
			if IPInCidr(req.IP, c) {
				return VerdictTrue
			}
		}
		return VerdictFalse
	}

	if size := asRecord(s["SizeConstraintStatement"]); size != nil {
		values, unknown := preparedValues(req, size, ctx, "SizeConstraintStatement")
		if unknown {
			return VerdictUnknown
		}
		op, _ := str(size["ComparisonOperator"])
		limit := num(size["Size"])
		return anyOf(values, func(v string) Verdict3 { return compare(float64(len(v)), op, limit) })
	}

	if geo := asRecord(s["GeoMatchStatement"]); geo != nil {
		codes := strList(geo["CountryCodes"])
		if len(codes) == 0 {
			ctx.note("GeoMatchStatement에 CountryCodes가 없음 — 평가 불가")
			return VerdictUnknown
		}
		country := strings.ToUpper(req.Country)
		for _, c := range codes {
			if strings.ToUpper(c) == country {
				return VerdictTrue
			}
		}
		return VerdictFalse
	}

	if sqli := asRecord(s["SqliMatchStatement"]); sqli != nil {
		values, unknown := preparedValues(req, sqli, ctx, "SqliMatchStatement")
		if unknown {
			return VerdictUnknown
		}
		ctx.approx("SqliMatchStatement")
		ctx.note("SqliMatchStatement는 AWS 내부 토크나이저 대신 로컬 시그니처로 근사 평가 — 실제 WAF 판정과 다를 수 있음")
		level := ReadSensitivity(sqli["SensitivityLevel"])
		for _, v := range values {
			if LooksLikeSqli(v, level) {
				return VerdictTrue
			}
		}
		return VerdictFalse
	}

	if xss := asRecord(s["XssMatchStatement"]); xss != nil {
		values, unknown := preparedValues(req, xss, ctx, "XssMatchStatement")
		if unknown {
			return VerdictUnknown
		}
		ctx.approx("XssMatchStatement")
		ctx.note("XssMatchStatement는 AWS 내부 토크나이저 대신 로컬 시그니처로 근사 평가 — 실제 WAF 판정과 다를 수 있음")
		for _, v := range values {
			if LooksLikeXss(v, SensitivityHigh) {
				return VerdictTrue
			}
		}
		return VerdictFalse
	}

	if label := asRecord(s["LabelMatchStatement"]); label != nil {
		key, ok := str(label["Key"])
		if !ok {
			return VerdictUnknown
		}
		scope, _ := str(label["Scope"])
		scope = strings.ToUpper(scope)
		if scope == "" {
			scope = "LABEL"
		}
		all := map[string]struct{}{}
		for l := range req.Labels {
			all[l] = struct{}{}
		}
		for l := range ctx.Emitted {
			all[l] = struct{}{}
		}
		if len(all) == 0 {
			ctx.note(fmt.Sprintf(`라벨 "%s"를 붙이는 선행 규칙이 없음 — 미매칭으로 평가함(요청 행의 라벨란에 직접 넣으면 매칭 검증 가능)`, key))
			return VerdictFalse
		}
		needle := strings.ToLower(key)
		for l := range all {
			have := strings.ToLower(l)
			if scope == "NAMESPACE" {
				if strings.HasPrefix(have, needle) {
					return VerdictTrue
				}
			} else if have == needle {
				return VerdictTrue
			}
		}
		return VerdictFalse
	}

	if rate := asRecord(s["RateBasedStatement"]); rate != nil {
		ctx.approx("RateBasedStatement")
		limit := num(rate["Limit"])
		window := num(rate["EvaluationWindowSec"])
		if window == 0 {
			window = 300
		}
		limitStr := "?"
		if limit > 0 {
			limitStr = strconv.FormatFloat(limit, 'f', -1, 64)
		}
		ctx.note(fmt.Sprintf(`RateBasedStatement는 요청량(%s건/%.0f초)이 조건 — 합성 요청 한 건으로는 재현할 수 없어 스코프다운 조건만 평가함. 매칭으로 표시된 행은 "해당 키가 임계치를 넘겼을 때 걸린다"는 뜻.`, limitStr, window))
		if _, ok := rate["ScopeDownStatement"]; !ok {
			return VerdictTrue
		}
		return EvalStatement(rate["ScopeDownStatement"], req, ctx)
	}

	if managed := asRecord(s["ManagedRuleGroupStatement"]); managed != nil {
		vendor, _ := str(managed["VendorName"])
		name, _ := str(managed["Name"])
		if _, ok := managed["ScopeDownStatement"]; ok {
			scope := EvalStatement(managed["ScopeDownStatement"], req, ctx)
			if scope != VerdictTrue {
				return scope
			}
		}
		excluded := map[string]struct{}{}
		if list, ok := managed["ExcludedRules"].([]any); ok {
			for _, e := range list {
				if n, ok := str(asRecord(e)["Name"]); ok {
					excluded[n] = struct{}{}
				}
			}
		}
		// A rule overridden to Count still matches; only Allow removes it from
		// the group's blocking behaviour.
		if list, ok := managed["RuleActionOverrides"].([]any); ok {
			for _, e := range list {
				o := asRecord(e)
				if o == nil {
					continue
				}
				if action := asRecord(o["ActionToUse"]); action != nil {
					if _, allow := action["Allow"]; allow {
						if n, ok := str(o["Name"]); ok {
							excluded[n] = struct{}{}
						}
					}
				}
			}
		}
		verdict := EvaluateManagedGroup(vendor, name, req, excluded)
		if verdict.Matched == VerdictUnknown {
			ctx.unsup(fmt.Sprintf("ManagedRuleGroupStatement(%s)", name))
			if verdict.Note != "" {
				ctx.note(verdict.Note)
			}
			return VerdictUnknown
		}
		ctx.approx(fmt.Sprintf("ManagedRuleGroupStatement(%s)", name))
		ctx.note(fmt.Sprintf(`관리형 규칙 그룹 "%s"은 공개된 규칙 의도를 로컬 근사로 평가 — 실제 매칭 여부는 COUNT로 확인 필요`, name))
		if verdict.Matched == VerdictTrue {
			for _, l := range verdict.Labels {
				ctx.Emitted[l] = struct{}{}
			}
			ctx.note(fmt.Sprintf(`"%s" 근사 매칭: %s`, name, strings.Join(verdict.Rules, ", ")))
		}
		return verdict.Matched
	}

	if groupRef := asRecord(s["RuleGroupReferenceStatement"]); groupRef != nil {
		rulesList, ok := groupRef["Rules"].([]any)
		if !ok {
			ctx.unsup("RuleGroupReferenceStatement")
			ctx.note(`사용자 규칙 그룹의 내용을 로컬에서 알 수 없음 — 문장 안에 "Rules": [ … ] 로 규칙 배열을 넣으면 평가함`)
			return VerdictUnknown
		}
		if _, ok := groupRef["ScopeDownStatement"]; ok {
			scope := EvalStatement(groupRef["ScopeDownStatement"], req, ctx)
			if scope != VerdictTrue {
				return scope
			}
		}
		ctx.approx("RuleGroupReferenceStatement")
		sawUnknown := false
		for _, r := range rulesList {
			switch EvalStatement(asRecord(r)["Statement"], req, ctx) {
			case VerdictTrue:
				return VerdictTrue
			case VerdictUnknown:
				sawUnknown = true
			}
		}
		if sawUnknown {
			return VerdictUnknown
		}
		return VerdictFalse
	}

	for _, name := range unsupportedStatements {
		if _, ok := s[name]; ok {
			ctx.unsup(name)
			ctx.note(name + "은 AWS 측 데이터가 있어야 판정 가능 — 로컬 평가 불가")
			return VerdictUnknown
		}
	}

	key := "(empty)"
	for k := range s {
		key = k
		break
	}
	ctx.unsup(key)
	return VerdictUnknown
}
