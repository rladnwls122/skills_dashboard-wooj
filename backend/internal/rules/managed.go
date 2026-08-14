package rules

// Local approximation of the AWS managed rule groups, ported from
// src/lib/server/rulemanaged.ts. What is reproduced is the documented intent
// of their best-known rules; a group whose decision genuinely depends on
// AWS-side data returns UNKNOWN rather than a guess.

import (
	"regexp"
	"strings"
)

type ManagedVerdict struct {
	Matched Verdict3
	// names of the approximated sub-rules that fired
	Rules []string
	// labels the group would add to the request
	Labels []string
	// why the group could not be decided, when Matched == VerdictUnknown
	Note string
}

type subRule struct {
	name string
	test func(r *NormalizedRequest) bool
}

func argValues(r *NormalizedRequest) []string {
	out := make([]string, 0, len(r.Args))
	for _, a := range r.Args {
		out = append(out, a.Value)
	}
	return out
}

func cookieValues(r *NormalizedRequest) []string { return r.Cookies.Values() }

func uaOf(r *NormalizedRequest) string {
	v, _ := r.Headers.Get("user-agent")
	return v
}

// The surfaces AWS's managed groups inspect for injection payloads.
func injectionSurfaces(r *NormalizedRequest) []string {
	all := append([]string{r.Path, r.Query}, argValues(r)...)
	all = append(all, r.Body)
	all = append(all, cookieValues(r)...)
	all = append(all, uaOf(r))
	out := all[:0]
	for _, s := range all {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func anyMatch(values []string, re *regexp.Regexp) bool {
	for _, v := range values {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

var (
	traversalRe       = regexp.MustCompile(`(?i)(?:^|[/\\])\.\.(?:[/\\]|$)|%2e%2e[/\\%]`)
	metadataRe        = regexp.MustCompile(`(?i)169\.254\.169\.254|/latest/meta-data|/latest/api/token`)
	rfiRe             = regexp.MustCompile(`(?i)(?:https?|ftp|php|file|gopher|dict)://`)
	restrictedExtRe   = regexp.MustCompile(`(?i)\.(?:log|ini|bak|backup|old|swp|sql|conf|config|dll|exe)(?:$|[?#])`)
	lfiFileRe         = regexp.MustCompile(`(?i)/(?:etc/(?:passwd|shadow|hosts|group)|proc/self/(?:environ|cmdline)|windows/win\.ini|boot\.ini)\b`)
	shellRe           = regexp.MustCompile("(?i)(?:;|\\||&&|\\$\\(|`)\\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|netcat|bash|sh|python|perl|chmod|rm)\\b")
	shellshockRe      = regexp.MustCompile(`\(\s*\)\s*\{`)
	windowsRe         = regexp.MustCompile(`(?i)(?:powershell(?:\.exe)?\b|cmd\.exe\b|%SystemRoot%|\bnet\s+(?:user|localgroup)\b|\bwmic\b)`)
	phpRe             = regexp.MustCompile(`(?i)(?:<\?php\b|php://|\$_(?:GET|POST|REQUEST|SERVER|COOKIE|FILES)\b|\ballow_url_include\b|\bbase64_decode\s*\()`)
	wordpressRe       = regexp.MustCompile(`(?i)/(?:wp-admin|wp-login\.php|wp-content|wp-includes|wp-config\.php|xmlrpc\.php)`)
	adminPathRe       = regexp.MustCompile(`(?i)^/(?:admin|administrator|phpmyadmin|pma|manager/html|jmx-console|cgi-bin|console|adminer\.php|wp-admin)\b`)
	exploitablePathRe = regexp.MustCompile(`(?i)/(?:web-inf|meta-inf|\.git\b|\.svn\b|\.env\b|\.aws/credentials|server-status|actuator/env|struts|jenkins/script)`)
	log4jRe           = regexp.MustCompile(`(?i)\$\{(?:jndi:|[^}]{0,20}(?:lower|upper|env|sys|date|ctx):)`)
	javaSerialRe      = regexp.MustCompile(`(?:rO0AB|` + "\xc2\xac\xc3\xad\x00\x05" + `|aced0005)`)
	httpLibraryUaRe   = regexp.MustCompile(`(?i)\b(?:curl|wget|python-requests|python-urllib|go-http-client|java|okhttp|libwww-perl|axios|node-fetch|httpclient|guzzle|restsharp|postmanruntime|scrapy|aiohttp)\b`)
	browserUaRe       = regexp.MustCompile(`(?i)\b(?:applewebkit|gecko|trident|khtml|presto|chrome|firefox|safari|edg|opr)\b`)
	localhostHostRe   = regexp.MustCompile(`(?i)^(?:localhost|127\.0\.0\.1|\[?::1\]?)(?::\d+)?$`)
)

func byteLen(s string) int { return len(s) }

var commonRuleSet = []subRule{
	{"NoUserAgent_HEADER", func(r *NormalizedRequest) bool { return uaOf(r) == "" }},
	{"UserAgent_BadBots_HEADER", func(r *NormalizedRequest) bool {
		c := ClassifyUa(uaOf(r))
		return c != nil && c.Category == CategoryScanner
	}},
	{"SizeRestrictions_URIPATH", func(r *NormalizedRequest) bool { return byteLen(r.Path) > 1024 }},
	{"SizeRestrictions_QUERYSTRING", func(r *NormalizedRequest) bool { return byteLen(r.Query) > 2048 }},
	{"SizeRestrictions_BODY", func(r *NormalizedRequest) bool { return byteLen(r.Body) > 8192 }},
	{"SizeRestrictions_Cookie_HEADER", func(r *NormalizedRequest) bool {
		v, _ := r.Headers.Get("cookie")
		return byteLen(v) > 10240
	}},
	{"EC2MetaDataSSRF_BODY", func(r *NormalizedRequest) bool { return metadataRe.MatchString(r.Body) }},
	{"EC2MetaDataSSRF_URIPATH_QUERYARGUMENTS", func(r *NormalizedRequest) bool {
		return metadataRe.MatchString(r.Path) || anyMatch(argValues(r), metadataRe)
	}},
	{"GenericLFI_URIPATH_QUERYARGUMENTS_BODY", func(r *NormalizedRequest) bool {
		return traversalRe.MatchString(r.Path) || anyMatch(argValues(r), traversalRe) || traversalRe.MatchString(r.Body)
	}},
	{"GenericRFI_QUERYARGUMENTS_BODY", func(r *NormalizedRequest) bool {
		return anyMatch(argValues(r), rfiRe) || rfiRe.MatchString(r.Body)
	}},
	{"RestrictedExtensions_URIPATH_QUERYARGUMENTS", func(r *NormalizedRequest) bool {
		return restrictedExtRe.MatchString(r.Path) || anyMatch(argValues(r), restrictedExtRe)
	}},
	{"CrossSiteScripting_BODY_QUERYARGUMENTS_URIPATH_COOKIE", func(r *NormalizedRequest) bool {
		for _, v := range injectionSurfaces(r) {
			if LooksLikeXss(v, SensitivityHigh) {
				return true
			}
		}
		return false
	}},
}

var knownBadInputs = []subRule{
	{"Log4JRCE_HEADER_QUERYSTRING_BODY_URIPATH", func(r *NormalizedRequest) bool {
		return anyMatch(injectionSurfaces(r), log4jRe)
	}},
	{"JavaDeserializationRCE_HEADER_QUERYSTRING_BODY_URIPATH", func(r *NormalizedRequest) bool {
		return anyMatch(injectionSurfaces(r), javaSerialRe)
	}},
	{"Host_localhost_HEADER", func(r *NormalizedRequest) bool {
		v, _ := r.Headers.Get("host")
		return localhostHostRe.MatchString(v)
	}},
	{"PROPFIND_METHOD", func(r *NormalizedRequest) bool { return r.Method == "PROPFIND" }},
	{"ExploitablePaths_URIPATH", func(r *NormalizedRequest) bool { return exploitablePathRe.MatchString(r.Path) }},
}

var sqliRuleSet = []subRule{
	{"SQLi_QUERYARGUMENTS", func(r *NormalizedRequest) bool {
		for _, v := range argValues(r) {
			if LooksLikeSqli(v, SensitivityHigh) {
				return true
			}
		}
		return false
	}},
	{"SQLi_BODY", func(r *NormalizedRequest) bool { return LooksLikeSqli(r.Body, SensitivityHigh) }},
	{"SQLi_COOKIE", func(r *NormalizedRequest) bool {
		for _, v := range cookieValues(r) {
			if LooksLikeSqli(v, SensitivityHigh) {
				return true
			}
		}
		return false
	}},
	{"SQLi_URIPATH", func(r *NormalizedRequest) bool { return LooksLikeSqli(r.Path, SensitivityHigh) }},
}

var linuxRuleSet = []subRule{
	{"LFI_URIPATH_QUERYARGUMENTS_BODY", func(r *NormalizedRequest) bool {
		vals := append([]string{r.Path}, argValues(r)...)
		vals = append(vals, r.Body)
		return anyMatch(vals, lfiFileRe)
	}},
	{"ShellShock_HEADER", func(r *NormalizedRequest) bool {
		return anyMatch(r.Headers.Values(), shellshockRe)
	}},
}

var unixRuleSet = append(append([]subRule{}, linuxRuleSet...), subRule{
	"UNIXShellCommandsVariables", func(r *NormalizedRequest) bool {
		return anyMatch(injectionSurfaces(r), shellRe)
	},
})

var windowsRuleSet = []subRule{
	{"WindowsShellCommands", func(r *NormalizedRequest) bool { return anyMatch(injectionSurfaces(r), windowsRe) }},
}

var phpRuleSet = []subRule{
	{"PHPHighRiskMethodsVariables", func(r *NormalizedRequest) bool { return anyMatch(injectionSurfaces(r), phpRe) }},
}

var wordpressRuleSet = []subRule{
	{"WordPressExploitableCommands", func(r *NormalizedRequest) bool { return wordpressRe.MatchString(r.Path) }},
}

var adminProtection = []subRule{
	{"AdminProtection_URIPATH", func(r *NormalizedRequest) bool { return adminPathRe.MatchString(r.Path) }},
}

var botControl = []subRule{
	{"CategoryHttpLibrary", func(r *NormalizedRequest) bool { return httpLibraryUaRe.MatchString(uaOf(r)) }},
	{"SignalNonBrowserUserAgent", func(r *NormalizedRequest) bool {
		ua := uaOf(r)
		return ua != "" && !browserUaRe.MatchString(ua) && !httpLibraryUaRe.MatchString(ua)
	}},
	{"CategoryScrapingFramework", func(r *NormalizedRequest) bool {
		c := ClassifyUa(uaOf(r))
		return c != nil && (c.Category == CategoryScanner || c.Category == CategoryRecon)
	}},
}

type groupSpec struct {
	slug  string
	rules []subRule
}

var managedGroups = map[string]groupSpec{
	"awsmanagedrulescommonruleset":          {"core-rule-set", commonRuleSet},
	"awsmanagedrulesknownbadinputsruleset":  {"known-bad-inputs", knownBadInputs},
	"awsmanagedrulessqliruleset":            {"sql-database", sqliRuleSet},
	"awsmanagedruleslinuxruleset":           {"linux-os", linuxRuleSet},
	"awsmanagedrulesunixruleset":            {"posix-os", unixRuleSet},
	"awsmanagedruleswindowsruleset":         {"windows-os", windowsRuleSet},
	"awsmanagedrulesphpruleset":             {"php-app", phpRuleSet},
	"awsmanagedruleswordpressruleset":       {"wordpress-app", wordpressRuleSet},
	"awsmanagedrulesadminprotectionruleset": {"admin-protection", adminProtection},
	"awsmanagedrulesbotcontrolruleset":      {"bot-control", botControl},
}

// Groups whose decision lives in AWS-side data. Private space is still a
// definite no-match; anything routable is honestly UNKNOWN.
var reputationGroups = map[string]string{
	"awsmanagedrulesamazonipreputationlist": "IP 평판 목록은 AWS 내부 데이터 — 공인 IP는 로컬에서 판정할 수 없음(사설 IP만 미매칭으로 확정)",
	"awsmanagedrulesanonymousiplist":        "익명 프록시/VPN 목록은 AWS 내부 데이터 — 공인 IP는 로컬에서 판정할 수 없음(사설 IP만 미매칭으로 확정)",
}

// Groups that need request state the sandbox does not model at all.
var statefulGroups = map[string]string{
	"awsmanagedrulesatpruleset":  "ATP 규칙 그룹은 로그인 시도 이력·자격증명 유출 DB에 의존 — 단일 합성 요청으로 판정 불가",
	"awsmanagedrulesacfpruleset": "ACFP 규칙 그룹은 계정 생성 흐름 상태에 의존 — 단일 합성 요청으로 판정 불가",
}

func EvaluateManagedGroup(vendorName, name string, req *NormalizedRequest, excluded map[string]struct{}) ManagedVerdict {
	if strings.ToLower(vendorName) != "aws" {
		return ManagedVerdict{
			Matched: VerdictUnknown,
			Note:    vendorName + " 마켓플레이스 규칙 그룹은 내용이 공개돼 있지 않아 로컬 판정 불가",
		}
	}

	key := strings.ToLower(name)

	if note, ok := statefulGroups[key]; ok {
		return ManagedVerdict{Matched: VerdictUnknown, Note: note}
	}
	if note, ok := reputationGroups[key]; ok {
		if IsPrivateIP(req.IP) {
			return ManagedVerdict{Matched: VerdictFalse}
		}
		return ManagedVerdict{Matched: VerdictUnknown, Note: note}
	}

	group, ok := managedGroups[key]
	if !ok {
		return ManagedVerdict{
			Matched: VerdictUnknown,
			Note:    `관리형 규칙 그룹 "` + name + `"의 근사 정의가 없음 — 로컬 판정 불가`,
		}
	}

	verdict := ManagedVerdict{Matched: VerdictFalse}
	for _, r := range group.rules {
		if _, skip := excluded[r.name]; skip {
			continue
		}
		if r.test(req) {
			verdict.Matched = VerdictTrue
			verdict.Rules = append(verdict.Rules, r.name)
			verdict.Labels = append(verdict.Labels, "awswaf:managed:aws:"+group.slug+":"+r.name)
		}
	}
	return verdict
}
