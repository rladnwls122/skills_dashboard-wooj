package rules

// Threat classification for a synthetic or sampled request's User-Agent and
// query, ported from src/lib/server/threatsig.ts. Pure and AWS-free so it is
// shared by anomaly detection, the WAF recommender, and the rule sandbox.
// UNKNOWN is not a signature — it is the absence of one.

import (
	"regexp"
	"strings"
)

type ThreatCategory string

const (
	CategoryScanner    ThreatCategory = "SCANNER"
	CategoryRecon      ThreatCategory = "RECON"
	CategorySpoofed    ThreatCategory = "SPOOFED"
	CategoryAutomation ThreatCategory = "AUTOMATION"
	CategoryUnknown    ThreatCategory = "UNKNOWN"
)

type ThreatHit struct {
	Category ThreatCategory
	Label    string
}

// Go's default HTTP client is the competition's load generator and the expected
// AI-agent traffic (REQ-01): always allowed, unless an explicit tool signature
// below fires first.
var goAllowRe = regexp.MustCompile(`(?i)go-http-client/|go-language`)

// Named offensive tools. A hit is an unambiguous attack signature.
// "attacker-bot" is the User-Agent the product binary itself treats as an
// attack (it answers 500 "Consumed resources by malicious attacks") — the
// task's abnormal-request probe, which the WAF has to turn into a 403.
var scannerTools = []string{
	"sqlmap", "nikto", "acunetix", "dirbuster", "dirb", "w3af", "netsparker",
	"zaproxy", "gobuster", "wpscan", "arachni", "nessus", "openvas", "commix",
	"attacker-bot",
}
var reconTools = []string{"nmap", "masscan", "zgrab", "censysinspect", "zmap"}

// HTTP clients and headless browsers. None of these is an attack by itself —
// kept separate from SCANNER so the rule can say "automation, not a named weapon".
var automationTools = []string{
	"curl", "wget", "python-requests", "python-urllib", "urllib", "libwww-perl",
	"okhttp", "apache-httpclient", "java", "axios", "node-fetch", "got", "httpie",
	"postmanruntime", "insomnia", "scrapy", "phantomjs", "headlesschrome",
	"puppeteer", "playwright", "selenium", "httpclient", "restsharp", "guzzle",
	"winhttp", "powershell", "lwp-request", "aiohttp", "httpx", "reqwest",
}

func toolRe(tools []string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(^|[^a-z])(` + strings.Join(tools, "|") + `)([^a-z]|$)`)
}

var (
	scannerRe    = toolRe(scannerTools)
	reconRe      = toolRe(reconTools)
	automationRe = toolRe(automationTools)
)

// Clients this environment is expected to see. Everything else observed is
// suspicious by default — see ClassifyUa.
var knownGoodUa = []*regexp.Regexp{
	// A real browser always names a rendering engine.
	regexp.MustCompile(`(?i)(applewebkit|gecko|trident|khtml|presto)\b`),
	// The competition's load generator and expected AI-agent traffic (REQ-01).
	regexp.MustCompile(`(?i)go-http-client/|go-language`),
	// AWS infrastructure probes.
	regexp.MustCompile(`(?i)^elb-healthchecker/`),
	regexp.MustCompile(`(?i)^amazon-route53-health-check-service`),
	regexp.MustCompile(`(?i)^amazon cloudfront`),
	regexp.MustCompile(`(?i)^kube-probe/`),
	// This dashboard's own traffic check — deliberately named so it can be told
	// apart, and it must not end up in a rule that blocks the next check.
	regexp.MustCompile(`(?i)^skills-dashboard/traffic-check`),
}

func IsKnownGoodUa(ua string) bool {
	for _, re := range knownGoodUa {
		if re.MatchString(ua) {
			return true
		}
	}
	return false
}

// Injection payloads smuggled into the UA field (Log4Shell, SQLi, OS command).
var uaInjectionRe = regexp.MustCompile(`(?i)(\$\{jndi:|\bunion\s+select\b|['"]\s*or\s+1\s*=\s*1|;\s*(cat|wget|curl|nc|bash|sh)\b)`)

// A standalone base64 blob long enough to hide a payload.
var b64BlobRe = regexp.MustCompile(`(^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})($|[^A-Za-z0-9+/=])`)

func hasBase64Blob(s string) bool {
	m := b64BlobRe.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	blob := m[2]
	return len(blob) >= 24 && len(blob)%4 == 0
}

var (
	mozillaStartRe = regexp.MustCompile(`(?i)^mozilla/\d`)
	engineRe       = regexp.MustCompile(`(?i)(applewebkit|gecko|trident|khtml|presto|chrome|firefox|safari|edg|opr)\b`)
	longLettersRe  = regexp.MustCompile(`(?i)[a-z]{20,}`)
)

// Starts like a browser but names no rendering engine and carries a long
// unbroken letter run no real token has — reads as filler.
func isMalformedMozilla(ua string) bool {
	return mozillaStartRe.MatchString(ua) && !engineRe.MatchString(ua) && longLettersRe.MatchString(ua)
}

// What a classification looks like as a WAF regex, for the SPOOFED categories
// whose label is a category name rather than text found in the UA.
// RE2 syntax, lowercase only: the rules that use these apply LOWERCASE (and
// COMPRESS_WHITE_SPACE) before matching.
var spoofedPatterns = map[string][]string{
	"injection-in-ua": {
		`\$\{jndi:`,
		`union\s+select`,
		`['"]\s*or\s+1\s*=\s*1`,
		`;\s*(cat|wget|curl|nc|bash|sh)\b`,
	},
	// Base64 folds to lowercase under the transform, so the class is a-z0-9+/.
	"base64-ua": {`(^|[^a-z0-9+/])[a-z0-9+/]{24,}={0,2}([^a-z0-9+/=]|$)`},
	// RE2 has no lookahead, so this takes the other half of the signal — the
	// long unbroken letter run right after the mozilla token.
	"malformed-mozilla": {`^mozilla/[0-9.]+\s*\(?[a-z]{20,}`},
}

// SpoofedUaPatterns returns the regexes that express a classification; [] when
// the label is unknown.
func SpoofedUaPatterns(label string) []string {
	return spoofedPatterns[label]
}

var uaTokenSplitRe = regexp.MustCompile(`[\s/(;,]`)

// UaToken is the leading product token of a UA — "python-requests" out of
// "python-requests/2.31.0". The version that follows changes between releases,
// so a rule written against the whole string stops firing on upgrade.
func UaToken(ua string) string {
	parts := uaTokenSplitRe.Split(strings.TrimSpace(ua), 2)
	return strings.ToLower(parts[0])
}

func ClassifyUa(ua string) *ThreatHit {
	if m := scannerRe.FindStringSubmatch(ua); m != nil {
		return &ThreatHit{CategoryScanner, strings.ToLower(m[2])}
	}
	if m := reconRe.FindStringSubmatch(ua); m != nil {
		return &ThreatHit{CategoryRecon, strings.ToLower(m[2])}
	}
	// Payload-in-the-UA outranks the allow list: a request carrying ${jndi: is
	// an attack no matter what it claims to be.
	if uaInjectionRe.MatchString(ua) {
		return &ThreatHit{CategorySpoofed, "injection-in-ua"}
	}
	// The Go bypass applies only after explicit attack signatures are ruled out.
	if goAllowRe.MatchString(ua) {
		return nil
	}
	if isMalformedMozilla(ua) {
		return &ThreatHit{CategorySpoofed, "malformed-mozilla"}
	}
	if hasBase64Blob(ua) {
		return &ThreatHit{CategorySpoofed, "base64-ua"}
	}
	if m := automationRe.FindStringSubmatch(ua); m != nil {
		return &ThreatHit{CategoryAutomation, strings.ToLower(m[2])}
	}
	// Nothing recognised it and it is not one of the clients this environment
	// expects, so it is reported rather than passed. An empty UA lands here too.
	if IsKnownGoodUa(ua) {
		return nil
	}
	token := UaToken(ua)
	if token == "" {
		token = "(빈 User-Agent)"
	}
	return &ThreatHit{CategoryUnknown, token}
}

func QueryHasBase64Blob(query string) bool {
	return hasBase64Blob(query)
}
