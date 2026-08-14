package rules

// Local stand-ins for AWS's SqliMatchStatement / XssMatchStatement, ported from
// src/lib/server/ruleinjection.ts. AWS runs a libinjection-style tokenizer we
// cannot reproduce byte-for-byte, so these are signature detectors over
// well-known payload shapes. Every statement that uses them is reported as an
// approximation ("근사").

import "regexp"

type Sensitivity string

const (
	SensitivityLow  Sensitivity = "LOW"
	SensitivityHigh Sensitivity = "HIGH"
)

func mustAll(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

// Shapes that are attack payloads in any context. LOW sensitivity uses these
// alone, which is what AWS's LOW level is for: fewer false positives.
var sqliStrong = mustAll(
	`(?is)\bunion\b.{0,40}\bselect\b`,
	`(?is)\bselect\b.{0,80}\bfrom\b`,
	`(?i)\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|truncate\s+table|alter\s+table)\b`,
	`(?i)(?:'|")\s*(?:or|and)\s+(?:'|")?[\w]+(?:'|")?\s*=\s*(?:'|")?[\w]+`,
	`(?i)\b(?:or|and)\s+\d+\s*=\s*\d+\b`,
	`(?i);\s*(?:select|insert|update|delete|drop|shutdown|exec)\b`,
	`(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(`,
	`(?i)\bwaitfor\s+delay\b`,
	`(?i)\b(?:load_file|into\s+outfile|into\s+dumpfile)\b`,
	`(?i)\b(?:information_schema|sysobjects|syscolumns|pg_catalog)\b`,
	`(?i)\b(?:extractvalue|updatexml)\s*\(`,
	`(?i)\bxp_cmdshell\b`,
	`/\*!\d{5}`,
)

// Weaker signals: real SQLi tells, but also things a legitimate parameter can
// contain. Only HIGH sensitivity looks at them, matching AWS's own trade-off.
var sqliLoose = mustAll(
	`'\s*(?:--|#)`,
	`(?:^|[\s&=])(?:--|#)\s*$`,
	`(?i)\b(?:cast|convert)\s*\(\s*\w+\s+as\b`,
	`(?i)\bhaving\b\s+\d+\s*=\s*\d+`,
	`(?is)\bgroup\s+by\b.{0,40}\bhaving\b`,
	`(?i)\border\s+by\s+\d+\s*(?:--|#|;|$)`,
	`(?is)\bunion\b.{0,20}\ball\b`,
	`'\s*\|\|\s*'`,
	`(?i)\bconcat\s*\(\s*(?:0x|char\s*\()`,
)

func LooksLikeSqli(value string, sensitivity Sensitivity) bool {
	if value == "" {
		return false
	}
	for _, re := range sqliStrong {
		if re.MatchString(value) {
			return true
		}
	}
	if sensitivity != SensitivityHigh {
		return false
	}
	for _, re := range sqliLoose {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

var xssStrong = mustAll(
	`(?i)<\s*script\b`,
	`(?i)<\s*/\s*script\s*>`,
	`(?i)\bjavascript\s*:`,
	`(?i)\bvbscript\s*:`,
	`(?i)\bon(?:error|load|click|mouseover|focus|blur|submit|toggle|animationstart|animationend|pointerover|beforeprint)\s*=`,
	`(?i)<\s*(?:iframe|object|embed|svg|img|body|video|audio|marquee|details|form|input|link|meta|base|style|applet)\b[^>]*\bon[a-z]+\s*=`,
	`(?i)<\s*(?:iframe|svg|img|embed|object|script)\b[^>]*\bsrc\s*=\s*["']?\s*(?:javascript|data)\s*:`,
	`(?i)\bdocument\s*\.\s*(?:cookie|location|write|domain)\b`,
	`(?i)\bwindow\s*\.\s*(?:location|name)\s*=`,
	"(?i)\\beval\\s*\\(\\s*[\"'`]",
	"(?i)\\b(?:setTimeout|setInterval|Function)\\s*\\(\\s*[\"'`]",
	`(?i)<\s*svg\b[^>]*>\s*<\s*(?:script|animate|set)\b`,
	"(?i)\\balert\\s*\\(\\s*(?:\\d|[\"'`])",
)

var xssLoose = mustAll(
	`(?i)<\s*(?:iframe|object|embed|svg|applet|meta|base)\b`,
	`(?i)&#x?0*(?:3c|60);`,
	`(?i)%3c\s*script`,
	`(?i)\bexpression\s*\(`,
	`(?i)\bsrcdoc\s*=`,
	`(?i)\bformaction\s*=`,
	`(?i)<\s*\w+[^>]*\bstyle\s*=\s*["'][^"']*\burl\s*\(`,
)

func LooksLikeXss(value string, sensitivity Sensitivity) bool {
	if value == "" {
		return false
	}
	for _, re := range xssStrong {
		if re.MatchString(value) {
			return true
		}
	}
	if sensitivity != SensitivityHigh {
		return false
	}
	for _, re := range xssLoose {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func ReadSensitivity(v any) Sensitivity {
	if s, ok := v.(string); ok && (s == "HIGH" || s == "high" || s == "High") {
		return SensitivityHigh
	}
	return SensitivityLow
}
