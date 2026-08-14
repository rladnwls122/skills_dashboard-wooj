// Package analysis holds the pure log/traffic analysis ported from
// src/lib/server: masking, log-line parsing, error fingerprinting, anomaly
// detection, correlation, the gateway contract, and the incident report.
package analysis

import "regexp"

// Sensitive-data masking (spec §20). Applied to every log line and generated
// incident context before it leaves the server. Ported from mask.ts.

type maskRule struct {
	re      *regexp.Regexp
	replace string
}

var maskRules = []maskRule{
	{regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)\S[^\r\n]*`), "$1[REDACTED]"},
	{regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*`), "$1[REDACTED]"},
	{regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|secret[-_]?key|x-api-key|session)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&,;'"]+)`), "$1[REDACTED]"},
	{regexp.MustCompile(`(?i)(cookie\s*[:=]\s*)[^\r\n]*`), "$1[REDACTED]"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[REDACTED_AWS_KEY]"},
	{regexp.MustCompile(`ASIA[0-9A-Z]{16}`), "[REDACTED_AWS_KEY]"},
	// JWT (three base64url segments)
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}`), "[REDACTED_JWT]"},
	// Kubernetes service-account token file mentions
	{regexp.MustCompile(`/var/run/secrets/kubernetes\.io/serviceaccount/token\S*`), "[REDACTED]"},
}

var privateIPRe = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)

func MaskLine(line string) string {
	out := line
	for _, r := range maskRules {
		out = r.re.ReplaceAllString(out, r.replace)
	}
	return out
}

func MaskLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, MaskLine(l))
	}
	return out
}

func MaskText(text string) string { return MaskLine(text) }

// MaskPrivateIPs is the maskPrivateIp=true variant, kept separate because only
// one caller wants it.
func MaskPrivateIPs(text string) string {
	return privateIPRe.ReplaceAllString(MaskLine(text), "[PRIVATE_IP]")
}
