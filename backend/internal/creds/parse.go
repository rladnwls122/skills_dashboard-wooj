// Package creds owns the AWS credentials this process signs with: reading them
// out of whatever the operator has in hand, holding the injected set, and
// handing the SDK a provider for it.
//
// The parsing half is ported from src/lib/awscreds.ts and is deliberately pure
// — no SDK, no filesystem — so the browser and the server pick fields out of a
// pasted blob the same way.
//
// Under time pressure the keys arrive in whatever shape the source produced: a
// CloudShell `export` block, the console's "명령줄 액세스" panel, an .env
// fragment, a `~/.aws/credentials` section, the JSON that
// `aws configure export-credentials` prints. Asking someone to retype three
// values into three boxes is how a session token ends up truncated, so the
// screen takes the blob and this picks the fields out of it.
package creds

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Parsed is the four fields worth recovering from a blob. Expiration is
// ISO-8601 as printed by `aws configure export-credentials`, when present.
type Parsed struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

// An access key id is the one field with a recognisable shape: AKIA for a long
// lived user key, ASIA for a temporary (session) one.
var keyIDShape = regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{12,})\b`)

// `aws_secret_access_key`, `SecretAccessKey`, `secret-access-key` — the same
// field in four notations. Anchored on the distinguishing word of each so that
// `aws_secret_access_key` cannot also satisfy the access-key-id pattern (it
// carries no "id").
var fieldPatterns = []struct {
	set func(*Parsed, string)
	get func(*Parsed) string
	re  *regexp.Regexp
}{
	{func(p *Parsed, v string) { p.AccessKeyID = v }, func(p *Parsed) string { return p.AccessKeyID },
		regexp.MustCompile(`(?i)(?:aws[_-]?)?access[_-]?key[_-]?id`)},
	{func(p *Parsed, v string) { p.SecretAccessKey = v }, func(p *Parsed) string { return p.SecretAccessKey },
		regexp.MustCompile(`(?i)(?:aws[_-]?)?secret[_-]?access[_-]?key`)},
	{func(p *Parsed, v string) { p.SessionToken = v }, func(p *Parsed) string { return p.SessionToken },
		regexp.MustCompile(`(?i)(?:aws[_-]?)?(?:session|security)[_-]?token`)},
	{func(p *Parsed, v string) { p.Expiration = v }, func(p *Parsed) string { return p.Expiration },
		regexp.MustCompile(`(?i)^expiration$`)},
}

var (
	prefixRe     = regexp.MustCompile(`(?i)^(?:export|set|setx)\s+`)
	envPrefixRe  = regexp.MustCompile(`(?i)^\$env:`)
	assignmentRe = regexp.MustCompile(`^["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*[:=]\s*(.*)$`)
	trailingRe   = regexp.MustCompile(`[,;]\s*$`)
	quotedRe     = regexp.MustCompile(`^(["'])([\s\S]*)["']$`)
	sectionRe    = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
	profileWord  = regexp.MustCompile(`(?i)^profile\s+`)
	asiaRe       = regexp.MustCompile(`(?i)^ASIA`)
)

// splitAssignment strips the shell/PowerShell/cmd/JSON scaffolding around
// `NAME = VALUE`. Returns ok=false for anything that is not an assignment.
func splitAssignment(line string) (name, value string, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "[") {
		return "", "", false
	}
	// `export FOO=..`, `set FOO=..`, `setx FOO ..`, `$Env:FOO=..`, `$env:FOO=..`
	s = envPrefixRe.ReplaceAllString(prefixRe.ReplaceAllString(s, ""), "")
	m := assignmentRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	// Trailing JSON punctuation, then surrounding quotes.
	v := strings.TrimSpace(trailingRe.ReplaceAllString(strings.TrimSpace(m[2]), ""))
	if q := quotedRe.FindStringSubmatch(v); q != nil && strings.HasSuffix(v, q[1]) {
		v = q[2]
	}
	return m[1], strings.TrimSpace(v), true
}

// splitJSONPieces breaks one line at every `,` or `{` that is followed by a
// quoted key, so a JSON blob printed on a single line is read field by field.
// Go's regexp has no lookbehind, so the scan is written out.
func splitJSONPieces(line string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] != ',' && line[i] != '{' {
			continue
		}
		j := i + 1
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		if j < len(line) && line[j] == '"' && j > start {
			out = append(out, line[start:j])
			start = j
		}
	}
	return append(out, line[start:])
}

// ParseBlob extracts whatever of the four fields the text contains. Anything it
// does not recognise is ignored rather than rejected — a blob usually carries a
// profile header, a region, an expiry note and a blank line as well.
func ParseBlob(text string) Parsed {
	out := Parsed{}
	for _, rawLine := range strings.Split(text, "\n") {
		rawLine = strings.TrimSuffix(rawLine, "\r")
		for _, piece := range splitJSONPieces(rawLine) {
			name, value, ok := splitAssignment(strings.Trim(piece, "{} \t"))
			if !ok || value == "" {
				continue
			}
			for _, f := range fieldPatterns {
				if f.get(&out) == "" && f.re.MatchString(name) {
					f.set(&out, value)
					break
				}
			}
		}
	}

	// A bare key pasted on its own — no name, no assignment. Worth catching: it
	// is what someone reads off a screen when only the id is in question.
	if out.AccessKeyID == "" {
		if m := keyIDShape.FindStringSubmatch(text); m != nil {
			out.AccessKeyID = m[1]
		}
	}
	return out
}

// ParseSharedCredentialsFile reads one `[profile]` section. The file is the
// fallback path for hosts with no usable CLI session: a key obtained by
// `aws configure` still lands here as `aws_session_token`.
func ParseSharedCredentialsFile(text, profile string) Parsed {
	want := strings.TrimSpace(profileWord.ReplaceAllString(profile, ""))
	if want == "" {
		want = "default"
	}
	inSection := false
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if header := sectionRe.FindStringSubmatch(line); header != nil {
			inSection = strings.TrimSpace(profileWord.ReplaceAllString(header[1], "")) == want
			continue
		}
		if inSection {
			lines = append(lines, line)
		}
	}
	return ParseBlob(strings.Join(lines, "\n"))
}

func (p Parsed) Complete() bool {
	return p.AccessKeyID != "" && p.SecretAccessKey != ""
}

func (p Parsed) Temporary() bool { return asiaRe.MatchString(p.AccessKeyID) }

// Problem catches what would otherwise come back as InvalidClientTokenId, an
// error that names nothing about the missing field. Returns "" when the set is
// usable.
func (p Parsed) Problem() string {
	switch {
	case p.AccessKeyID == "" && p.SecretAccessKey == "":
		return "붙여넣은 값에서 키를 찾지 못했습니다."
	case p.AccessKeyID == "":
		return "Access Key ID 가 비어 있습니다."
	case p.SecretAccessKey == "":
		return "Secret Access Key 가 비어 있습니다."
	case p.Temporary() && p.SessionToken == "":
		return "ASIA 로 시작하는 임시 키인데 Session Token 이 없습니다 — 세 값을 함께 넣어야 합니다."
	}
	return ""
}

// MaskKeyID shows enough of the id to recognise which key is in force, never
// enough to use it.
func MaskKeyID(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return value[:2] + "••••"
	}
	return value[:4] + "••••" + value[len(value)-4:]
}

// MaskSecret reports length only. There is no version of "part of the secret"
// that is safe to put on a screen someone may be sharing.
func MaskSecret(value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("•••••••• (%d자)", len([]rune(value)))
}

// ExpiresInMs is the milliseconds left on a temporary credential, or nil when
// it does not expire (a long-lived user key) or the timestamp is unreadable.
func ExpiresInMs(expiration string, nowMs int64) *int64 {
	t, ok := ParseExpiration(expiration)
	if !ok {
		return nil
	}
	left := t.UnixMilli() - nowMs
	return &left
}

// ParseExpiration accepts the ISO-8601 shapes the CLI and the console produce.
func ParseExpiration(expiration string) (time.Time, bool) {
	s := strings.TrimSpace(expiration)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02 15:04:05Z07:00", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
