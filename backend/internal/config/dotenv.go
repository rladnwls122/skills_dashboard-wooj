package config

// Reads a .env file into the process environment.
//
// The dashboard is started by hand on a venue machine — often by
// double-clicking the release binary — so there is no launcher (mise, direnv,
// dotenv-cli) to populate the environment first, and a missing AWS_REGION shows
// up much later as an empty panel. The process therefore loads its own .env.
//
// Two rules keep this predictable:
//   - A variable already present in the real environment always wins. Exporting
//     a value overrides the file without editing it.
//   - A missing file is not an error. Every value here has a default or lives in
//     the settings table.
//
// backend/config/dotenv.ts in the Node port parses the same grammar; keep the
// two in step.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Dotenv reports what a load found: the file that was read (empty if none), the
// keys taken from it, and the keys it yielded to the environment on.
type Dotenv struct {
	Path    string
	Applied []string
	Skipped []string
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// dotenvCandidates lists the paths to try, in order; the first that reads wins.
//
// ENV_FILE is the explicit escape hatch (two instances, two configs). The
// working directory is the normal case. The directory holding the executable
// covers a release binary launched from Explorer, where the working directory
// is whatever the shortcut says and rarely where the .env sits.
func dotenvCandidates(explicit string) []string {
	var list []string
	add := func(p string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		for _, seen := range list {
			if seen == abs {
				return
			}
		}
		list = append(list, abs)
	}

	if explicit == "" {
		explicit = strings.TrimSpace(os.Getenv("ENV_FILE"))
	}
	add(explicit)
	add(".env")
	if exe, err := os.Executable(); err == nil {
		add(filepath.Join(filepath.Dir(exe), ".env"))
	}
	return list
}

// ParseEnv parses .env text. It supports KEY=value, an optional "export "
// prefix, # comments, single-quoted (literal) and double-quoted (escapes)
// values, and a trailing comment after an unquoted value. Malformed lines are
// skipped rather than reported: a stray line in a config file must not stop the
// dashboard from booting mid-exercise.
func ParseEnv(text string) map[string]string {
	out := map[string]string{}
	// A leading BOM would otherwise become part of the first key — Windows
	// editors add one, and the resulting "<BOM>AWS_REGION" silently reads empty.
	text = strings.TrimPrefix(text, "\ufeff")

	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		body := line
		if rest, ok := strings.CutPrefix(body, "export "); ok {
			body = strings.TrimSpace(rest)
		}
		key, value, ok := strings.Cut(body, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !envKeyRe.MatchString(key) {
			continue
		}
		out[key] = parseEnvValue(strings.TrimSpace(value))
	}
	return out
}

func parseEnvValue(raw string) string {
	if strings.HasPrefix(raw, "'") && len(raw) > 1 {
		// Single quotes are literal: no escapes, no interpolation.
		if end := strings.Index(raw[1:], "'"); end >= 0 {
			return raw[1 : 1+end]
		}
		return raw[1:]
	}
	if strings.HasPrefix(raw, `"`) && len(raw) > 1 {
		inner := raw[1:]
		if end := closingDouble(raw); end >= 0 {
			inner = raw[1:end]
		}
		return unescapeDouble(inner)
	}
	// Unquoted: whitespace then # starts a trailing comment. A bare # inside a
	// token (a URL fragment, a password) is kept. A value that starts where a
	// comment would is an empty value with a note after it: "KEY=  # note".
	if strings.HasPrefix(raw, "#") {
		return ""
	}
	for i := 1; i < len(raw); i++ {
		if raw[i] == '#' && (raw[i-1] == ' ' || raw[i-1] == '\t') {
			return strings.TrimSpace(raw[:i])
		}
	}
	return raw
}

// closingDouble is the index of the closing double quote, skipping escaped ones.
func closingDouble(raw string) int {
	for i := 1; i < len(raw); i++ {
		if raw[i] == '\\' {
			i++
			continue
		}
		if raw[i] == '"' {
			return i
		}
	}
	return -1
}

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// LoadDotenv folds the first .env found into the process environment without
// overwriting anything the environment already provides. Pass an empty path to
// use the normal search order.
func LoadDotenv(explicit string) Dotenv {
	for _, path := range dotenvCandidates(explicit) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Absent, or unreadable — try the next candidate.
		}
		res := Dotenv{Path: path}
		for key, value := range ParseEnv(string(data)) {
			// An empty value in .env means "unset" — the file ships with blank
			// AWS keys as documentation, and turning those into empty strings
			// would shadow the credentials the settings screen injects later.
			if value == "" {
				continue
			}
			if existing := os.Getenv(key); existing != "" {
				res.Skipped = append(res.Skipped, key)
				continue
			}
			if err := os.Setenv(key, value); err != nil {
				continue
			}
			res.Applied = append(res.Applied, key)
		}
		return res
	}
	return Dotenv{}
}
