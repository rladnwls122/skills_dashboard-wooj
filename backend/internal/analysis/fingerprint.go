package analysis

// Error-line fingerprinting (spec §14), ported from fingerprint.ts.

import (
	"regexp"
	"sort"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

var errorLineRe = regexp.MustCompile(`(?i)(error|fatal|exception|panic|fail(ed|ure)?|timeout|timed out|refused|oom|out of memory|too many connections|deadlock|5\d{2}\s)`)

var normalizers = []struct {
	re  *regexp.Regexp
	sub string
}{
	// ISO / RFC3339 timestamps (incl. log-prefix timestamps)
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?`), "<TS>"},
	{regexp.MustCompile(`\d{2}:\d{2}:\d{2}(\.\d+)?`), "<TS>"},
	// UUID
	{regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), "<UUID>"},
	// Request/trace ids and long hex
	{regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`), "<HEX>"},
	// IPv4
	{regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b`), "<IP>"},
	// Remaining numbers
	{regexp.MustCompile(`\b\d+\b`), "<*>"},
}

var (
	leadingTokenRe = regexp.MustCompile(`^\S+\s`)
	isoPrefixRe    = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T`)
	tsExtractRe    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)`)
)

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary so multi-byte text is not split mid-character.
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

func NormalizeLine(line string) string {
	// Strip kubectl-style leading timestamp before normalizing.
	out := leadingTokenRe.ReplaceAllStringFunc(line, func(m string) string {
		if isoPrefixRe.MatchString(m) {
			return ""
		}
		return m
	})
	for _, n := range normalizers {
		out = n.re.ReplaceAllString(out, n.sub)
	}
	return truncate(trimSpace(out), 300)
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func ExtractTimestamp(line string) string {
	if m := tsExtractRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

type PodLines struct {
	Pod   string
	Lines []string
}

// AggregateFingerprints groups equivalent error lines into fingerprints.
func AggregateFingerprints(podLines []PodLines) []types.FingerprintEntry {
	type acc struct {
		count     int
		pods      []string
		podSet    map[string]struct{}
		firstSeen string
		lastSeen  string
		sample    string
	}
	m := map[string]*acc{}
	order := []string{}
	for _, pl := range podLines {
		for _, line := range pl.Lines {
			if !errorLineRe.MatchString(line) {
				continue
			}
			fp := NormalizeLine(line)
			if len(fp) < 5 {
				continue
			}
			ts := ExtractTimestamp(line)
			entry, ok := m[fp]
			if ok {
				entry.count++
				if _, seen := entry.podSet[pl.Pod]; !seen {
					entry.podSet[pl.Pod] = struct{}{}
					entry.pods = append(entry.pods, pl.Pod)
				}
				if ts != "" && (entry.lastSeen == "" || ts > entry.lastSeen) {
					entry.lastSeen = ts
				}
				if ts != "" && (entry.firstSeen == "" || ts < entry.firstSeen) {
					entry.firstSeen = ts
				}
			} else {
				m[fp] = &acc{
					count:     1,
					pods:      []string{pl.Pod},
					podSet:    map[string]struct{}{pl.Pod: {}},
					firstSeen: ts,
					lastSeen:  ts,
					sample:    truncate(line, 300),
				}
				order = append(order, fp)
			}
		}
	}
	out := make([]types.FingerprintEntry, 0, len(order))
	for _, fp := range order {
		v := m[fp]
		out = append(out, types.FingerprintEntry{
			Fingerprint: fp,
			Count:       v.count,
			Pods:        v.pods,
			FirstSeen:   v.firstSeen,
			LastSeen:    v.lastSeen,
			Sample:      v.sample,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}
