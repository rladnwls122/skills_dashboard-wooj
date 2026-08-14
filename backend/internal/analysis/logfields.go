package analysis

import "regexp"

// The app logs structured JSON, so Insights can pull method/path/status/latency
// out as real fields. Shared by the pod log reader and the app request-log
// query. Ported from logfields.ts.
const ParseFields = `parse log /"latency_ms":(?<latency_ms>[0-9.]+)/` +
	` | parse log /"method":"(?<method>[A-Z]+)"/` +
	` | parse log /"path":"(?<path>[^"]*)"/` +
	` | parse log /"status":(?<status>[0-9]+)/`

var hhmmssRe = regexp.MustCompile(`T(\d{2}:\d{2}:\d{2})`)

// ToIso converts "2026-08-10 03:07:12.727" (Insights @timestamp, UTC) to ISO.
func ToIso(ts string) string {
	out := []byte(ts)
	for i, c := range out {
		if c == ' ' {
			out[i] = 'T'
			break
		}
	}
	return string(out) + "Z"
}

func Hhmmss(iso string) string {
	if m := hhmmssRe.FindStringSubmatch(iso); m != nil {
		return m[1]
	}
	return ""
}
