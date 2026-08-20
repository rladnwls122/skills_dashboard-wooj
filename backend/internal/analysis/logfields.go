package analysis

// What the competition binaries (user · product · stress, Go/Gin 1.10) actually
// write, and how Logs Insights pulls fields out of it. Verified by
// disassembling the 2025 national-competition task-3 binaries — see
// docs/binaries.md.
//
// Every app is gin.Default() plus one custom middleware, so each request leaves
// two lines:
//
//	stdout  [GIN] 2025/09/23 - 03:12:45 | 201 |   12.345678ms |   203.0.113.10 | POST     "/v1/user?requestid=1&uuid=x"
//	stderr  2025/09/23 03:12:45 [2025-09-23T03:12:45Z] POST /v1/user from 203.0.113.10
//
// Only the [GIN] line carries status and latency, so it is the access log.
// Its path is the full request URI (query string included — the grader puts
// requestid and uuid there), the latency is a Go time.Duration as printed by
// String() ("850ns", "45.678µs", "12.345ms", "1.2s", "1m2s"), and the client
// IP is what gin resolved after X-Forwarded-For.
//
// The log group may be an ECS awslogs group (the line is @message) or an EKS
// Container Insights group (the line is the "log" field of a JSON @message,
// with the quotes around the path escaped as \"). Parsing @message with an
// optional character before the opening quote covers both.

import "regexp"

// GinParse extracts the access-log fields from @message. Field names are the
// ones the rest of the queries consume:
//
//	status     3-digit response code
//	lat_num    latency number as printed
//	lat_unit   its unit token (ns, µs, ms, s, or the m…s form past a minute)
//	client_ip  resolved client IP
//	method     HTTP method
//	uri        path with query string, exactly as logged
//
// The JSON-wrapped (EKS) form escapes the quotes around the path as \", so
// the opening quote is preceded by an optional character (".?") and the uri
// capture runs to the next quote — which leaves the escaping backslash on the
// end of the capture in that form; CleanURI/CleanPath strip it where the
// value is read. A regex-level "\\" (four backslashes in the query string)
// looked like the clean way to say "optional backslash" and did work in a
// one-parse query, but returned a different row set once a second parse
// clause followed it — verified against a scratch log group, see
// docs/binaries.md — so no backslash is written in any pattern here.
const GinParse = `parse @message /\[GIN\] [0-9\/]+ - [0-9:]+ \|\s*(?<status>[0-9]{3})\s*\|\s*(?<lat_num>[0-9.]+)(?<lat_unit>[^\s|]+)\s*\|\s*(?<client_ip>[^\s|]+)\s*\|\s*(?<method>[A-Z]+)\s+.?"(?<uri>[^"]*)/`

// LatencyFields turns the printed duration into latency_ms. Insights has no
// conditional, so each unit is parsed into its own field and the absent ones
// are coalesced to zero; only one of them is ever present per line.
const LatencyFields = `parse @message /\|\s*(?<lat_ms>[0-9.]+)ms\s*\|/` +
	` | parse @message /\|\s*(?<lat_us>[0-9.]+)µs\s*\|/` +
	` | parse @message /\|\s*(?<lat_s>[0-9.]+)s\s*\|/` +
	` | parse @message /\|\s*(?<lat_ns>[0-9.]+)ns\s*\|/` +
	` | parse @message /\|\s*(?<lat_m>[0-9]+)m[0-9.]*s\s*\|/` +
	` | fields coalesce(lat_ms, 0) + coalesce(lat_us, 0) / 1000 + coalesce(lat_s, 0) * 1000 + coalesce(lat_ns, 0) / 1000000 + coalesce(lat_m, 0) * 60000 as latency_ms`

// RouteFields splits the logged URI into the route (path without query — what
// every "by path" aggregation has to group on, or each GET is its own row
// because requestid is in the query) and the grader's requestid. The requestid
// class deliberately excludes the backslash the JSON form can leave behind.
const RouteFields = `parse uri /^(?<path>[^?]*)/ | parse uri /[?&]requestid=(?<requestid>[0-9A-Za-z_-]+)/`

// ParseFields is the whole chain: status, latency_ms, client_ip, method, uri,
// path, requestid. Rows that are not access-log lines (the stderr middleware
// line, DB errors, [GIN-debug] startup) have none of these set — filter on
// ispresent(status) after it.
const ParseFields = GinParse + " | " + LatencyFields + " | " + RouteFields

// AccessLogFilter keeps only the lines ParseFields understood.
const AccessLogFilter = "filter ispresent(status)"

// ErrorLineLike is the Insights-side twin of fingerprint.go's errorLineRe:
// what the binaries print when something went wrong. "malicious" is the
// product app's own trap line ("Consumed resources by malicious attacks." for
// User-Agent Attacker-Bot), which no generic error keyword would catch.
const ErrorLineLike = `/(?i)(error|warn|fail|panic|fatal|timeout|refused|malicious|\[Recovery\])/`

// MaliciousTrapLine is the exact stdout line the product binary writes when it
// serves a request whose User-Agent is "Attacker-Bot" — it then answers 500.
// Each occurrence is one abnormal request that got past the WAF.
const MaliciousTrapLine = "Consumed resources by malicious attacks"

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

// CleanURI strips the trailing backslash the JSON-wrapped (EKS) form leaves on
// the uri/path captures (see GinParse) and, when route is true, the query
// string.
func CleanURI(uri string, route bool) string {
	for len(uri) > 0 && uri[len(uri)-1] == '\\' {
		uri = uri[:len(uri)-1]
	}
	if route {
		for i := 0; i < len(uri); i++ {
			if uri[i] == '?' {
				return uri[:i]
			}
		}
	}
	return uri
}

// CleanPath is CleanURI for a field that was already split on "?" by
// RouteFields but may still carry the EKS backslash.
func CleanPath(p string) string { return CleanURI(p, true) }
