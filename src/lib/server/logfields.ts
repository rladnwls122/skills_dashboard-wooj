import "server-only";

// The app logs structured JSON, so Insights can pull method/path/status/latency
// out as real fields — status is then filterable as a number. Shared by the pod
// log reader and the app request-log query.
//
// requestid/uuid are the join keys to the WAF log: the task appends both as
// query-string parameters and the app writes them as first-class fields, so a
// WAF verdict and the app's response code can be lined up for one request.
// They are empty on POST/PUT — the app only reads them from the query string.
export const PARSE_FIELDS =
  'parse log /"latency_ms":(?<latency_ms>[0-9.]+)/' +
  ' | parse log /"method":"(?<method>[A-Z]+)"/' +
  ' | parse log /"path":"(?<path>[^"]*)"/' +
  ' | parse log /"status":(?<status>[0-9]+)/' +
  ' | parse log /"requestid":"(?<requestid>[^"]*)"/' +
  ' | parse log /"uuid":"(?<uuid>[^"]*)"/';

// The User-Agent, for the request-log table only — the stats queries that share
// PARSE_FIELDS have no use for it, and an extra parse there would buy nothing.
//
// Kept tolerant of the field name because the app's log schema is given, not
// chosen: "user_agent", "user-agent", "userAgent", a bare "ua". The casing is
// spelled out as character classes rather than an inline `(?i)` flag —
// Insights' regex dialect is not the place to find out a flag is unsupported,
// because the failure takes the whole query down with it and the panel goes
// empty for a reason that has nothing to do with the traffic.
//
// Missing field, empty column: an app that logs no User-Agent is a normal
// answer here, not an error.
export const UA_FIELD =
  'parse log /"(?:[uU][sS][eE][rR][-_]?[aA][gG][eE][nN][tT]|[uU][aA])"\\s*:\\s*"(?<user_agent>[^"]*)"/';

// Converts "2026-08-10 03:07:12.727" (Insights @timestamp, UTC) to ISO.
export function toIso(ts: string): string {
  return `${ts.replace(" ", "T")}Z`;
}

export function hhmmss(iso: string): string {
  const m = iso.match(/T(\d{2}:\d{2}:\d{2})/);
  return m?.[1] ?? "";
}
