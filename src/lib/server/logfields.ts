import "server-only";

// The app logs structured JSON, so Insights can pull method/path/status/latency
// out as real fields — status is then filterable as a number. Shared by the pod
// log reader and the app request-log query.
export const PARSE_FIELDS =
  'parse log /"latency_ms":(?<latency_ms>[0-9.]+)/' +
  ' | parse log /"method":"(?<method>[A-Z]+)"/' +
  ' | parse log /"path":"(?<path>[^"]*)"/' +
  ' | parse log /"status":(?<status>[0-9]+)/';

// Converts "2026-08-10 03:07:12.727" (Insights @timestamp, UTC) to ISO.
export function toIso(ts: string): string {
  return `${ts.replace(" ", "T")}Z`;
}

export function hhmmss(iso: string): string {
  const m = iso.match(/T(\d{2}:\d{2}:\d{2})/);
  return m?.[1] ?? "";
}
