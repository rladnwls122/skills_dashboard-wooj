import "server-only";
import { PARSE_FIELDS, UA_FIELD, toIso } from "./logfields";
import type { RequestLogRow } from "@/lib/types";

export type StatusClass = "ALL" | "2xx" | "3xx" | "4xx" | "5xx";

const STATUS_RANGE: Record<Exclude<StatusClass, "ALL">, [number, number]> = {
  "2xx": [200, 300],
  "3xx": [300, 400],
  "4xx": [400, 500],
  "5xx": [500, 600],
};

// How many rows come back, NOT how much is searched: every filter below is a
// Logs Insights `filter` stage, so the status class and the path term are
// applied to every record in the window (100k+ requests) before this limit
// takes the newest N of what matched. The number is a transfer cap — at 200 a
// path search that matched thousands showed a suspiciously round 200 and read
// as "it only looked at the first page".
export const ROW_LIMIT = 1000;
export const PATH_FILTER_MAX = 120;

// The filter is interpolated into an Insights query string inside double
// quotes. The allowed set excludes both the quote and the backslash, so no
// escaping is reachable — this validation is the whole guarantee.
const PATH_FILTER_RE = /^[A-Za-z0-9/_.-]*$/;

export function validatePathFilter(raw: string): string {
  const v = raw.trim();
  if (v.length > PATH_FILTER_MAX) {
    throw new Error(`경로 검색어가 너무 김 (최대 ${PATH_FILTER_MAX}자)`);
  }
  if (!PATH_FILTER_RE.test(v)) {
    throw new Error("경로 검색어에 허용되지 않는 문자가 있음 (영문·숫자와 / _ . - 만 가능)");
  }
  return v;
}

export function buildRequestLogQuery(params: {
  statusClass: StatusClass;
  pathContains: string;
  // Paths dropped before anything else runs — the health check, by default.
  // It is the busiest path in the log by a wide margin (thousands of 200s per
  // minute against a few hundred API requests), so without this the newest
  // 1000 rows are all health checks and the panel shows no application traffic
  // at all. Dropped in the query rather than in the client so the match count
  // and the scanned bytes both shrink with it.
  excludePaths?: readonly string[];
}): string {
  const parts: string[] = [PARSE_FIELDS, UA_FIELD, "filter ispresent(status)"];
  if (params.statusClass !== "ALL") {
    const [lo, hi] = STATUS_RANGE[params.statusClass];
    parts.push(`filter status >= ${lo} and status < ${hi}`);
  }
  const path = validatePathFilter(params.pathContains);
  if (path) parts.push(`filter path like "${path}"`);
  for (const raw of params.excludePaths ?? []) {
    const excluded = validatePathFilter(raw);
    if (!excluded) continue;
    // Searching for the excluded path itself has to win — otherwise the box
    // accepts "/healthcheck" and silently answers "no such request".
    if (path && excluded.includes(path)) continue;
    parts.push(`filter path not like "${excluded}"`);
  }
  // `log` is the raw line the app wrote. It rides along because the parsed
  // columns are a guess at which fields matter, and a header the app logged
  // under a name nobody predicted is exactly what an operator goes looking for
  // when a request is being blocked and the reason is not in the path.
  parts.push("display @timestamp, method, path, status, latency_ms, user_agent, requestid, log");
  parts.push("sort @timestamp desc");
  parts.push(`limit ${ROW_LIMIT}`);
  return parts.join(" | ");
}

export function toRequestLogRow(r: Record<string, string>): RequestLogRow {
  const userAgent = r["user_agent"] ?? "";
  return {
    ts: toIso(r["@timestamp"] ?? ""),
    method: r["method"] ?? "",
    path: r["path"] ?? "",
    status: Number(r["status"] ?? "0"),
    latencyMs: Number(r["latency_ms"] ?? "0"),
    requestId: r["requestid"] ?? "",
    userAgent,
    uaSource: userAgent ? "app" : "",
    // Masking happens in the caller, which is where every other log line on
    // this dashboard is masked (server/mask.ts).
    raw: r["log"] ?? r["@message"] ?? "",
  };
}
