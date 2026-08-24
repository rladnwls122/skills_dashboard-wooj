// Access-log parsing from raw pod/container log lines (spec item 1). Lines are
// already masked upstream. The line shape is gin's default logger — what all
// three competition binaries print (see logfields.ts / docs/binaries.md).

import { cleanUri } from "./logfields.ts";
import type {
  PathLatencyStat,
  RequestLogAnalysis,
  RequestLogEntry,
} from "../../src/lib/types.ts";

// [GIN] 2025/09/23 - 03:12:45 | 201 |   12.345678ms |   203.0.113.10 | POST     "/v1/user?requestid=1"
// The k8s API prefixes its own RFC3339 timestamp and the EKS log shipper
// may wrap the line in JSON; neither is anchored on, and the optional
// backslash before the quote is the JSON-escaped form.
const GIN_RE =
  /\[GIN\]\s+(\d{4}\/\d{2}\/\d{2}) - (\d{2}:\d{2}:\d{2})\s*\|\s*(\d{3})\s*\|\s*([^\s|]+)\s*\|\s*([^\s|]+)\s*\|\s*([A-Z]+)\s+\\?"([^"\\]*)/;
// The custom middleware line: 2025/09/23 03:12:45 [2025-09-23T03:12:45Z] POST /v1/user from 203.0.113.10
// Logged before the handler runs, so it has no status — it duplicates the
// [GIN] line that follows and must not be counted as a second request.
const ARRIVAL_RE = /\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\]]*)\]\s+([A-Z]+)\s+(\S+)\s+from\s+(\S+)/;
// Generic "METHOD /path -> STATUS Nms" fallback for anything else.
const GENERIC_RE =
  /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\D+?(\d{3})\D+?([\d.]+)\s*(µs|ms|s|ns)?/i;
const ERR_WARN_RE = /\b(error|warn|warning|fail|failed|panic|fatal|malicious)\b/i;

// One Go time.Duration component as String() prints it. Go's own parser
// accepts "us" as well as "µs"; the logger writes "µs".
const DURATION_PART_RE = /([0-9]*\.?[0-9]+)(ns|µs|μs|us|ms|s|m|h)/g;
const UNIT_MS: Record<string, number> = {
  ns: 1e-6,
  "µs": 1e-3,
  "μs": 1e-3,
  us: 1e-3,
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
};

/**
 * durationMs parses a Go time.Duration as printed by String() — "850ns",
 * "45.678µs", "12.345678ms", "1.2s", "1m2s" (gin truncates anything past a
 * minute to whole seconds). The unit is taken literally so "ms" is never
 * mistaken for "s".
 *
 * Returns null when the token is not a duration at all; Go's ParseDuration
 * returns an error there and every caller treats that as "not an access line".
 */
export function durationMs(token: string): number | null {
  const trimmed = token.trim();
  if (trimmed === "") return null;
  if (trimmed === "0") return 0;
  let sign = 1;
  let rest = trimmed;
  if (rest.startsWith("-")) {
    sign = -1;
    rest = rest.slice(1);
  } else if (rest.startsWith("+")) {
    rest = rest.slice(1);
  }
  // Every character has to belong to a unit component, or the token is
  // something else that merely starts with digits.
  DURATION_PART_RE.lastIndex = 0;
  let total = 0;
  let consumed = 0;
  let matched = false;
  let m: RegExpExecArray | null;
  while ((m = DURATION_PART_RE.exec(rest)) !== null) {
    if (m.index !== consumed) return null;
    const scale = UNIT_MS[m[2]!];
    if (scale === undefined) return null;
    total += Number.parseFloat(m[1]!) * scale;
    consumed = m.index + m[0].length;
    matched = true;
  }
  if (!matched || consumed !== rest.length) return null;
  return sign * total;
}

function toMs(value: number, unit: string): number {
  switch (unit) {
    case "ns":
      return value / 1_000_000;
    case "µs":
      return value / 1_000;
    case "s":
      return value * 1000;
    default:
      return value;
  }
}

const round3 = (v: number): number => Math.round(v * 1000) / 1000;
const round2 = (v: number): number => Math.round(v * 100) / 100;

function stripQuery(p: string): string {
  return p.split("?")[0]!;
}

/**
 * requestIdOf reads the grader's requestid out of a logged URI. "" when the
 * request did not carry one in the query string (POST bodies are not logged).
 */
export function requestIdOf(uri: string): string {
  const i = uri.indexOf("?");
  if (i < 0) return "";
  const query = uri.slice(i + 1);
  try {
    return new URLSearchParams(query).get("requestid") ?? "";
  } catch {
    // A malformed query usually still has the key readable.
    for (const pair of query.split("&")) {
      if (pair.startsWith("requestid=")) return pair.slice("requestid=".length);
    }
    return "";
  }
}

/** parseAccessLine reads one gin access-log line. null when the line is not one. */
export function parseAccessLine(line: string): RequestLogEntry | null {
  const m = GIN_RE.exec(line);
  if (!m) return null;
  const lat = durationMs(m[4]!) ?? 0;
  const uri = cleanUri(m[7]!, false);
  return {
    ts: m[2]!,
    method: m[6]!,
    path: stripQuery(uri),
    status: Number.parseInt(m[3]!, 10) || 0,
    latencyMs: round3(lat),
    clientIp: m[5]!,
    requestId: requestIdOf(uri),
  };
}

/**
 * isArrivalLine reports whether the line is the binaries' custom middleware
 * line ("[ts] METHOD /path from IP") — a request that arrived, status unknown.
 */
export function isArrivalLine(line: string): boolean {
  return ARRIVAL_RE.test(line);
}

function parseLine(line: string): RequestLogEntry | null {
  const access = parseAccessLine(line);
  if (access) return access;
  if (ARRIVAL_RE.test(line)) return null;
  const generic = GENERIC_RE.exec(line);
  if (generic) {
    let latency = 0;
    if (generic[4]) {
      latency = round3(toMs(Number.parseFloat(generic[4]) || 0, generic[5] || "ms"));
    }
    return {
      ts: "",
      method: generic[1]!.toUpperCase(),
      path: stripQuery(generic[2]!),
      status: Number.parseInt(generic[3]!, 10) || 0,
      latencyMs: latency,
    };
  }
  return null;
}

function isNonOk(status: number): boolean {
  return status < 200 || status >= 300;
}

function tail<T>(list: T[], n: number): T[] {
  return list.length > n ? list.slice(list.length - n) : list;
}

/**
 * Extracts latency / non-2xx responses / error-warn lines from raw pod log
 * lines.
 */
export function analyzeRequestLog(lines: string[]): RequestLogAnalysis {
  const entries: RequestLogEntry[] = [];
  const errorWarnLines: string[] = [];

  for (const line of lines) {
    const e = parseLine(line);
    if (e) entries.push(e);
    if (ERR_WARN_RE.test(line)) errorWarnLines.push(line);
  }

  const nonOkEntries = entries.filter((e) => isNonOk(e.status));

  interface PathAcc {
    count: number;
    sum: number;
    max: number;
    nonOk: number;
  }
  const byPathMap = new Map<string, PathAcc>();
  for (const e of entries) {
    let s = byPathMap.get(e.path);
    if (!s) {
      s = { count: 0, sum: 0, max: 0, nonOk: 0 };
      byPathMap.set(e.path, s);
    }
    s.count++;
    s.sum += e.latencyMs;
    if (e.latencyMs > s.max) s.max = e.latencyMs;
    if (isNonOk(e.status)) s.nonOk++;
  }

  const byPath: PathLatencyStat[] = [];
  for (const [path, s] of byPathMap) {
    byPath.push({
      path,
      count: s.count,
      avgLatencyMs: round2(s.sum / s.count),
      maxLatencyMs: round2(s.max),
      nonOkCount: s.nonOk,
    });
  }
  byPath.sort((a, b) => b.count - a.count);

  let avgLatencyMs: number | null = null;
  let maxLatencyMs: number | null = null;
  if (entries.length > 0) {
    let sum = 0;
    let max = 0;
    for (const e of entries) {
      sum += e.latencyMs;
      if (e.latencyMs > max) max = e.latencyMs;
    }
    avgLatencyMs = round2(sum / entries.length);
    maxLatencyMs = round2(max);
  }

  return {
    entries: tail(entries, 500),
    nonOkEntries: tail(nonOkEntries, 100),
    errorWarnLines: tail(errorWarnLines, 100),
    avgLatencyMs,
    maxLatencyMs,
    byPath: byPath.slice(0, 20),
    // Counted over everything parsed, not over the truncated sample lists above
    // — and set here rather than left absent. This is the path the panel takes
    // when Logs Insights failed, which is exactly when something is already
    // wrong, and a blank "총 요청" next to a populated table reads as "no data"
    // when it means "nobody filled the field in". The caller (live/podlogs.ts)
    // still owns `basis`, which says which population these totals describe.
    totalRequests: entries.length,
    nonOkTotal: nonOkEntries.length,
    errorWarnTotal: errorWarnLines.length,
  };
}
