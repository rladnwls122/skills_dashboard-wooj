import "server-only";
import type { PathLatencyStat, RequestLogAnalysis, RequestLogEntry } from "@/lib/types";

// Parses Go/Gin's default access-log line, e.g.:
//   [GIN] 2026/08/09 - 12:00:00 | 200 |     1.234ms |   127.0.0.1 | GET      "/v1/user"
// Falls back to a generic "METHOD /path -> STATUS Nms" shape some frameworks use.
const GIN_RE =
  /\[GIN\]\s+\S+\s+-\s+(\d{2}:\d{2}:\d{2})\s*\|\s*(\d{3})\s*\|\s*([\d.]+)(µs|ms|s|ns)\s*\|[^|]*\|\s*(\S+)\s+"([^"]+)"/;
const GENERIC_RE =
  /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\D+?(\d{3})\D+?([\d.]+)\s*(µs|ms|s|ns)?/i;

const ERROR_WARN_RE = /\b(error|warn|warning)\b/i;

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

function parseLine(line: string): RequestLogEntry | null {
  const gin = line.match(GIN_RE);
  if (gin) {
    const [, time, status, latencyVal, latencyUnit, method, path] = gin;
    return {
      ts: time ?? "",
      method: method ?? "",
      path: (path ?? "").split("?")[0] ?? "",
      status: Number(status),
      latencyMs: Math.round(toMs(Number(latencyVal), latencyUnit ?? "ms") * 1000) / 1000,
    };
  }
  const generic = line.match(GENERIC_RE);
  if (generic) {
    const [, method, path, status, latencyVal, latencyUnit] = generic;
    return {
      ts: "",
      method: (method ?? "").toUpperCase(),
      path: (path ?? "").split("?")[0] ?? "",
      status: Number(status),
      latencyMs: latencyVal
        ? Math.round(toMs(Number(latencyVal), latencyUnit ?? "ms") * 1000) / 1000
        : 0,
    };
  }
  return null;
}

// Extracts latency / non-2xx responses / error-warn lines from raw pod log
// lines (spec item 1). Lines are already masked upstream (getPodLogs).
export function analyzeRequestLog(lines: string[]): RequestLogAnalysis {
  const entries: RequestLogEntry[] = [];
  const errorWarnLines: string[] = [];

  for (const line of lines) {
    const entry = parseLine(line);
    if (entry) entries.push(entry);
    if (ERROR_WARN_RE.test(line)) errorWarnLines.push(line);
  }

  const nonOkEntries = entries.filter((e) => e.status !== 200 && e.status !== 201);

  const byPathMap = new Map<string, { count: number; sum: number; max: number; nonOk: number }>();
  for (const e of entries) {
    const s = byPathMap.get(e.path) ?? { count: 0, sum: 0, max: 0, nonOk: 0 };
    s.count += 1;
    s.sum += e.latencyMs;
    s.max = Math.max(s.max, e.latencyMs);
    if (e.status !== 200 && e.status !== 201) s.nonOk += 1;
    byPathMap.set(e.path, s);
  }
  const byPath: PathLatencyStat[] = [...byPathMap.entries()]
    .map(([path, s]) => ({
      path,
      count: s.count,
      avgLatencyMs: Math.round((s.sum / s.count) * 100) / 100,
      maxLatencyMs: Math.round(s.max * 100) / 100,
      nonOkCount: s.nonOk,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  const latencies = entries.map((e) => e.latencyMs);
  const avgLatencyMs =
    latencies.length > 0
      ? Math.round((latencies.reduce((a, v) => a + v, 0) / latencies.length) * 100) / 100
      : null;
  const maxLatencyMs = latencies.length > 0 ? Math.round(Math.max(...latencies) * 100) / 100 : null;

  return {
    entries: entries.slice(-500),
    nonOkEntries: nonOkEntries.slice(-100),
    errorWarnLines: errorWarnLines.slice(-100),
    avgLatencyMs,
    maxLatencyMs,
    byPath,
  };
}
