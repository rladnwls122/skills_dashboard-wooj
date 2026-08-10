import "server-only";
import { PARSE_FIELDS, toIso } from "./logfields";
import type { RequestLogRow } from "@/lib/types";

export type StatusClass = "ALL" | "2xx" | "3xx" | "4xx" | "5xx";

const STATUS_RANGE: Record<Exclude<StatusClass, "ALL">, [number, number]> = {
  "2xx": [200, 300],
  "3xx": [300, 400],
  "4xx": [400, 500],
  "5xx": [500, 600],
};

export const ROW_LIMIT = 200;
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
}): string {
  const parts: string[] = [PARSE_FIELDS, "filter ispresent(status)"];
  if (params.statusClass !== "ALL") {
    const [lo, hi] = STATUS_RANGE[params.statusClass];
    parts.push(`filter status >= ${lo} and status < ${hi}`);
  }
  const path = validatePathFilter(params.pathContains);
  if (path) parts.push(`filter path like "${path}"`);
  parts.push("fields @timestamp, method, path, status, latency_ms");
  parts.push("sort @timestamp desc");
  parts.push(`limit ${ROW_LIMIT}`);
  return parts.join(" | ");
}

export function toRequestLogRow(r: Record<string, string>): RequestLogRow {
  return {
    ts: toIso(r["@timestamp"] ?? ""),
    method: r["method"] ?? "",
    path: r["path"] ?? "",
    status: Number(r["status"] ?? "0"),
    latencyMs: Number(r["latency_ms"] ?? "0"),
  };
}
