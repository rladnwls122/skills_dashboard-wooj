// Small helpers shared by the log-reading paths.

import type { ResolvedWindow } from "../../src/lib/types.ts";

export function parseF(s: string | undefined): number {
  const n = Number.parseFloat(s ?? "");
  return Number.isFinite(n) ? n : 0;
}

export function atoiF(s: string | undefined): number {
  return Math.trunc(parseF(s));
}

/**
 * Cache keys have to change when the window does, or a panel serves the previous
 * span's numbers under the new label.
 */
export function windowKey(w: ResolvedWindow): string {
  return `${w.windowMin}-${w.intervalMin}-${w.endMs}`;
}

export const PATH_FILTER_MAX = 120;

/**
 * The filter is interpolated into an Insights query string inside double quotes.
 * The allowed set excludes both the quote and the backslash, so no escaping is
 * reachable — this validation is the whole guarantee.
 */
const PATH_FILTER_RE = /^[A-Za-z0-9/_.-]*$/;

export function validatePathFilter(raw: string): string {
  const v = (raw ?? "").trim();
  if (v.length > PATH_FILTER_MAX) {
    throw new Error(`경로 검색어가 너무 김 (최대 ${PATH_FILTER_MAX}자)`);
  }
  if (!PATH_FILTER_RE.test(v)) {
    throw new Error("경로 검색어에 허용되지 않는 문자가 있음 (영문·숫자와 / _ . - 만 가능)");
  }
  return v;
}

export function firstNonEmpty(...values: (string | undefined)[]): string {
  for (const v of values) {
    if (v) return v;
  }
  return "";
}
