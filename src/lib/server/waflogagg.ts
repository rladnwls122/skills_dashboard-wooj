import "server-only";

// Folding of WAF-log Logs Insights results. Kept apart from waf.ts (and its AWS
// SDK imports) so the part that decides what the numbers mean is pure and
// testable without a cloud call — the query strings themselves can only be
// verified against a real log group.
//
// Counts arrive grouped by (key, action) rather than filtered to blocks. A list
// of blocked paths alone cannot tell "nothing was blocked" from "nothing
// arrived", and grouping by the pair costs no extra scan.

import type { InsightsRow } from "./logsinsights";

export interface Folded {
  count: number;
  blocked: number;
}

export function rowValue(row: InsightsRow, field: string): string {
  return row[field] ?? "";
}

export function rowCount(row: InsightsRow): number {
  const n = Number(row["cnt"] ?? "0");
  return Number.isFinite(n) ? n : 0;
}

export function foldByAction(rows: InsightsRow[], keyField: string): Map<string, Folded> {
  const out = new Map<string, Folded>();
  for (const r of rows) {
    const key = rowValue(r, keyField);
    const entry = out.get(key) ?? { count: 0, blocked: 0 };
    const n = rowCount(r);
    entry.count += n;
    if (rowValue(r, "action").toUpperCase() === "BLOCK") entry.blocked += n;
    out.set(key, entry);
  }
  return out;
}

export function totals(folded: Map<string, Folded>): { total: number; blockedTotal: number } {
  let total = 0;
  let blockedTotal = 0;
  for (const v of folded.values()) {
    total += v.count;
    blockedTotal += v.blocked;
  }
  return { total, blockedTotal };
}

// A cached aggregation covers the window it was run for, not the one the panel
// is labelled with. Once that gap is a minute or more the difference shows in
// the numbers, so it is spelled out next to the window label rather than left
// for the operator to discover by comparing panels.
export function insightsAgeNote(coveredEndMs: number, nowMs: number): string {
  const min = Math.floor((nowMs - coveredEndMs) / 60_000);
  return min >= 1 ? ` · ${min}분 전 집계` : "";
}

export function topKeyCounts(
  rows: InsightsRow[],
  keyField: string,
  n: number,
): { key: string; count: number }[] {
  return rows
    .map((r) => ({ key: rowValue(r, keyField), count: rowCount(r) }))
    .filter((r) => r.key.length > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}
