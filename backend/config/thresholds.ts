// Metric thresholds and limits.

import type { Status } from "../../src/lib/types.ts";

export interface MetricThreshold {
  // WARNING when (abs >= warnAbs) OR (pct >= warnPct AND abs >= minAbs).
  // CRITICAL requires BOTH abs >= critAbs AND pct >= critPct — a single
  // criterion is never enough (false-positive guard, spec §8).
  warnAbs: number;
  critAbs: number;
  warnPct: number;
  critPct: number;
  minAbs: number;
}

export const THRESHOLDS: Record<string, MetricThreshold> = {
  targetResponseTime: { warnAbs: 0.5, critAbs: 2.0, warnPct: 80, critPct: 200, minAbs: 0.2 },
  http4xx: { warnAbs: 50, critAbs: 300, warnPct: 100, critPct: 300, minAbs: 20 },
  http5xx: { warnAbs: 20, critAbs: 100, warnPct: 100, critPct: 300, minAbs: 10 },
  rdsClientConnections: { warnAbs: 80, critAbs: 200, warnPct: 80, critPct: 200, minAbs: 20 },
  rdsDatabaseConnections: { warnAbs: 60, critAbs: 150, warnPct: 80, critPct: 200, minAbs: 15 },
  wafBlocked: { warnAbs: 50, critAbs: 500, warnPct: 100, critPct: 400, minAbs: 20 },
};

export function statusFor(
  key: string,
  current: number,
  percentChange: number | null | undefined,
): Status {
  const t = THRESHOLDS[key];
  if (!t) return "NORMAL";
  const pct = percentChange ?? 0;
  if (current >= t.critAbs && pct >= t.critPct) return "CRITICAL";
  if (current >= t.warnAbs) return "WARNING";
  if (pct >= t.warnPct && current >= t.minAbs) return "WARNING";
  return "NORMAL";
}

/** Insights limits — hard caps that bound bytes scanned structurally. */
export const INSIGHTS_LIMITS = {
  maxWindowMs: 4 * 60 * 60 * 1000,
  defaultWindowMs: 60 * 60 * 1000,
  queryDeadlineMs: 20_000,
  maxConcurrent: 2,
};

export const WAF_LIMITS = {
  maxWCU: 5000,
  sampleWindowMinutes: 15,
};

/**
 * The WAF-log aggregation is five Insights queries over the whole window, so it
 * refreshes on its own slower tier.
 */
export const WAF_INSIGHTS_TTL_MS = 2 * 60 * 1000;
