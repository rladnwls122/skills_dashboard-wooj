// The one time window every panel reads.
//
//   - The span is capped at 4 hours. Insights bills per byte scanned.
//   - Only span/interval pairs producing 4..250 buckets are offered.
//   - The end is floored to an interval boundary, so every bucket is complete.
//     A partial trailing bucket reads as a sudden drop.

import type { ResolvedWindow, WindowSelection } from "../../src/lib/types.ts";

const WINDOW_CHOICES_MIN = [15, 30, 60, 120, 240];
const INTERVAL_CHOICES_MIN = [1, 5, 10, 60];

const MIN_BUCKETS = 4;
const MAX_BUCKETS = 250;

const DEFAULT_WINDOW: WindowSelection = { windowMin: 60, intervalMin: 1 };

function validIntervals(windowMin: number): number[] {
  return INTERVAL_CHOICES_MIN.filter((i) => {
    if (windowMin % i !== 0) return false;
    const b = windowMin / i;
    return b >= MIN_BUCKETS && b <= MAX_BUCKETS;
  });
}

function windowLabel(windowMin: number): string {
  return windowMin % 60 === 0 ? `${windowMin / 60}h` : `${windowMin}m`;
}

/**
 * Turns a selection into concrete bounds. Invalid input is corrected rather than
 * rejected — a stale bookmark should still render, and the correction is visible
 * because the resolved window is what the UI labels.
 */
export function resolveWindow(
  sel: WindowSelection | null | undefined,
  nowMs: number,
): ResolvedWindow {
  const windowMin =
    sel && WINDOW_CHOICES_MIN.includes(sel.windowMin) ? sel.windowMin : DEFAULT_WINDOW.windowMin;

  const allowed = validIntervals(windowMin);
  let intervalMin = allowed[0] ?? 1;
  if (sel && allowed.includes(sel.intervalMin)) intervalMin = sel.intervalMin;

  const intervalMs = intervalMin * 60_000;
  const endMs = Math.floor(nowMs / intervalMs) * intervalMs;
  return {
    windowMin,
    intervalMin,
    startMs: endMs - windowMin * 60_000,
    endMs,
    buckets: windowMin / intervalMin,
    label: `${windowLabel(windowMin)} / ${intervalMin}m`,
  };
}
