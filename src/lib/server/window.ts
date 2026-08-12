import "server-only";

// The one time window every panel reads. Before this, each source picked its
// own: metrics looked back 14 minutes, WAF sampled 15, the WAF log aggregation
// hardcoded 15, pod logs took whatever the Insights default was. Numbers from
// two panels could not be compared because nobody said what span they covered.
//
// Now the window is chosen once, validated here, and passed down. The rules:
//
//   - The span is capped at 4 hours. Insights bills per byte scanned, so the
//     cap bounds cost structurally rather than by asking people to be careful.
//   - Only span/interval pairs producing 4..250 buckets are offered. Fewer than
//     four buckets is not a trend; more than 250 is unreadable and expensive.
//   - The end is floored to an interval boundary, so every bucket in the window
//     is a complete bucket. A partial trailing bucket reads as a sudden drop.

import type { ResolvedWindow, WindowSelection } from "@/lib/types";

export const WINDOW_CHOICES_MIN = [15, 30, 60, 120, 240] as const;
export const INTERVAL_CHOICES_MIN = [1, 5, 10, 60] as const;

const MIN_BUCKETS = 4;
const MAX_BUCKETS = 250;

export const DEFAULT_WINDOW: WindowSelection = { windowMin: 60, intervalMin: 1 };

// The intervals that yield a readable bucket count for this span. The UI only
// offers these; the server rejects anything else.
export function validIntervals(windowMin: number): number[] {
  return INTERVAL_CHOICES_MIN.filter((i) => {
    if (windowMin % i !== 0) return false;
    const buckets = windowMin / i;
    return buckets >= MIN_BUCKETS && buckets <= MAX_BUCKETS;
  });
}

function label(windowMin: number): string {
  return windowMin % 60 === 0 ? `${windowMin / 60}h` : `${windowMin}m`;
}

// Resolves a selection into concrete bounds. Invalid input is corrected rather
// than rejected — a stale bookmark or an old client should still render, and
// the correction is visible because the resolved window is what the UI labels.
export function resolveWindow(sel: WindowSelection | undefined, nowMs: number): ResolvedWindow {
  const windowMin = (WINDOW_CHOICES_MIN as readonly number[]).includes(sel?.windowMin ?? 0)
    ? (sel?.windowMin ?? DEFAULT_WINDOW.windowMin)
    : DEFAULT_WINDOW.windowMin;
  const allowed = validIntervals(windowMin);
  const intervalMin =
    sel?.intervalMin !== undefined && allowed.includes(sel.intervalMin)
      ? sel.intervalMin
      : (allowed[0] ?? 1);

  const intervalMs = intervalMin * 60_000;
  // Floor to an interval boundary so the last bucket is complete.
  const endMs = Math.floor(nowMs / intervalMs) * intervalMs;
  const startMs = endMs - windowMin * 60_000;

  return {
    windowMin,
    intervalMin,
    startMs,
    endMs,
    buckets: windowMin / intervalMin,
    label: `${label(windowMin)} / ${intervalMin}m`,
  };
}

// Cache keys have to change when the window does, or a panel serves the
// previous span's numbers under the new label.
export function windowKey(w: ResolvedWindow): string {
  return `${w.windowMin}-${w.intervalMin}-${w.endMs}`;
}
