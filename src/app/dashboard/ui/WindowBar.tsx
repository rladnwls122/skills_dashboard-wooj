"use client";

import type { ResolvedWindow, WindowSelection } from "@/lib/types";
import { LastUpdated } from "./shared";

// The one control that decides what span every panel on the page covers.
//
// The ranges are buttons rather than a dropdown because the current value has
// to be readable without opening anything — this is the caption for every
// number on screen, and a collapsed <select> hides it behind a click.
//
// Four hours is the largest span offered, and the cap is visible here rather
// than discovered as a server error: Logs Insights bills per byte scanned, so
// the limit is a cost decision, not a validation rule.

const WINDOW_CHOICES = [15, 30, 60, 120, 240] as const;
const INTERVAL_CHOICES = [1, 5, 10, 60] as const;
const REFRESH_CHOICES = [5, 10, 15, 20, 25, 30] as const;

// Mirrors server/window.ts. The server validates and corrects whatever
// arrives, so a mismatch degrades to a corrected window — but offering an
// invalid pair would still be a lie about what the page can show.
export function intervalsFor(windowMin: number): number[] {
  return INTERVAL_CHOICES.filter((i) => {
    if (windowMin % i !== 0) return false;
    const buckets = windowMin / i;
    return buckets >= 4 && buckets <= 250;
  });
}

function rangeLabel(min: number): string {
  return min % 60 === 0 ? `${min / 60}h` : `${min}m`;
}

function stamp(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${pad(d.getMonth() + 1)}.${pad(d.getDate())}. ${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}:${pad(d.getSeconds())}`;
}

export function WindowBar({
  window: win,
  onChange,
  // The window the server actually resolved — its bounds are floored to a
  // bucket boundary, so they are not derivable from the selection and the
  // wall clock. Null until the first load.
  resolved,
  refreshSec,
  onRefreshSec,
  onRefresh,
  lastUpdated,
  busy,
}: {
  window: WindowSelection;
  onChange: (w: WindowSelection) => void;
  resolved: ResolvedWindow | null;
  refreshSec: number;
  onRefreshSec: (s: number) => void;
  onRefresh: () => void;
  lastUpdated: number | null;
  busy?: boolean;
}) {
  const setRange = (windowMin: number): void => {
    const allowed = intervalsFor(windowMin);
    // Keep the interval when the new span still offers it; otherwise take the
    // finest one it allows.
    const intervalMin = allowed.includes(win.intervalMin) ? win.intervalMin : (allowed[0] ?? 1);
    onChange({ windowMin, intervalMin });
  };

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <div role="group" aria-label="조회 기간" className="flex overflow-hidden rounded-[4px] border border-neutral-800">
        {WINDOW_CHOICES.map((m) => (
          <button
            key={m}
            type="button"
            aria-pressed={win.windowMin === m}
            onClick={() => setRange(m)}
            className={`px-2 py-1 font-mono text-[11px] tabular-nums transition-colors ${
              win.windowMin === m
                ? "bg-sky-900 text-sky-100"
                : "bg-neutral-900 text-neutral-500 hover:bg-neutral-800 hover:text-neutral-300"
            }`}
          >
            {rangeLabel(m)}
          </button>
        ))}
      </div>

      <label className="flex items-center gap-1 font-mono text-[10px] text-neutral-500">
        간격
        <select
          value={win.intervalMin}
          onChange={(e) => onChange({ ...win, intervalMin: Number(e.target.value) })}
          className="rounded-[4px] border border-neutral-800 bg-neutral-900 px-1.5 py-1 font-mono text-[11px] text-neutral-300"
        >
          {intervalsFor(win.windowMin).map((m) => (
            <option key={m} value={m}>
              {m}분
            </option>
          ))}
        </select>
      </label>

      <label className="flex items-center gap-1 font-mono text-[10px] text-neutral-500">
        갱신
        <select
          value={refreshSec}
          onChange={(e) => onRefreshSec(Number(e.target.value))}
          className="rounded-[4px] border border-neutral-800 bg-neutral-900 px-1.5 py-1 font-mono text-[11px] text-neutral-300"
        >
          {REFRESH_CHOICES.map((s) => (
            <option key={s} value={s}>
              {s}초
            </option>
          ))}
        </select>
      </label>

      <button
        type="button"
        onClick={onRefresh}
        disabled={busy}
        title="지금 새로고침"
        className="rounded-[4px] border border-neutral-800 bg-neutral-900 px-2 py-1 font-mono text-[11px] text-neutral-300 hover:bg-neutral-800 hover:text-neutral-100 disabled:opacity-40"
      >
        ⟳ 새로고침
      </button>

      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <LastUpdated at={lastUpdated} />
        {/* "1h / 1m" says how wide the window is, never where it sits. Two
            operators comparing screens, or a screen against a log, need the
            wall-clock bounds. */}
        {resolved && (
          <span className="font-mono text-[10px] tabular-nums text-neutral-600">
            {stamp(resolved.startMs)} ~ {stamp(resolved.endMs)} · {resolved.intervalMin * 60}초 버킷
            · {resolved.buckets}개
          </span>
        )}
      </div>
    </div>
  );
}
