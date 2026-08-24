// The arithmetic behind the node-count panel — the one grader input this
// dashboard can count itself.
//
// The cost score is computed from how many instances were running during the
// scoring window (match start +1h to +3h), sampled every few minutes. The
// formula from count to score is sealed, so this module produces counts and
// never a score.
//
// Everything here is pure: the AWS reads live in awsx, the samples come from
// SQLite, and this is the part that can be reasoned about without either.

import type { InstanceRow, OffSpecInstance, ScoringWindow } from "../../src/lib/types.ts";
import type { CloudTrailEvent } from "../types/types.ts";

/** The scoring window opens an hour after the match starts and runs for two. */
export const WINDOW_OFFSET_MS = 60 * 60_000;
export const WINDOW_LENGTH_MS = 2 * 60 * 60_000;
/**
 * The only instance type the 2025 task sheet allows for workload hosts
 * ("EC2 인스턴스는 c5.large 타입만"). Overridable with ALLOWED_INSTANCE_TYPE
 * for a variant of the task that names another type.
 */
export const DEFAULT_ALLOWED_TYPE = "c5.large";
/**
 * Readings are floored to a 30s grid, matching the poll interval. The primary
 * key is (key, t), so the floor makes repeated writes inside one bucket
 * idempotent instead of accumulating rows.
 */
export const GRID_MS = 30_000;
/** The metric_samples key the readings are stored under. */
export const SAMPLE_KEY = "nodes:count";

export interface Sample {
  t: number;
  v: number;
}

// --- match start and the window it implies -----------------------------------

const HHMM_RE = /^(\d{1,2}):(\d{2})$/;
const FULL_RE = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})/;

/**
 * Accepts what a person types under time pressure: "2026-08-14 09:00",
 * "2026-08-14T09:00", or a bare "09:00" meaning today. Interpreted in the
 * machine's local time, which is the clock the operator is reading.
 */
export function parseMatchStart(raw: string, nowMs: number): number | null {
  const s = raw.trim();
  if (s === "") return null;

  const hhmm = HHMM_RE.exec(s);
  if (hhmm) {
    const now = new Date(nowMs);
    return new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
      Number(hhmm[1]),
      Number(hhmm[2]),
      0,
      0,
    ).getTime();
  }

  const full = FULL_RE.exec(s);
  if (full) {
    return new Date(
      Number(full[1]),
      Number(full[2]) - 1,
      Number(full[3]),
      Number(full[4]),
      Number(full[5]),
      0,
      0,
    ).getTime();
  }

  const parsed = Date.parse(s);
  return Number.isFinite(parsed) ? parsed : null;
}

export function window(startMs: number): ScoringWindow {
  return {
    startMs: startMs + WINDOW_OFFSET_MS,
    endMs: startMs + WINDOW_OFFSET_MS + WINDOW_LENGTH_MS,
  };
}

// --- the arithmetic ----------------------------------------------------------

/**
 * The mean of a step function. Samples are readings, not events: a value holds
 * until the next one replaces it, so a five-minute stretch at 6 nodes weighs
 * five times a one-minute stretch at 6.
 *
 * A plain mean of the samples would be wrong whenever the poll interval is
 * uneven — which it is, because the dashboard gets closed and reopened.
 */
export function timeWeightedAvg(
  samples: Sample[],
  fromMs: number,
  toMs: number,
): number | null {
  if (toMs <= fromMs) return null;
  const sorted = [...samples].sort((a, b) => a.t - b.t);

  // The value in effect when the window opens is the last reading at or before
  // it, not the first reading inside it.
  let cur: number | null = null;
  const inside: Sample[] = [];
  for (const s of sorted) {
    if (s.t <= fromMs) cur = s.v;
    else if (s.t < toMs) inside.push(s);
  }
  if (cur === null) {
    if (inside.length === 0) return null;
    // Nothing was recorded before the window opened. Holding the first reading
    // backwards is the only assumption available; backfill normally makes this
    // branch unreachable.
    cur = inside[0]!.v;
  }

  let area = 0;
  let prevT = fromMs;
  for (const s of inside) {
    area += cur * (s.t - prevT);
    cur = s.v;
    prevT = s.t;
  }
  area += cur * (toMs - prevT);
  return area / (toMs - fromMs);
}

/** The part of the panel that is arithmetic rather than a reading. */
export interface Projection {
  current: number | null;
  elapsedMin: number | null;
  remainingMin: number | null;
  cumulativeAvg: number | null;
  finalAvg: number | null;
  marginalPerInstance: number | null;
}

/**
 * What the window average lands on if the current count is held to the end, and
 * how much one instance moves it.
 *
 *   final    = (cumulative × elapsed + current × remaining) / W
 *   marginal = remaining / W
 *
 * The marginal term is the number the scaling decision actually turns on: the
 * same instance costs less the later it is added, and near the end of the window
 * it costs almost nothing.
 */
export function project(
  samples: Sample[],
  current: number | null,
  win: ScoringWindow,
  nowMs: number,
): Projection {
  const w = win.endMs - win.startMs;
  const clampedNow = Math.min(Math.max(nowMs, win.startMs), win.endMs);
  const elapsed = clampedNow - win.startMs;
  const remaining = w - elapsed;

  const cumulative = elapsed > 0 ? timeWeightedAvg(samples, win.startMs, clampedNow) : null;
  const base = cumulative ?? (current !== null ? current : null);

  return {
    current,
    elapsedMin: Math.round(elapsed / 60_000),
    remainingMin: Math.round(remaining / 60_000),
    cumulativeAvg: cumulative,
    finalAvg:
      current !== null && base !== null ? (base * elapsed + current * remaining) / w : null,
    marginalPerInstance: remaining / w,
  };
}

/**
 * The one EC2 type the task permits — the environment can override the
 * task-sheet default when a variant names another.
 */
export function allowedInstanceType(): string {
  return (process.env.ALLOWED_INSTANCE_TYPE ?? "").trim() || DEFAULT_ALLOWED_TYPE;
}

/**
 * Anything outside what the task allows. Existence alone is a penalty, so this
 * reports facts (type, region, no cluster tag) and not a judgement about how bad
 * they are.
 */
export function offSpec(rows: InstanceRow[], region: string): OffSpecInstance[] {
  const out: OffSpecInstance[] = [];
  const allowed = allowedInstanceType();
  for (const r of rows) {
    const reasons: string[] = [];
    if (r.type !== "" && r.type !== allowed) reasons.push("타입 " + r.type);
    if (r.az !== "" && !r.az.startsWith(region)) reasons.push("리전 " + r.az);
    if (r.clusterTag === null) reasons.push("클러스터에 속하지 않음");
    if (reasons.length > 0) out.push({ ...r, reason: reasons.join(" · ") });
  }
  return out;
}

// --- backfill ----------------------------------------------------------------

export interface TrailDelta {
  t: number;
  delta: number;
}

/**
 * Turns CloudTrail's event stream into count deltas. One RunInstances can launch
 * several instances, so the delta is the size of the instance set, not one per
 * event.
 */
export function parseTrailEvents(events: CloudTrailEvent[]): TrailDelta[] {
  const out: TrailDelta[] = [];
  for (const e of events) {
    let sign = 0;
    if (e.name === "RunInstances") sign = 1;
    else if (e.name === "TerminateInstances") sign = -1;
    if (sign === 0 || e.tsMs === 0) continue;

    let n = 1;
    // A malformed event body still tells us one instance moved. Dropping the
    // event entirely would understate the count for the rest of the window.
    try {
      const body = JSON.parse(e.body) as {
        responseElements?: { instancesSet?: { items?: unknown[] } };
      };
      const count = body.responseElements?.instancesSet?.items?.length ?? 0;
      if (count > 0) n = count;
    } catch {
      // keep n = 1
    }
    out.push({ t: e.tsMs, delta: sign * n });
  }
  return out;
}

/**
 * Walks the count backwards from a known present value.
 *
 * n(now) is what describe-instances just said. For an event at t with delta d,
 * the count immediately before t is (count after t) − d. Emitting a sample at
 * each event time gives the same step function the live poller would have
 * recorded had it been running.
 */
export function reconstruct(
  deltas: TrailDelta[],
  currentCount: number,
  fromMs: number,
  nowMs: number,
): Sample[] {
  const desc = deltas
    .filter((d) => d.t > fromMs && d.t <= nowMs)
    .sort((a, b) => b.t - a.t);

  const out: Sample[] = [{ t: nowMs, v: currentCount }];
  let cur = currentCount;
  for (const d of desc) {
    out.push({ t: d.t, v: cur });
    cur -= d.delta;
  }
  out.push({ t: fromMs, v: cur });

  // Counts cannot be negative. A negative here means CloudTrail and
  // describe-instances disagree — usually an instance terminated outside the
  // lookup window — and clamping is closer to the truth than a negative node.
  for (const s of out) {
    if (s.v < 0) s.v = 0;
  }
  out.sort((a, b) => a.t - b.t);
  return out;
}
