import "server-only";

// Node count over the scoring window — the one grader input we can count
// ourselves.
//
// The cost score is computed from how many instances were running during the
// scoring window (match start +1h to +3h), sampled every few minutes. The
// formula from count to score is sealed, so this module produces counts and
// never a score.
//
// Two sources, deliberately:
//   - `describe-instances` every 30s is the live number, and the same response
//     answers the off-spec question (type, region, unattached) without a
//     second call.
//   - CloudTrail RunInstances/TerminateInstances reconstructs the stretches the
//     dashboard was not running for. It needs no prior setup, retains 90 days,
//     and — unlike the AutoScaling group metrics — does not miss Karpenter
//     nodes, which belong to no ASG at all.

import { DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import type { Instance } from "@aws-sdk/client-ec2";
import { LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { cloudTrailClient, ec2Client } from "./aws";
import { ENV } from "./config";
import { loadMetricSamples, saveMetricSamples } from "./db";
import { value } from "./settings";

// The scoring window opens an hour after the match starts and runs for two.
const WINDOW_OFFSET_MS = 60 * 60_000;
const WINDOW_LENGTH_MS = 2 * 60 * 60_000;

// The only instance type the task allows for workload nodes.
const ALLOWED_TYPE = "t3.medium";

const SAMPLE_KEY = "nodes:count";
// Readings are floored to a 30s grid, matching the poll interval. The primary
// key is (key, t), so the floor makes repeated writes inside one bucket
// idempotent instead of accumulating rows.
const GRID_MS = 30_000;

export interface NodeSample {
  t: number;
  v: number;
}

export interface ScoringWindow {
  startMs: number;
  endMs: number;
}

export interface InstanceRow {
  id: string;
  type: string;
  az: string;
  name: string | null;
  // The `kubernetes.io/cluster/<name>` tag both EKS managed nodegroups and
  // Karpenter put on the instances they create. Absent means the instance is
  // running outside the cluster.
  clusterTag: string | null;
  launchedMs: number | null;
}

export interface OffSpecInstance extends InstanceRow {
  reason: string;
}

export interface NodeCountProjection {
  // null when the match start time has not been set — see `matchStartMs`.
  window: ScoringWindow | null;
  current: number | null;
  elapsedMin: number | null;
  remainingMin: number | null;
  cumulativeAvg: number | null;
  finalAvg: number | null;
  // How much the final average moves if one instance is added or removed now.
  marginalPerInstance: number | null;
  offSpec: OffSpecInstance[];
  notes: string[];
}

// --- match start and the window it implies ---------------------------------

// Accepts what a person types under time pressure: "2026-08-14 09:00",
// "2026-08-14T09:00", or a bare "09:00" meaning today. Interpreted in the
// machine's local time, which is the clock the operator is reading.
export function parseMatchStart(raw: string, nowMs: number): number | null {
  const s = raw.trim();
  if (!s) return null;

  const hhmm = /^(\d{1,2}):(\d{2})$/.exec(s);
  if (hhmm) {
    const d = new Date(nowMs);
    d.setHours(Number(hhmm[1]), Number(hhmm[2]), 0, 0);
    return d.getTime();
  }

  const full = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})/.exec(s);
  if (full) {
    const d = new Date(
      Number(full[1]),
      Number(full[2]) - 1,
      Number(full[3]),
      Number(full[4]),
      Number(full[5]),
      0,
      0,
    );
    return d.getTime();
  }

  const parsed = Date.parse(s);
  return Number.isFinite(parsed) ? parsed : null;
}

export function matchStartMs(nowMs: number): number | null {
  return parseMatchStart(value("MATCH_START"), nowMs);
}

export function scoringWindow(startMs: number): ScoringWindow {
  return {
    startMs: startMs + WINDOW_OFFSET_MS,
    endMs: startMs + WINDOW_OFFSET_MS + WINDOW_LENGTH_MS,
  };
}

// --- the arithmetic --------------------------------------------------------

// Time-weighted mean of a step function. Samples are readings, not events: a
// value holds until the next one replaces it, so a five-minute stretch at 6
// nodes weighs five times a one-minute stretch at 6.
//
// A plain mean of the samples would be wrong whenever the poll interval is
// uneven — which it is, because the dashboard gets closed and reopened.
export function timeWeightedAvg(
  samples: NodeSample[],
  fromMs: number,
  toMs: number,
): number | null {
  if (toMs <= fromMs) return null;
  const sorted = [...samples].sort((a, b) => a.t - b.t);

  // The value in effect when the window opens is the last reading at or before
  // it, not the first reading inside it.
  let cur: number | null = null;
  for (const s of sorted) {
    if (s.t <= fromMs) cur = s.v;
    else break;
  }
  const inside = sorted.filter((s) => s.t > fromMs && s.t < toMs);
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

// What the window average lands on if the current count is held to the end,
// and how much one instance moves it.
//
//   final    = (cumulative × elapsed + current × remaining) / W
//   marginal = remaining / W
//
// The marginal term is the number the scaling decision actually turns on: the
// same instance costs less the later it is added, and near the end of the
// window it costs almost nothing.
export function project(
  samples: NodeSample[],
  current: number | null,
  win: ScoringWindow,
  nowMs: number,
): Omit<NodeCountProjection, "offSpec" | "window" | "notes"> {
  const w = win.endMs - win.startMs;
  const clampedNow = Math.min(Math.max(nowMs, win.startMs), win.endMs);
  const elapsed = clampedNow - win.startMs;
  const remaining = w - elapsed;

  const cumulativeAvg = elapsed > 0 ? timeWeightedAvg(samples, win.startMs, clampedNow) : null;
  const base = cumulativeAvg ?? current;

  const finalAvg =
    current === null || base === null ? null : (base * elapsed + current * remaining) / w;

  return {
    current,
    elapsedMin: Math.round(elapsed / 60_000),
    remainingMin: Math.round(remaining / 60_000),
    cumulativeAvg,
    finalAvg,
    marginalPerInstance: remaining / w,
  };
}

// --- live reading ----------------------------------------------------------

function tagOf(inst: Instance, predicate: (key: string) => boolean): string | null {
  for (const t of inst.Tags ?? []) {
    if (t.Key && predicate(t.Key)) return t.Value ?? "";
  }
  return null;
}

export function toInstanceRow(inst: Instance): InstanceRow {
  return {
    id: inst.InstanceId ?? "",
    type: inst.InstanceType ?? "",
    az: inst.Placement?.AvailabilityZone ?? "",
    name: tagOf(inst, (k) => k === "Name"),
    clusterTag: tagOf(inst, (k) => k.startsWith("kubernetes.io/cluster/")),
    launchedMs: inst.LaunchTime ? inst.LaunchTime.getTime() : null,
  };
}

// Running instances, paginated. The state filter is server-side on purpose:
// without it every terminated instance from the last hour comes back and eats
// the page budget.
export async function describeRunningInstances(): Promise<InstanceRow[]> {
  const client = ec2Client();
  const rows: InstanceRow[] = [];
  let token: string | undefined;
  do {
    const res = await client.send(
      new DescribeInstancesCommand({
        Filters: [{ Name: "instance-state-name", Values: ["running"] }],
        NextToken: token,
      }),
    );
    for (const r of res.Reservations ?? []) {
      for (const i of r.Instances ?? []) rows.push(toInstanceRow(i));
    }
    token = res.NextToken;
  } while (token);
  return rows;
}

// Anything outside what the task allows. Existence alone is a penalty, so this
// reports facts (type, region, no cluster tag) and not a judgement about how
// bad they are.
export function offSpec(rows: InstanceRow[], region: string): OffSpecInstance[] {
  const out: OffSpecInstance[] = [];
  for (const r of rows) {
    const reasons: string[] = [];
    if (r.type && r.type !== ALLOWED_TYPE) reasons.push(`타입 ${r.type}`);
    if (r.az && !r.az.startsWith(region)) reasons.push(`리전 ${r.az}`);
    if (r.clusterTag === null) reasons.push("클러스터에 속하지 않음");
    if (reasons.length > 0) out.push({ ...r, reason: reasons.join(" · ") });
  }
  return out;
}

export function recordNodeCount(count: number, nowMs: number): void {
  const t = Math.floor(nowMs / GRID_MS) * GRID_MS;
  saveMetricSamples(SAMPLE_KEY, [{ t, v: count }]);
}

export function loadNodeSamples(fromMs: number): NodeSample[] {
  return loadMetricSamples(SAMPLE_KEY, fromMs);
}

// --- backfill --------------------------------------------------------------

interface TrailDelta {
  t: number;
  delta: number;
}

// Turns CloudTrail's event stream into count deltas. One RunInstances can
// launch several instances, so the delta is the size of the instance set, not
// one per event.
export function parseTrailEvents(
  events: { EventName?: string; EventTime?: Date; CloudTrailEvent?: string }[],
): TrailDelta[] {
  const out: TrailDelta[] = [];
  for (const e of events) {
    if (!e.EventTime) continue;
    const sign = e.EventName === "RunInstances" ? 1 : e.EventName === "TerminateInstances" ? -1 : 0;
    if (sign === 0) continue;
    let n = 1;
    try {
      const parsed = JSON.parse(e.CloudTrailEvent ?? "{}");
      const items = parsed?.responseElements?.instancesSet?.items;
      if (Array.isArray(items) && items.length > 0) n = items.length;
    } catch {
      // A malformed event body still tells us one instance moved. Dropping the
      // event entirely would understate the count for the rest of the window.
    }
    out.push({ t: e.EventTime.getTime(), delta: sign * n });
  }
  return out;
}

// Walks the count backwards from a known present value.
//
// n(now) is what describe-instances just said. For an event at t with delta d,
// the count immediately before t is (count after t) − d. Emitting a sample at
// each event time gives the same step function the live poller would have
// recorded had it been running.
export function reconstruct(
  deltas: TrailDelta[],
  currentCount: number,
  fromMs: number,
  nowMs: number,
): NodeSample[] {
  const desc = [...deltas]
    .filter((d) => d.t > fromMs && d.t <= nowMs)
    .sort((a, b) => b.t - a.t);

  const out: NodeSample[] = [{ t: nowMs, v: currentCount }];
  let cur = currentCount;
  for (const d of desc) {
    out.push({ t: d.t, v: cur });
    cur = cur - d.delta;
  }
  out.push({ t: fromMs, v: cur });

  // Counts cannot be negative. A negative here means CloudTrail and
  // describe-instances disagree — usually an instance terminated outside the
  // lookup window — and clamping is closer to the truth than a negative node.
  return out.map((s) => ({ ...s, v: Math.max(0, s.v) })).sort((a, b) => a.t - b.t);
}

async function lookup(
  eventName: string,
  fromMs: number,
  toMs: number,
): Promise<{ EventName?: string; EventTime?: Date; CloudTrailEvent?: string }[]> {
  const client = cloudTrailClient();
  const out: { EventName?: string; EventTime?: Date; CloudTrailEvent?: string }[] = [];
  let token: string | undefined;
  do {
    const res = await client.send(
      new LookupEventsCommand({
        LookupAttributes: [{ AttributeKey: "EventName", AttributeValue: eventName }],
        StartTime: new Date(fromMs),
        EndTime: new Date(toMs),
        NextToken: token,
      }),
    );
    for (const e of res.Events ?? []) out.push(e);
    token = res.NextToken;
  } while (token);
  return out;
}

// Fills the stretches the dashboard was not running for. Called once at
// startup — a button would mean the panel is quietly wrong until someone
// remembers to press it.
//
// ponytail: two sequential LookupEvents calls, not parallel. The API is capped
// at 2 TPS and the whole window is tens of events; parallelise only if the
// event count ever makes this slow.
export async function backfillFromCloudTrail(
  win: ScoringWindow,
  currentCount: number,
  nowMs: number,
): Promise<NodeSample[]> {
  const from = win.startMs;
  const to = Math.min(nowMs, win.endMs);
  if (to <= from) return [];

  const runs = await lookup("RunInstances", from, to);
  const terms = await lookup("TerminateInstances", from, to);
  const samples = reconstruct(parseTrailEvents([...runs, ...terms]), currentCount, from, to);

  // ponytail: saveMetricSamples prunes rows older than 6h, which covers a 3h
  // match. A window that opened longer ago than that cannot be backfilled —
  // raise the prune horizon if this is ever used outside a contest day.
  saveMetricSamples(SAMPLE_KEY, samples);
  return samples;
}

// --- panel -----------------------------------------------------------------

// Backfill runs once per process, on the first read that has a window to fill.
// A button would leave the panel quietly wrong until someone remembered to
// press it; a retry loop would re-scan CloudTrail every 30s for an error that
// is almost always a missing permission.
let backfillAttempted = false;
let backfillNote: string | null = null;

async function backfillOnce(win: ScoringWindow, current: number, nowMs: number): Promise<void> {
  if (backfillAttempted) return;
  backfillAttempted = true;
  try {
    await backfillFromCloudTrail(win, current, nowMs);
  } catch (e) {
    backfillNote = `CloudTrail 조회에 실패해 대시보드가 꺼져 있던 구간을 메우지 못했습니다 (${
      e instanceof Error ? e.message : String(e)
    }). 누적 평균은 이 화면이 켜져 있던 구간만 반영합니다.`;
  }
}

// One call for the whole panel. Records the live reading as a side effect so
// the caller does not need a second scheduler for it.
export async function nodeCountPanel(nowMs: number = Date.now()): Promise<NodeCountProjection> {
  const rows = await describeRunningInstances();
  const inCluster = rows.filter((r) => r.clusterTag !== null);
  const current = inCluster.length;
  recordNodeCount(current, nowMs);

  const start = matchStartMs(nowMs);
  const spec = offSpec(rows, ENV.region);
  if (start === null) {
    // No match start: the count is real, the average is not computable, and
    // the panel says so rather than showing a provisional figure.
    return {
      window: null,
      current,
      elapsedMin: null,
      remainingMin: null,
      cumulativeAvg: null,
      finalAvg: null,
      marginalPerInstance: null,
      offSpec: spec,
      notes: ["경기 시작 시각이 설정되지 않아 채점 창 평균을 계산하지 않습니다. 톱니에서 입력하세요."],
    };
  }

  const win = scoringWindow(start);
  await backfillOnce(win, current, nowMs);
  const samples = loadNodeSamples(win.startMs);
  const notes: string[] = [];
  if (backfillNote) notes.push(backfillNote);
  if (nowMs < win.startMs) notes.push("채점 창이 아직 시작되지 않았습니다.");
  if (nowMs > win.endMs) notes.push("채점 창이 끝났습니다. 값은 확정입니다.");
  return { window: win, ...project(samples, current, win, nowMs), offSpec: spec, notes };
}
