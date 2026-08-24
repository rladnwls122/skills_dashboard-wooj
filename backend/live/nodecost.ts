// Node count over the scoring window — the reading, the recording and the
// one-shot backfill. The arithmetic is in backend/nodecost.

import { errMsg } from "../awsx/clients.ts";
import { describeRunningInstances, lookupInstanceEvents } from "../awsx/nodecount.ts";
import {
  GRID_MS,
  offSpec as computeOffSpec,
  parseMatchStart,
  parseTrailEvents,
  project,
  reconstruct,
  SAMPLE_KEY,
  window as scoringWindow,
  type Sample,
} from "../nodecost/nodecost.ts";
import type { NodeCountProjection, ScoringWindow } from "../../src/lib/types.ts";
import type { LiveProvider } from "./live.ts";

/**
 * Backfill runs once per process, on the first read that has a window to fill. A
 * button would leave the panel quietly wrong until someone remembered to press
 * it; a retry loop would re-scan CloudTrail every 30s for an error that is
 * almost always a missing permission.
 */
export class BackfillState {
  attempted = false;
  note = "";
  /** One flight at a time, so two concurrent panel reads share the scan. */
  inflight: Promise<string> | null = null;
}

function recordNodeCount(p: LiveProvider, count: number, nowMs: number): void {
  const t = Math.floor(nowMs / GRID_MS) * GRID_MS;
  // Recording must never take the panel down: the count on screen is a live
  // reading, and only the cumulative average depends on the row landing.
  try {
    p.store.saveMetricSamples(SAMPLE_KEY, [{ t, v: count }]);
  } catch {
    // ignored
  }
}

function loadNodeSamples(p: LiveProvider, fromMs: number): Sample[] {
  try {
    return p.store.loadMetricSamples(SAMPLE_KEY, fromMs);
  } catch {
    return [];
  }
}

/**
 * Fills the stretches the dashboard was not running for, from CloudTrail's
 * RunInstances/TerminateInstances history.
 */
function backfillOnce(
  p: LiveProvider,
  win: ScoringWindow,
  current: number,
  nowMs: number,
): Promise<string> {
  const state = p.backfill;
  if (state.attempted) return Promise.resolve(state.note);
  if (state.inflight) return state.inflight;

  const from = win.startMs;
  const to = Math.min(win.endMs, nowMs);
  // Nothing to reconstruct yet — the scoring window has not opened. Marking the
  // one-shot as spent here would mean the stretch before the dashboard was
  // opened is never backfilled once the window does open, and the cumulative
  // average would silently cover only the minutes this screen happened to be
  // running. So: no attempt was made, and none is recorded.
  if (to <= from) return Promise.resolve("");

  state.attempted = true;

  const flight = (async () => {
    try {
      const runs = await lookupInstanceEvents(p.aws, "RunInstances", from, to);
      const terms = await lookupInstanceEvents(p.aws, "TerminateInstances", from, to);
      const samples = reconstruct(parseTrailEvents([...runs, ...terms]), current, from, to);
      // saveMetricSamples prunes rows older than 6h, which covers a 3h match. A
      // window that opened longer ago than that cannot be backfilled.
      p.store.saveMetricSamples(SAMPLE_KEY, samples);
      return "";
    } catch (e) {
      state.note =
        "CloudTrail 조회에 실패해 대시보드가 꺼져 있던 구간을 메우지 못했습니다 (" +
        errMsg(e) +
        "). 누적 평균은 이 화면이 켜져 있던 구간만 반영합니다.";
      return state.note;
    } finally {
      state.inflight = null;
    }
  })();
  state.inflight = flight;
  return flight;
}

/**
 * One call for the whole panel. It records the live reading as a side effect so
 * the caller does not need a second scheduler for it.
 */
export async function nodeCost(p: LiveProvider): Promise<NodeCountProjection> {
  const rows = await describeRunningInstances(p.aws);
  const inCluster = rows.filter((r) => r.clusterTag !== null).length;
  const nowMs = p.now();
  recordNodeCount(p, inCluster, nowMs);

  const offSpec = computeOffSpec(rows, p.settings.region());
  const startMs = parseMatchStart(p.settings.value("MATCH_START"), nowMs);
  if (startMs === null) {
    // No match start: the count is real, the average is not computable, and the
    // panel says so rather than showing a provisional figure.
    return {
      window: null,
      current: inCluster,
      elapsedMin: null,
      remainingMin: null,
      cumulativeAvg: null,
      finalAvg: null,
      marginalPerInstance: null,
      offSpec,
      notes: [
        "경기 시작 시각이 설정되지 않아 채점 창 평균을 계산하지 않습니다. 설정에서 MATCH_START 를 입력하세요.",
      ],
    };
  }

  const win = scoringWindow(startMs);
  const notes: string[] = [];
  const note = await backfillOnce(p, win, inCluster, nowMs);
  if (note !== "") notes.push(note);
  if (nowMs < win.startMs) notes.push("채점 창이 아직 시작되지 않았습니다.");
  if (nowMs > win.endMs) notes.push("채점 창이 끝났습니다. 값은 확정입니다.");

  const proj = project(loadNodeSamples(p, win.startMs), inCluster, win, nowMs);
  return {
    window: win,
    current: proj.current,
    elapsedMin: proj.elapsedMin,
    remainingMin: proj.remainingMin,
    cumulativeAvg: proj.cumulativeAvg,
    finalAvg: proj.finalAvg,
    marginalPerInstance: proj.marginalPerInstance,
    offSpec,
    notes,
  };
}
