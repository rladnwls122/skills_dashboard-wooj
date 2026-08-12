import "server-only";

// Pod and node resource usage over time.
//
// metrics.k8s.io answers one question — "what is it right now" — and keeps no
// history, so a usage bar can show 95% without saying whether that is a spike
// or the last forty minutes. CloudWatch would know, but Container Insights is
// not enabled here. So the dashboard keeps its own: every kube poll appends the
// current reading to the same SQLite table the CloudWatch samples already use,
// and the charts read it back over the page's shared window.
//
// This is a recording, not a metrics system. It only has what this dashboard
// happened to be running for — a gap in the line means nobody was watching, and
// the panel says so rather than drawing through it.

import { loadMetricSamples, listMetricKeys, saveMetricSamples } from "./db";
import type {
  MetricPoint,
  NamedSeries,
  NodeResourceUsage,
  PodResourceUsage,
  ResolvedWindow,
  ResourceHistory,
} from "@/lib/types";

const PREFIX = "res:";

// Readings are floored to a 10-second grid. The kube panel polls every 3s, and
// three rows per pod per 10 seconds is detail nobody reads at the cost of three
// times the table. The primary key is (key, t), so the floor also makes the
// repeated writes within one bucket idempotent instead of accumulating.
const GRID_MS = 10_000;

export type ResourceKind = "pod" | "node";
export type ResourceMetric = "cpu" | "mem";

// The sample key for one series. Names can contain almost anything, so the
// name goes last and the parser splits on a fixed number of leading fields
// rather than on every colon.
export function sampleKey(kind: ResourceKind, metric: ResourceMetric, name: string): string {
  return `${PREFIX}${kind}:${metric}:${name}`;
}

export function parseSampleKey(
  key: string,
): { kind: ResourceKind; metric: ResourceMetric; name: string } | null {
  if (!key.startsWith(PREFIX)) return null;
  const rest = key.slice(PREFIX.length);
  const first = rest.indexOf(":");
  const second = rest.indexOf(":", first + 1);
  if (first < 0 || second < 0) return null;
  const kind = rest.slice(0, first);
  const metric = rest.slice(first + 1, second);
  const name = rest.slice(second + 1);
  if ((kind !== "pod" && kind !== "node") || (metric !== "cpu" && metric !== "mem")) return null;
  if (!name) return null;
  return { kind, metric, name };
}

// Appends one reading per series. Called from the kube panel, which already
// runs on a timer — nothing here schedules anything of its own.
export function recordResourceSamples(
  pods: PodResourceUsage[],
  nodes: NodeResourceUsage[],
  nowMs: number,
): void {
  const t = Math.floor(nowMs / GRID_MS) * GRID_MS;
  const write = (kind: ResourceKind, metric: ResourceMetric, name: string, v: number | null) => {
    // A pod with no limit set has no percentage. Writing 0 would draw a floor
    // that reads as "idle" when it means "not measurable".
    if (v === null || !Number.isFinite(v)) return;
    saveMetricSamples(sampleKey(kind, metric, name), [{ t, v }]);
  };
  for (const p of pods) {
    write("pod", "cpu", p.pod, p.cpuPct);
    write("pod", "mem", p.pod, p.memPct);
  }
  for (const n of nodes) {
    write("node", "cpu", n.name, n.cpuPct);
    write("node", "mem", n.name, n.memPct);
  }
}

function toPoints(rows: { t: number; v: number }[], win: ResolvedWindow): MetricPoint[] {
  return rows
    .filter((r) => r.t >= win.startMs && r.t <= win.endMs)
    .map((r) => ({ t: new Date(r.t).toISOString(), v: Math.round(r.v * 10) / 10 }));
}

// Reads back every series recorded in the window. Series with nothing in the
// window are dropped rather than returned empty — an empty line in a legend is
// a name with no data behind it.
export function loadResourceHistory(win: ResolvedWindow): ResourceHistory {
  const out: ResourceHistory = { podCpu: [], podMem: [], nodeCpu: [], nodeMem: [] };
  for (const key of listMetricKeys(PREFIX, win.startMs)) {
    const parsed = parseSampleKey(key);
    if (!parsed) continue;
    const points = toPoints(loadMetricSamples(key, win.startMs), win);
    if (points.length === 0) continue;
    const series: NamedSeries = { label: parsed.name, points };
    if (parsed.kind === "pod") {
      (parsed.metric === "cpu" ? out.podCpu : out.podMem).push(series);
    } else {
      (parsed.metric === "cpu" ? out.nodeCpu : out.nodeMem).push(series);
    }
  }
  const byLabel = (a: NamedSeries, b: NamedSeries): number => a.label.localeCompare(b.label);
  out.podCpu.sort(byLabel);
  out.podMem.sort(byLabel);
  out.nodeCpu.sort(byLabel);
  out.nodeMem.sort(byLabel);
  return out;
}
