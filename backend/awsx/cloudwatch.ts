// CloudWatch metric fetch + summarisation.

import {
  GetMetricDataCommand,
  type Dimension,
  type MetricDataQuery,
  type MetricDataResult,
} from "@aws-sdk/client-cloudwatch";

import { statusFor } from "../config/thresholds.ts";
import type { Sample } from "../store/store.ts";
import type {
  MetricPoint,
  MetricSummary,
  ResolvedWindow,
  TargetGroupMetrics,
} from "../../src/lib/types.ts";
import { AWS, errMsg } from "./clients.ts";
import { discoverAlb } from "./alb.ts";

interface RawPoint {
  t: number;
  v: number;
}

export interface RawSeries {
  key: string;
  label: string;
  unit: string;
  /** "Average" | "Sum" */
  stat: string;
  points: RawPoint[];
  /** Lets a per-TG series borrow the shared threshold. */
  thresholdKey: string;
  /**
   * The CloudWatch metric this came from — what someone checking the number in
   * the console has to search for.
   */
  metric: string;
}

function toSeries(
  key: string,
  label: string,
  unit: string,
  stat: string,
  metric: string,
  r: MetricDataResult | undefined,
  thresholdKey: string,
): RawSeries {
  const points: RawPoint[] = [];
  if (r?.Timestamps) {
    r.Timestamps.forEach((t, i) => {
      points.push({ t: new Date(t).getTime(), v: r.Values?.[i] ?? 0 });
    });
    points.sort((a, b) => a.t - b.t);
  }
  return { key, label, unit, stat, points, thresholdKey, metric };
}

/**
 * How many buckets are aggregated into the headline number, to smooth a single
 * noisy bucket; every summary carries a basis saying what it counted.
 */
const AGG_BUCKETS = 3;

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

export function summarize(s: RawSeries, win: ResolvedWindow): MetricSummary {
  // Drop the newest (possibly incomplete) bucket, then compare the last 3
  // complete buckets against the 3 before them.
  const pts = s.points.length > 0 ? s.points.slice(0, -1) : s.points;
  const slice = (from: number, to: number) => pts.slice(Math.max(from, 0), Math.max(to, 0));
  const currentWin = slice(pts.length - AGG_BUCKETS, pts.length);
  const prevWin = slice(pts.length - 2 * AGG_BUCKETS, pts.length - AGG_BUCKETS);

  // A Sum metric is normalised to a per-minute rate rather than left as a bucket
  // total — thresholds are absolute, so a raw total would make the alert depend
  // on the chosen interval.
  const agg = (w: RawPoint[]): number => {
    if (w.length === 0) return 0;
    const sum = w.reduce((acc, p) => acc + p.v, 0);
    if (s.stat === "Average") return sum / w.length;
    return sum / (w.length * win.intervalMin);
  };

  const current = round3(agg(currentWin));
  const previous = round3(agg(prevWin));
  const delta = round3(current - previous);
  let percentChange: number | null;
  if (previous > 0) percentChange = round3(((current - previous) / previous) * 100);
  else if (current > 0) percentChange = null;
  else percentChange = 0;

  const points: MetricPoint[] = pts.map((p) => ({
    t: new Date(p.t).toISOString(),
    v: round3(p.v),
  }));

  const thresholdKey = s.thresholdKey || s.key;
  const span = AGG_BUCKETS * win.intervalMin;
  const basis =
    `${s.metric} ${s.stat} · ` +
    (s.stat === "Sum"
      ? `최근 ${AGG_BUCKETS}버킷(${span}분) 합계를 분당으로 환산 · 직전 동일 구간과 비교`
      : `최근 ${AGG_BUCKETS}버킷(${span}분) 평균 · 직전 동일 구간과 비교`);

  return {
    key: s.key,
    label: s.label,
    unit: s.unit,
    current,
    previous,
    delta,
    percentChange,
    status: statusFor(thresholdKey, current, percentChange),
    points,
    basis,
  };
}

export interface CoreMetricsResult {
  summaries: MetricSummary[];
  errors: string[];
}

function q(
  id: string,
  namespace: string,
  metricName: string,
  dims: Dimension[],
  stat: string,
  periodSec: number,
): MetricDataQuery {
  return {
    Id: id,
    MetricStat: {
      Metric: { Namespace: namespace, MetricName: metricName, Dimensions: dims },
      Period: periodSec,
      Stat: stat,
    },
    ReturnData: true,
  };
}

function dim(name: string, value: string): Dimension {
  return { Name: name, Value: value };
}

function byId(results: MetricDataResult[] | undefined): Map<string, MetricDataResult> {
  const out = new Map<string, MetricDataResult>();
  for (const r of results ?? []) {
    if (r.Id) out.set(r.Id, r);
  }
  return out;
}

export async function fetchCoreMetrics(
  a: AWS,
  win: ResolvedWindow,
): Promise<CoreMetricsResult> {
  const end = new Date(win.endMs);
  const start = new Date(win.startMs);
  const periodSec = win.intervalMin * 60;

  const results: RawSeries[] = [];
  const errors: string[] = [];

  // --- ALB + RDS Proxy (workload region) ---
  try {
    const alb = await discoverAlb(a);
    const albDim = [dim("LoadBalancer", alb.loadBalancer)];
    const rdsProxy = a.settings.rdsProxyName();
    const queries = [
      q("trt", "AWS/ApplicationELB", "TargetResponseTime", albDim, "Average", periodSec),
      q("c4xx", "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", albDim, "Sum", periodSec),
      q("c5xx", "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", albDim, "Sum", periodSec),
      q("c2xx", "AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", albDim, "Sum", periodSec),
      q("c3xx", "AWS/ApplicationELB", "HTTPCode_Target_3XX_Count", albDim, "Sum", periodSec),
      q("reqs", "AWS/ApplicationELB", "RequestCount", albDim, "Sum", periodSec),
      q("rdscc", "AWS/RDS", "ClientConnections", [dim("ProxyName", rdsProxy)], "Average", periodSec),
      q("rdsdc", "AWS/RDS", "DatabaseConnections", [dim("ProxyName", rdsProxy)], "Average", periodSec),
    ];
    const res = await a.cloudWatch(a.settings.region()).send(
      new GetMetricDataCommand({
        StartTime: start,
        EndTime: end,
        MetricDataQueries: queries,
      }),
    );
    const m = byId(res.MetricDataResults);
    results.push(
      toSeries("targetResponseTime", "TargetResponseTime", "s", "Average", "AWS/ApplicationELB TargetResponseTime", m.get("trt"), ""),
      toSeries("http4xx", "Target 4XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_4XX_Count", m.get("c4xx"), ""),
      toSeries("http5xx", "Target 5XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_5XX_Count", m.get("c5xx"), ""),
      toSeries("http2xx", "Target 2XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_2XX_Count", m.get("c2xx"), ""),
      toSeries("http3xx", "Target 3XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_3XX_Count", m.get("c3xx"), ""),
      toSeries("requestCount", "RequestCount", "req/min", "Sum", "AWS/ApplicationELB RequestCount", m.get("reqs"), ""),
      toSeries("rdsClientConnections", "RDS Proxy Client Conn", "conn", "Average", `AWS/RDS ClientConnections (ProxyName=${rdsProxy})`, m.get("rdscc"), ""),
      toSeries("rdsDatabaseConnections", "RDS Proxy DB Conn", "conn", "Average", `AWS/RDS DatabaseConnections (ProxyName=${rdsProxy})`, m.get("rdsdc"), ""),
    );
  } catch (e) {
    errors.push("ALB/RDS metrics: " + errMsg(e));
  }

  // --- WAF Blocked/Allowed (us-east-1 for CLOUDFRONT scope) ---
  try {
    const aclName = a.settings.wafWebAclName();
    const dims = [dim("WebACL", aclName), dim("Rule", "ALL")];
    if (a.settings.wafScope() !== "CLOUDFRONT") dims.push(dim("Region", a.settings.region()));
    const res = await a.cloudWatch(a.settings.wafRegion()).send(
      new GetMetricDataCommand({
        StartTime: start,
        EndTime: end,
        MetricDataQueries: [
          q("wafb", "AWS/WAFV2", "BlockedRequests", dims, "Sum", periodSec),
          q("wafa", "AWS/WAFV2", "AllowedRequests", dims, "Sum", periodSec),
        ],
      }),
    );
    const m = byId(res.MetricDataResults);
    results.push(
      toSeries("wafBlocked", "WAF BlockedRequests", "req/min", "Sum", `AWS/WAFV2 BlockedRequests (WebACL=${aclName}, Rule=ALL)`, m.get("wafb"), ""),
      toSeries("wafAllowed", "WAF AllowedRequests", "req/min", "Sum", `AWS/WAFV2 AllowedRequests (WebACL=${aclName}, Rule=ALL)`, m.get("wafa"), ""),
    );
  } catch (e) {
    errors.push("WAF metrics: " + errMsg(e));
  }

  if (results.length === 0) {
    throw new Error(errors.length > 0 ? errors.join(" / ") : "no metric data");
  }

  for (const s of results) {
    // A metric-cache failure must not break the panel.
    try {
      const samples: Sample[] = s.points.map((p) => ({ t: p.t, v: p.v }));
      a.store?.saveMetricSamples(s.key, samples);
    } catch {
      // ignored
    }
  }

  return { summaries: results.map((r) => summarize(r, win)), errors };
}

/** Per-Target-Group ALB metrics (spec item 3). */
export async function fetchTargetGroupMetrics(
  a: AWS,
  win: ResolvedWindow,
): Promise<TargetGroupMetrics[]> {
  const end = new Date(win.endMs);
  const start = new Date(win.startMs);
  const periodSec = win.intervalMin * 60;
  const alb = await discoverAlb(a);
  if (alb.targetGroups.length === 0) return [];

  const queries: MetricDataQuery[] = [];
  alb.targetGroups.forEach((tg, i) => {
    const dims = [dim("LoadBalancer", alb.loadBalancer), dim("TargetGroup", tg.tgDim)];
    queries.push(
      q(`tg${i}trt`, "AWS/ApplicationELB", "TargetResponseTime", dims, "Average", periodSec),
      q(`tg${i}c4`, "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", dims, "Sum", periodSec),
      q(`tg${i}c5`, "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", dims, "Sum", periodSec),
    );
  });

  const res = await a.cloudWatch(a.settings.region()).send(
    new GetMetricDataCommand({ StartTime: start, EndTime: end, MetricDataQueries: queries }),
  );
  const m = byId(res.MetricDataResults);

  return alb.targetGroups.map((tg, i) => ({
    name: tg.name,
    pathPattern: tg.pathPattern,
    responseTime: summarize(
      toSeries(
        `tg-${tg.name}-trt`, "TargetResponseTime", "s", "Average",
        `AWS/ApplicationELB TargetResponseTime (TargetGroup=${tg.name})`,
        m.get(`tg${i}trt`), "targetResponseTime",
      ),
      win,
    ),
    c4xx: summarize(
      toSeries(
        `tg-${tg.name}-4xx`, "4XX", "req/min", "Sum",
        `AWS/ApplicationELB HTTPCode_Target_4XX_Count (TargetGroup=${tg.name})`,
        m.get(`tg${i}c4`), "http4xx",
      ),
      win,
    ),
    c5xx: summarize(
      toSeries(
        `tg-${tg.name}-5xx`, "5XX", "req/min", "Sum",
        `AWS/ApplicationELB HTTPCode_Target_5XX_Count (TargetGroup=${tg.name})`,
        m.get(`tg${i}c5`), "http5xx",
      ),
      win,
    ),
  }));
}
