import "server-only";
import {
  GetMetricDataCommand,
  type MetricDataQuery,
  type MetricDataResult,
} from "@aws-sdk/client-cloudwatch";
import { cloudWatch, cloudWatchForWaf, discoverAlb } from "./aws";
import { ENV, statusFor } from "./config";
import { saveMetricSamples } from "./db";
import type { MetricPoint, MetricSummary, TargetGroupMetrics } from "@/lib/types";

const WINDOW_MINUTES = 14;
const BUCKET_SECONDS = 60;

interface RawSeries {
  key: string;
  label: string;
  unit: string;
  stat: "Average" | "Sum";
  points: { t: number; v: number }[];
  thresholdKey?: string;
}

function floorToMinute(d: Date): Date {
  const t = new Date(d);
  t.setSeconds(0, 0);
  return t;
}

function toSeries(
  key: string,
  label: string,
  unit: string,
  stat: "Average" | "Sum",
  r: MetricDataResult | undefined,
  thresholdKey?: string,
): RawSeries {
  const ts = r?.Timestamps ?? [];
  const vs = r?.Values ?? [];
  const points = ts
    .map((t, i) => ({ t: t.getTime(), v: vs[i] ?? 0 }))
    .sort((a, b) => a.t - b.t);
  return { key, label, unit, stat, points, thresholdKey };
}

function summarize(s: RawSeries): MetricSummary {
  // Drop the newest (possibly incomplete) bucket, then compare the last 3
  // complete buckets against the 3 before them.
  const pts = s.points.slice(0, Math.max(0, s.points.length - 1));
  const currentWin = pts.slice(-3);
  const prevWin = pts.slice(-6, -3);
  const agg = (win: { v: number }[]): number => {
    if (win.length === 0) return 0;
    const sum = win.reduce((a, p) => a + p.v, 0);
    return s.stat === "Average" ? sum / win.length : sum;
  };
  const current = round(agg(currentWin));
  const previous = round(agg(prevWin));
  const delta = round(current - previous);
  const percentChange =
    previous > 0 ? round(((current - previous) / previous) * 100) : current > 0 ? null : 0;
  const points: MetricPoint[] = pts.map((p) => ({ t: new Date(p.t).toISOString(), v: round(p.v) }));
  return {
    key: s.key,
    label: s.label,
    unit: s.unit,
    current,
    previous,
    delta,
    percentChange,
    status: statusFor(s.thresholdKey ?? s.key, current, percentChange),
    points,
  };
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}

export interface CoreMetricsResult {
  summaries: MetricSummary[];
  errors: string[];
}

export async function fetchCoreMetrics(): Promise<CoreMetricsResult> {
  const end = floorToMinute(new Date());
  const start = new Date(end.getTime() - WINDOW_MINUTES * 60_000);

  const results: RawSeries[] = [];
  const errors: string[] = [];

  // --- ALB + RDS Proxy (workload region) ---
  try {
    const alb = await discoverAlb();
    const albDim = [{ Name: "LoadBalancer", Value: alb.loadBalancer }];
    const queries: MetricDataQuery[] = [
      q("trt", "AWS/ApplicationELB", "TargetResponseTime", albDim, "Average"),
      q("c4xx", "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", albDim, "Sum"),
      q("c5xx", "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", albDim, "Sum"),
      q("c2xx", "AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", albDim, "Sum"),
      q("c3xx", "AWS/ApplicationELB", "HTTPCode_Target_3XX_Count", albDim, "Sum"),
      q("reqs", "AWS/ApplicationELB", "RequestCount", albDim, "Sum"),
      q("rdscc", "AWS/RDS", "ClientConnections", [{ Name: "ProxyName", Value: ENV.rdsProxyName }], "Average"),
      q("rdsdc", "AWS/RDS", "DatabaseConnections", [{ Name: "ProxyName", Value: ENV.rdsProxyName }], "Average"),
    ];
    const res = await cloudWatch().send(
      new GetMetricDataCommand({ StartTime: start, EndTime: end, MetricDataQueries: queries }),
    );
    const byId = new Map((res.MetricDataResults ?? []).map((r) => [r.Id ?? "", r]));
    results.push(
      toSeries("targetResponseTime", "TargetResponseTime", "s", "Average", byId.get("trt")),
      toSeries("http4xx", "Target 4XX", "req/min", "Sum", byId.get("c4xx")),
      toSeries("http5xx", "Target 5XX", "req/min", "Sum", byId.get("c5xx")),
      toSeries("http2xx", "Target 2XX", "req/min", "Sum", byId.get("c2xx")),
      toSeries("http3xx", "Target 3XX", "req/min", "Sum", byId.get("c3xx")),
      toSeries("requestCount", "RequestCount", "req/min", "Sum", byId.get("reqs")),
      toSeries("rdsClientConnections", "RDS Proxy Client Conn", "conn", "Average", byId.get("rdscc")),
      toSeries("rdsDatabaseConnections", "RDS Proxy DB Conn", "conn", "Average", byId.get("rdsdc")),
    );
  } catch (e) {
    errors.push(`ALB/RDS metrics: ${errMsg(e)}`);
  }

  // --- WAF Blocked/Allowed (us-east-1 for CLOUDFRONT scope) ---
  try {
    const dims =
      ENV.wafScope === "CLOUDFRONT"
        ? [
            { Name: "WebACL", Value: ENV.wafWebAclName },
            { Name: "Rule", Value: "ALL" },
          ]
        : [
            { Name: "WebACL", Value: ENV.wafWebAclName },
            { Name: "Rule", Value: "ALL" },
            { Name: "Region", Value: ENV.region },
          ];
    const res = await cloudWatchForWaf().send(
      new GetMetricDataCommand({
        StartTime: start,
        EndTime: end,
        MetricDataQueries: [
          q("wafb", "AWS/WAFV2", "BlockedRequests", dims, "Sum"),
          q("wafa", "AWS/WAFV2", "AllowedRequests", dims, "Sum"),
        ],
      }),
    );
    const byId = new Map((res.MetricDataResults ?? []).map((r) => [r.Id ?? "", r]));
    results.push(
      toSeries("wafBlocked", "WAF BlockedRequests", "req/min", "Sum", byId.get("wafb")),
      toSeries("wafAllowed", "WAF AllowedRequests", "req/min", "Sum", byId.get("wafa")),
    );
  } catch (e) {
    errors.push(`WAF metrics: ${errMsg(e)}`);
  }

  if (results.length === 0) {
    throw new Error(errors.join(" / ") || "no metric data");
  }

  for (const s of results) {
    try {
      saveMetricSamples(s.key, s.points);
    } catch {
      // metric cache failure must not break the panel
    }
  }

  return { summaries: results.map(summarize), errors };
}

// Per-Target-Group ALB metrics (spec item 3) — each TG's CloudWatch dimension
// pair is [LoadBalancer, TargetGroup]; path labels come from listener rules
// (discoverAlb), matching this environment's /v1/user, /v1/product, /v1/stress
// routing.
export async function fetchTargetGroupMetrics(): Promise<TargetGroupMetrics[]> {
  const end = floorToMinute(new Date());
  const start = new Date(end.getTime() - WINDOW_MINUTES * 60_000);
  const alb = await discoverAlb();
  if (alb.targetGroups.length === 0) return [];

  const queries: MetricDataQuery[] = [];
  alb.targetGroups.forEach((tg, i) => {
    const dims = [
      { Name: "LoadBalancer", Value: alb.loadBalancer },
      { Name: "TargetGroup", Value: tg.tgDim },
    ];
    queries.push(
      q(`tg${i}trt`, "AWS/ApplicationELB", "TargetResponseTime", dims, "Average"),
      q(`tg${i}c4`, "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", dims, "Sum"),
      q(`tg${i}c5`, "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", dims, "Sum"),
    );
  });
  const res = await cloudWatch().send(
    new GetMetricDataCommand({ StartTime: start, EndTime: end, MetricDataQueries: queries }),
  );
  const byId = new Map((res.MetricDataResults ?? []).map((r) => [r.Id ?? "", r]));

  return alb.targetGroups.map((tg, i) => {
    const trt = summarize(
      toSeries(
        `tg-${tg.name}-trt`,
        "TargetResponseTime",
        "s",
        "Average",
        byId.get(`tg${i}trt`),
        "targetResponseTime",
      ),
    );
    const c4 = summarize(
      toSeries(`tg-${tg.name}-4xx`, "4XX", "req/min", "Sum", byId.get(`tg${i}c4`), "http4xx"),
    );
    const c5 = summarize(
      toSeries(`tg-${tg.name}-5xx`, "5XX", "req/min", "Sum", byId.get(`tg${i}c5`), "http5xx"),
    );
    return { name: tg.name, pathPattern: tg.pathPattern, responseTime: trt, c4xx: c4, c5xx: c5 };
  });
}

function q(
  id: string,
  namespace: string,
  metricName: string,
  dims: { Name: string; Value: string }[],
  stat: "Average" | "Sum",
): MetricDataQuery {
  return {
    Id: id,
    MetricStat: {
      Metric: { Namespace: namespace, MetricName: metricName, Dimensions: dims },
      Period: BUCKET_SECONDS,
      Stat: stat,
    },
    ReturnData: true,
  };
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
