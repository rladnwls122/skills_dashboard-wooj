import "server-only";
import {
  GetMetricDataCommand,
  type MetricDataQuery,
  type MetricDataResult,
} from "@aws-sdk/client-cloudwatch";
import { cloudWatch, cloudWatchForWaf, discoverAlb } from "./aws";
import { ENV, statusFor } from "./config";
import { saveMetricSamples } from "./db";
import type {
  MetricPoint,
  MetricSummary,
  ResolvedWindow,
  TargetGroupMetrics,
} from "@/lib/types";

export interface RawSeries {
  key: string;
  label: string;
  unit: string;
  stat: "Average" | "Sum";
  points: { t: number; v: number }[];
  thresholdKey?: string;
  // The CloudWatch metric this came from — "AWS/WAFV2 BlockedRequests". A
  // display label like "WAF BlockedRequests" is our wording; this is the
  // metric's own name, which is what someone checking the number in the
  // console has to search for. Passed in at the call that builds the query so
  // the two cannot drift.
  metric: string;
}

function toSeries(
  key: string,
  label: string,
  unit: string,
  stat: "Average" | "Sum",
  metric: string,
  r: MetricDataResult | undefined,
  thresholdKey?: string,
): RawSeries {
  const ts = r?.Timestamps ?? [];
  const vs = r?.Values ?? [];
  const points = ts
    .map((t, i) => ({ t: t.getTime(), v: vs[i] ?? 0 }))
    .sort((a, b) => a.t - b.t);
  return { key, label, unit, stat, points, thresholdKey, metric };
}

// AGG_BUCKETS buckets are aggregated into the headline number to smooth a
// single noisy bucket. The span that covers depends on the chosen interval, so
// every summary carries a basis saying what it counted — the unit alone ("req/min")
// does not, and a Sum over three buckets is not a per-minute rate.
const AGG_BUCKETS = 3;

export function summarize(s: RawSeries, win: ResolvedWindow): MetricSummary {
  // Drop the newest (possibly incomplete) bucket, then compare the last 3
  // complete buckets against the 3 before them.
  const pts = s.points.slice(0, Math.max(0, s.points.length - 1));
  const currentWin = pts.slice(-AGG_BUCKETS);
  const prevWin = pts.slice(-2 * AGG_BUCKETS, -AGG_BUCKETS);
  // A Sum metric is normalised to a per-minute rate rather than left as a
  // bucket total. Thresholds are absolute numbers, so a raw total would make
  // the alert depend on the chosen interval — the same traffic reads as 3
  // minutes' worth at a 1m interval and 3 hours' worth at 60m, and merely
  // widening the window would trip CRITICAL. The unit already says req/min.
  const agg = (w: { v: number }[]): number => {
    if (w.length === 0) return 0;
    const sum = w.reduce((a, p) => a + p.v, 0);
    return s.stat === "Average" ? sum / w.length : sum / (w.length * win.intervalMin);
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
    basis:
      `${s.metric} ${s.stat} · ` +
      (s.stat === "Sum"
        ? `최근 ${AGG_BUCKETS}버킷(${AGG_BUCKETS * win.intervalMin}분) 합계를 분당으로 환산 · 직전 동일 구간과 비교`
        : `최근 ${AGG_BUCKETS}버킷(${AGG_BUCKETS * win.intervalMin}분) 평균 · 직전 동일 구간과 비교`),
  };
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}

export interface CoreMetricsResult {
  summaries: MetricSummary[];
  errors: string[];
}

export async function fetchCoreMetrics(win: ResolvedWindow): Promise<CoreMetricsResult> {
  const end = new Date(win.endMs);
  const start = new Date(win.startMs);
  const periodSec = win.intervalMin * 60;

  const results: RawSeries[] = [];
  const errors: string[] = [];

  // --- ALB + RDS Proxy (workload region) ---
  try {
    const alb = await discoverAlb();
    const albDim = [{ Name: "LoadBalancer", Value: alb.loadBalancer }];
    const queries: MetricDataQuery[] = [
      q("trt", "AWS/ApplicationELB", "TargetResponseTime", albDim, "Average", periodSec),
      q("c4xx", "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", albDim, "Sum", periodSec),
      q("c5xx", "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", albDim, "Sum", periodSec),
      q("c2xx", "AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", albDim, "Sum", periodSec),
      q("c3xx", "AWS/ApplicationELB", "HTTPCode_Target_3XX_Count", albDim, "Sum", periodSec),
      q("reqs", "AWS/ApplicationELB", "RequestCount", albDim, "Sum", periodSec),
      q("rdscc", "AWS/RDS", "ClientConnections", [{ Name: "ProxyName", Value: ENV.rdsProxyName }], "Average", periodSec),
      q("rdsdc", "AWS/RDS", "DatabaseConnections", [{ Name: "ProxyName", Value: ENV.rdsProxyName }], "Average", periodSec),
    ];
    const res = await cloudWatch().send(
      new GetMetricDataCommand({ StartTime: start, EndTime: end, MetricDataQueries: queries }),
    );
    const byId = new Map((res.MetricDataResults ?? []).map((r) => [r.Id ?? "", r]));
    results.push(
      toSeries("targetResponseTime", "TargetResponseTime", "s", "Average", "AWS/ApplicationELB TargetResponseTime", byId.get("trt")),
      toSeries("http4xx", "Target 4XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_4XX_Count", byId.get("c4xx")),
      toSeries("http5xx", "Target 5XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_5XX_Count", byId.get("c5xx")),
      toSeries("http2xx", "Target 2XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_2XX_Count", byId.get("c2xx")),
      toSeries("http3xx", "Target 3XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_3XX_Count", byId.get("c3xx")),
      toSeries("requestCount", "RequestCount", "req/min", "Sum", "AWS/ApplicationELB RequestCount", byId.get("reqs")),
      toSeries("rdsClientConnections", "RDS Proxy Client Conn", "conn", "Average", `AWS/RDS ClientConnections (ProxyName=${ENV.rdsProxyName})`, byId.get("rdscc")),
      toSeries("rdsDatabaseConnections", "RDS Proxy DB Conn", "conn", "Average", `AWS/RDS DatabaseConnections (ProxyName=${ENV.rdsProxyName})`, byId.get("rdsdc")),
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
          q("wafb", "AWS/WAFV2", "BlockedRequests", dims, "Sum", periodSec),
          q("wafa", "AWS/WAFV2", "AllowedRequests", dims, "Sum", periodSec),
        ],
      }),
    );
    const byId = new Map((res.MetricDataResults ?? []).map((r) => [r.Id ?? "", r]));
    results.push(
      toSeries("wafBlocked", "WAF BlockedRequests", "req/min", "Sum", `AWS/WAFV2 BlockedRequests (WebACL=${ENV.wafWebAclName}, Rule=ALL)`, byId.get("wafb")),
      toSeries("wafAllowed", "WAF AllowedRequests", "req/min", "Sum", `AWS/WAFV2 AllowedRequests (WebACL=${ENV.wafWebAclName}, Rule=ALL)`, byId.get("wafa")),
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

  return { summaries: results.map((r) => summarize(r, win)), errors };
}

// Per-Target-Group ALB metrics (spec item 3) — each TG's CloudWatch dimension
// pair is [LoadBalancer, TargetGroup]; path labels come from listener rules
// (discoverAlb), matching this environment's /v1/user, /v1/product, /v1/stress
// routing.
export async function fetchTargetGroupMetrics(
  win: ResolvedWindow,
): Promise<TargetGroupMetrics[]> {
  const end = new Date(win.endMs);
  const start = new Date(win.startMs);
  const periodSec = win.intervalMin * 60;
  const alb = await discoverAlb();
  if (alb.targetGroups.length === 0) return [];

  const queries: MetricDataQuery[] = [];
  alb.targetGroups.forEach((tg, i) => {
    const dims = [
      { Name: "LoadBalancer", Value: alb.loadBalancer },
      { Name: "TargetGroup", Value: tg.tgDim },
    ];
    queries.push(
      q(`tg${i}trt`, "AWS/ApplicationELB", "TargetResponseTime", dims, "Average", periodSec),
      q(`tg${i}c4`, "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", dims, "Sum", periodSec),
      q(`tg${i}c5`, "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", dims, "Sum", periodSec),
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
        `AWS/ApplicationELB TargetResponseTime (TargetGroup=${tg.name})`,
        byId.get(`tg${i}trt`),
        "targetResponseTime",
      ),
      win,
    );
    const c4 = summarize(
      toSeries(
        `tg-${tg.name}-4xx`,
        "4XX",
        "req/min",
        "Sum",
        `AWS/ApplicationELB HTTPCode_Target_4XX_Count (TargetGroup=${tg.name})`,
        byId.get(`tg${i}c4`),
        "http4xx",
      ),
      win,
    );
    const c5 = summarize(
      toSeries(
        `tg-${tg.name}-5xx`,
        "5XX",
        "req/min",
        "Sum",
        `AWS/ApplicationELB HTTPCode_Target_5XX_Count (TargetGroup=${tg.name})`,
        byId.get(`tg${i}c5`),
        "http5xx",
      ),
      win,
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

// Two AWS failures are configuration mistakes rather than outages, and both
// reach the operator as SDK prose that names no fix. They are worth rewriting
// at the single point every panel already funnels its errors through.
//
// Deliberately appended, not substituted: the original text carries the request
// ID and the account, which is what a supervisor asks for when the cause turns
// out not to be the obvious one.
const HINTS: { match: RegExp; hint: string }[] = [
  {
    // Every AWS-backed panel fails at once with this, which reads as an outage.
    // It is almost always the process having started before .env held the keys —
    // env files are read at boot only, so editing one changes nothing until a
    // restart.
    match: /could not load credentials from any providers/i,
    hint: "AWS 자격증명을 찾지 못했습니다 — .env 를 채운 뒤 서버를 재시작했는지 확인하세요(.env 는 기동 시점에만 읽힙니다). 또는 `aws configure` 로 ~/.aws/credentials 를 만드세요.",
  },
  {
    // A name that is merely wrong looks identical to logging being off.
    match: /log group '.*' does not exist/i,
    hint: "설정된 로그 그룹 이름이 이 계정·리전에 없습니다 — 설정 탭의 자동 탐색으로 실제 존재하는 그룹을 고르세요. CLOUDFRONT scope 의 WAF 로그는 us-east-1 에 있습니다.",
  },
];

export function errMsg(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  const hint = HINTS.find((h) => h.match.test(raw))?.hint;
  return hint ? `${hint} (원문: ${raw})` : raw;
}
