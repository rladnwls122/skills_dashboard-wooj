import "server-only";
import {
  CheckCapacityCommand,
  GetSampledRequestsCommand,
  GetWebACLCommand,
  ListWebACLsCommand,
  UpdateWebACLCommand,
  type Rule,
  type SampledHTTPRequest,
  type Statement,
  type WebACL,
} from "@aws-sdk/client-wafv2";
import {
  GetQueryResultsCommand,
  StartQueryCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { cached } from "./cache";
import {
  ENV,
  POLLING,
  WAF_LIMITS,
  isIpConcentrated,
  isLowPriorityPath,
  isPathSuspicious,
  wafRegion,
} from "./config";
import { logsClient, wafClient } from "./aws";
import { insertWafHistory, getWafHistory, listWafHistory } from "./db";
import { maskText } from "./mask";
import { classifyUa, queryHasBase64Blob } from "./threatsig";
import { runInsightsQuery } from "./logsinsights";
import { foldByAction, insightsAgeNote, topKeyCounts, totals } from "./waflogagg";
import { errMsg } from "./cloudwatch";
import type {
  ApplyHistoryEntry,
  HttpSummary,
  IpStat,
  KeyCount,
  PathStat,
  ResolvedWindow,
  StatusDistribution,
  WafAclInfo,
  WafSampleRow,
} from "@/lib/types";

// Pretty-print WAF objects with SearchString bytes decoded to text — the same
// shape the WAF console JSON editor accepts, and readable by Amazon Q.
export function wafJson(value: unknown): string {
  return JSON.stringify(
    value,
    (_k, v: unknown) => {
      if (v instanceof Uint8Array) return new TextDecoder().decode(v);
      return v;
    },
    2,
  );
}

interface AclHandle {
  webAcl: WebACL;
  lockToken: string;
  arn: string;
}

async function getAclHandle(): Promise<AclHandle> {
  const client = wafClient();
  const list = await client.send(new ListWebACLsCommand({ Scope: ENV.wafScope }));
  const summary =
    list.WebACLs?.find((a) => a.Name === ENV.wafWebAclName) ?? list.WebACLs?.[0];
  if (!summary?.Name || !summary.Id || !summary.ARN) {
    throw new Error(`WebACL not found (scope=${ENV.wafScope}, name=${ENV.wafWebAclName})`);
  }
  const res = await client.send(
    new GetWebACLCommand({ Name: summary.Name, Id: summary.Id, Scope: ENV.wafScope }),
  );
  if (!res.WebACL || !res.LockToken) throw new Error("GetWebACL returned empty result");
  return { webAcl: res.WebACL, lockToken: res.LockToken, arn: summary.ARN };
}

export async function getAclInfo(): Promise<WafAclInfo> {
  const { webAcl } = await getAclHandle();
  return {
    name: webAcl.Name ?? "",
    id: webAcl.Id ?? "",
    scope: ENV.wafScope,
    capacityUsed: Number(webAcl.Capacity ?? 0),
    ruleCount: webAcl.Rules?.length ?? 0,
    rules: (webAcl.Rules ?? []).map((r) => ({
      name: r.Name ?? "",
      priority: r.Priority ?? 0,
      action: r.Action?.Block
        ? "BLOCK"
        : r.Action?.Count
          ? "COUNT"
          : r.OverrideAction?.Count
            ? "COUNT(override)"
            : r.Action?.Allow
              ? "ALLOW"
              : "GROUP",
    })),
  };
}

// Why the Insights path was skipped on the most recent call, so the fallback's
// source line can say it instead of silently reading as the intended source.
let insightsFallbackReason: string | null = null;

function fmtBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(2)}GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)}MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(0)}KB`;
  return `${n}B`;
}

export interface SampleSet {
  samples: SampledHTTPRequest[];
  windowMinutes: number;
}

export async function fetchSampledRequests(): Promise<SampleSet> {
  return cached("waf:samples", 30_000, async () => {
    const client = wafClient();
    const { webAcl, arn } = await getAclHandle();
    const end = new Date();
    const start = new Date(end.getTime() - WAF_LIMITS.sampleWindowMinutes * 60_000);
    const metricNames = new Set<string>();
    if (webAcl.VisibilityConfig?.MetricName) metricNames.add(webAcl.VisibilityConfig.MetricName);
    for (const r of webAcl.Rules ?? []) {
      if (r.VisibilityConfig?.MetricName) metricNames.add(r.VisibilityConfig.MetricName);
    }
    const samples: SampledHTTPRequest[] = [];
    for (const metricName of metricNames) {
      try {
        const res = await client.send(
          new GetSampledRequestsCommand({
            WebAclArn: arn,
            RuleMetricName: metricName,
            Scope: ENV.wafScope,
            TimeWindow: { StartTime: start, EndTime: end },
            MaxItems: 500,
          }),
        );
        samples.push(...(res.SampledRequests ?? []));
      } catch {
        // one rule's samples failing must not kill the whole set
      }
    }
    return { samples, windowMinutes: WAF_LIMITS.sampleWindowMinutes };
  });
}

function sampleUri(s: SampledHTTPRequest): string {
  return s.Request?.URI ?? "";
}

function samplePath(s: SampledHTTPRequest): string {
  return sampleUri(s).split("?")[0] ?? "";
}

function sampleQuery(s: SampledHTTPRequest): string {
  const uri = sampleUri(s);
  const idx = uri.indexOf("?");
  return idx >= 0 ? uri.slice(idx + 1) : "";
}

function sampleHeader(s: SampledHTTPRequest, name: string): string {
  const h = s.Request?.Headers?.find((x) => (x.Name ?? "").toLowerCase() === name);
  return h?.Value ?? "";
}

const BORING_HEADERS = new Set([
  "host",
  "user-agent",
  "accept",
  "accept-encoding",
  "accept-language",
  "content-type",
  "content-length",
  "connection",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-amzn-trace-id",
  "via",
  "cookie",
  "authorization",
]);

function topCounts(map: Map<string, number>, n: number): KeyCount[] {
  return [...map.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

export async function buildHttpSummary(
  statusDist: StatusDistribution | null,
  win: ResolvedWindow,
): Promise<HttpSummary> {
  // Real counts over the shared window when WAF logs are available; the
  // sampled-requests path below is the fallback and says so, because its
  // numbers are a 500-per-rule sample over WAF's own 3-hour ceiling and cannot
  // follow the selected window.
  if (ENV.wafLogGroup) {
    try {
      const agg = await fetchWafLogInsightsCached(win);
      return {
        totalSampled: agg.total,
        windowLabel: win.label,
        source: `WAF 로그 Logs Insights(${ENV.wafLogGroup}) · 구간 ${win.label} · 스캔 ${fmtBytes(agg.bytesScanned)} · 표본이 아닌 전수 집계${insightsAgeNote(agg.coveredEndMs, Date.now())}`,
        byPath: agg.byPath,
        byIp: agg.byIp,
        byUa: agg.byUa,
        byMethod: agg.byMethod,
        queryPatterns: agg.queryPatterns,
        headerPatterns: [],
        blockedTotal: agg.blockedTotal,
        statusDist,
        detailedStatus: null,
        notes: [
          "헤더 패턴은 WAF 로그 집계에서 수집하지 않음 — 헤더는 요청마다 순서가 달라 인덱스로 집계할 수 없다. 샘플 모드(WAF_LOG_GROUP 미설정)에서만 나온다.",
        ],
      };
    } catch (e) {
      // Fall through to sampling, but say why the better source is missing.
      insightsFallbackReason = errMsg(e);
    }
  }

  const { samples, windowMinutes } = await fetchSampledRequests();
  const byPath = new Map<string, { count: number; blocked: number }>();
  const byIp = new Map<string, number>();
  const byUa = new Map<string, number>();
  const byMethod = new Map<string, number>();
  const byQuery = new Map<string, number>();
  const byHeader = new Map<string, number>();

  for (const s of samples) {
    const path = samplePath(s);
    const entry = byPath.get(path) ?? { count: 0, blocked: 0 };
    entry.count += 1;
    if (s.Action === "BLOCK") entry.blocked += 1;
    byPath.set(path, entry);

    const ip = s.Request?.ClientIP ?? "";
    if (ip) byIp.set(ip, (byIp.get(ip) ?? 0) + 1);
    const ua = sampleHeader(s, "user-agent") || "(empty UA)";
    byUa.set(ua, (byUa.get(ua) ?? 0) + 1);
    const method = s.Request?.Method ?? "";
    if (method) byMethod.set(method, (byMethod.get(method) ?? 0) + 1);
    const query = sampleQuery(s);
    if (query) byQuery.set(query.slice(0, 120), (byQuery.get(query.slice(0, 120)) ?? 0) + 1);
    for (const h of s.Request?.Headers ?? []) {
      const name = (h.Name ?? "").toLowerCase();
      if (!name || BORING_HEADERS.has(name)) continue;
      const key = `${name}: ${(h.Value ?? "").slice(0, 60)}`;
      byHeader.set(key, (byHeader.get(key) ?? 0) + 1);
    }
  }

  const total = samples.length;
  // Full-population blocked count, taken before byPath is truncated to 20.
  let blockedTotal = 0;
  for (const v of byPath.values()) blockedTotal += v.blocked;

  const pathStats: PathStat[] = [...byPath.entries()]
    .map(([path, v]) => ({
      path,
      count: v.count,
      blocked: v.blocked,
      lowPriority: isLowPriorityPath(path),
      suspicious: isPathSuspicious(path, v.count, total),
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  let source = `WAF GetSampledRequests (최근 ${windowMinutes}분, 샘플 ${total}건 — 규칙당 500건 상한이라 전수가 아님, 선택한 구간을 따르지 않음)`;
  if (insightsFallbackReason) {
    source += ` · WAF 로그 집계 실패로 폴백: ${insightsFallbackReason}`;
    insightsFallbackReason = null;
  } else if (!ENV.wafLogGroup) {
    source += " · WAF_LOG_GROUP 을 설정하면 선택 구간의 전수 집계로 바뀜";
  }
  if (ENV.wafLogGroup) {
    try {
      const logAgg = await fetchWafLogAggregation();
      for (const r of logAgg.byIp) byIp.set(r.key, Math.max(byIp.get(r.key) ?? 0, r.count));
      source += ` + WAF 로그(${ENV.wafLogGroup})`;
    } catch {
      source += " (WAF 로그 조회 실패, 샘플만 사용)";
    }
  }

  const ipStats: IpStat[] = topCounts(byIp, 10).map((r) => ({
    key: r.key,
    count: r.count,
    sharePct: Math.round((r.count / Math.max(total, 1)) * 100),
    concentrated: isIpConcentrated(r.count, total),
  }));

  return {
    totalSampled: total,
    windowLabel: `${windowMinutes}m`,
    source,
    byPath: pathStats,
    byIp: ipStats,
    byUa: topCounts(byUa, 10),
    byMethod: topCounts(byMethod, 8),
    queryPatterns: topCounts(byQuery, 10),
    headerPatterns: topCounts(byHeader, 10),
    blockedTotal,
    statusDist,
    detailedStatus: null,
    notes: emptySampleNotes(total),
  };
}

// Why this panel is empty, when it is.
//
// GetSampledRequests only samples requests that a rule matched. A WebACL whose
// rules match nothing therefore returns zero samples, and every list built from
// them — paths, IPs, User-Agents — comes back empty. Empty reads as "nothing
// suspicious is happening"; it actually means "nothing was collected", and the
// difference decides whether an operator goes looking. So the panel says which
// one it is, and what to do about it.
//
// This is not hypothetical here: the app's own access log carries no
// user_agent field either (app, client_ip, latency_ms, method, path, status),
// so with sampling empty there is no UA anywhere in the system.
export function emptySampleNotes(total: number): string[] {
  if (total > 0) return [];
  return [
    "샘플 0건 — 트래픽이 없다는 뜻이 아니라 수집되지 않았다는 뜻입니다. WAF GetSampledRequests 는 규칙에 매칭된 요청만 표본으로 남기므로, 아무 규칙도 매칭하지 않는 WebACL 에서는 항상 0건입니다.",
    "따라서 경로·IP·User-Agent 통계가 전부 비어 있고, 이 상태에서는 UA 규칙을 조립할 수 없습니다.",
    "채우는 방법 ①: WAF 로깅을 CloudWatch Logs 로 켜고 .env 의 WAF_LOG_GROUP 을 그 로그 그룹으로 지정 — 표본이 아닌 전수 집계로 바뀝니다.",
    "채우는 방법 ②: WebACL 에 광범위한 COUNT 규칙을 하나 추가 — 차단 없이 매칭만 시켜 표본을 만듭니다.",
    "앱 액세스 로그로는 대체할 수 없습니다 — 이 환경의 앱 로그에는 user_agent 필드가 없습니다(app · client_ip · latency_ms · method · path · status · ts).",
  ];
}

// --- WAF logs via Logs Insights -------------------------------------------
//
// GetSampledRequests returns at most 500 requests per rule over at most three
// hours, so every count derived from it is a sample, not a total, and it cannot
// honour a window the operator chose. When a WAF log group is configured the
// same aggregates come from Logs Insights over the shared window instead —
// real counts, and the scanned bytes are reported so the cost is visible.
//
// Counts are grouped by (key, action) rather than filtered to blocks: a list of
// blocked paths alone cannot distinguish "nothing was blocked" from "nothing
// arrived", and folding the pair into one row costs no extra scan.

interface WafLogAggregation {
  byPath: PathStat[];
  byIp: IpStat[];
  byUa: KeyCount[];
  byMethod: KeyCount[];
  queryPatterns: KeyCount[];
  total: number;
  blockedTotal: number;
  bytesScanned: number;
  // End of the span these numbers actually cover — a cached result is older
  // than the window the caller resolved, and the panel has to say so.
  coveredEndMs: number;
}

// Keyed by span alone: the aggregation groups by key, never by time bucket, so
// the interval does not change the result, and keying on the exact end would
// miss on every poll and defeat the cache.
function fetchWafLogInsightsCached(win: ResolvedWindow): Promise<WafLogAggregation> {
  return cached(
    `waf:insights:${ENV.wafLogGroup}:${win.windowMin}`,
    POLLING.wafInsightsTtlMs,
    () => fetchWafLogInsights(win),
    POLLING.logFailTtlMs,
  );
}

async function fetchWafLogInsights(win: ResolvedWindow): Promise<WafLogAggregation> {
  // The region matters and is not the workload region. A CLOUDFRONT-scope WAF
  // only writes its logs in us-east-1, so querying the workload region returns
  // ResourceNotFoundException — which the fallback then reports as "log
  // aggregation failed", sending the operator to fix logging that is already on.
  const bounds = {
    region: wafRegion(),
    logGroup: ENV.wafLogGroup,
    startMs: win.startMs,
    endMs: win.endMs,
  };
  // The User-Agent lives inside httpRequest.headers[], whose index varies per
  // request, so it is pulled off the raw message rather than a JSON field.
  const [pathRes, ipRes, uaRes, methodRes, argsRes] = await Promise.all([
    runInsightsQuery({
      ...bounds,
      query:
        "stats count(*) as cnt by httpRequest.uri as path, action | sort cnt desc | limit 200",
    }),
    runInsightsQuery({
      ...bounds,
      query:
        "stats count(*) as cnt by httpRequest.clientIp as ip, action | sort cnt desc | limit 100",
    }),
    runInsightsQuery({
      ...bounds,
      query:
        'parse @message /"name":"(?i)user-agent","value":"(?<ua>[^"]*)"/ | stats count(*) as cnt by ua | sort cnt desc | limit 20',
    }),
    runInsightsQuery({
      ...bounds,
      query: "stats count(*) as cnt by httpRequest.httpMethod as method | sort cnt desc | limit 10",
    }),
    runInsightsQuery({
      ...bounds,
      query:
        "filter httpRequest.args != '' | stats count(*) as cnt by httpRequest.args as args | sort cnt desc | limit 20",
    }),
  ]);

  const pathFolded = foldByAction(pathRes.rows, "path");
  const { total, blockedTotal } = totals(pathFolded);

  const byPath: PathStat[] = [...pathFolded.entries()]
    .map(([path, v]) => ({
      path,
      count: v.count,
      blocked: v.blocked,
      lowPriority: isLowPriorityPath(path),
      suspicious: isPathSuspicious(path, v.count, total),
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  const ipFolded = foldByAction(ipRes.rows, "ip");
  const byIp: IpStat[] = [...ipFolded.entries()]
    .map(([key, v]) => ({
      key,
      count: v.count,
      sharePct: Math.round((v.count / Math.max(total, 1)) * 100),
      concentrated: isIpConcentrated(v.count, total),
    }))
    .filter((r) => r.key.length > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const bytesScanned =
    pathRes.bytesScanned +
    ipRes.bytesScanned +
    uaRes.bytesScanned +
    methodRes.bytesScanned +
    argsRes.bytesScanned;

  return {
    byPath,
    byIp,
    byUa: topKeyCounts(uaRes.rows, "ua", 10),
    byMethod: topKeyCounts(methodRes.rows, "method", 8),
    queryPatterns: topKeyCounts(argsRes.rows, "args", 10).map((r) => ({
      key: r.key.slice(0, 120),
      count: r.count,
    })),
    total,
    blockedTotal,
    bytesScanned,
    coveredEndMs: win.endMs,
  };
}

async function fetchWafLogAggregation(): Promise<{ byIp: KeyCount[] }> {
  const client = logsClient();
  const end = Math.floor(Date.now() / 1000);
  const start = end - 15 * 60;
  const q = await client.send(
    new StartQueryCommand({
      logGroupName: ENV.wafLogGroup,
      startTime: start,
      endTime: end,
      queryString:
        "stats count(*) as cnt by httpRequest.clientIp as ip | sort cnt desc | limit 10",
    }),
  );
  if (!q.queryId) throw new Error("StartQuery failed");
  for (let i = 0; i < 8; i += 1) {
    await new Promise((r) => setTimeout(r, 1000));
    const res = await client.send(new GetQueryResultsCommand({ queryId: q.queryId }));
    if (res.status === "Complete") {
      const rows = res.results ?? [];
      return {
        byIp: rows.map((row) => ({
          key: row.find((f) => f.field === "ip")?.value ?? "",
          count: Number(row.find((f) => f.field === "cnt")?.value ?? "0"),
        })),
      };
    }
    if (res.status === "Failed" || res.status === "Cancelled") {
      throw new Error(`Logs Insights query ${res.status}`);
    }
  }
  throw new Error("Logs Insights query timeout");
}

// ---------------------------------------------------------------------------
// Recommendation
// ---------------------------------------------------------------------------

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

// Exported for unit tests — the mapping is pure, the fetch is not.
export function toSampleRow(s: SampledHTTPRequest): WafSampleRow {
  return {
    ts: s.Timestamp ? new Date(s.Timestamp).toISOString() : "",
    ip: s.Request?.ClientIP ?? "",
    country: s.Request?.Country ?? "",
    method: s.Request?.Method ?? "",
    path: samplePath(s),
    query: sampleQuery(s).slice(0, 120),
    userAgent: sampleHeader(s, "user-agent").slice(0, 80),
    action: s.Action ?? "",
    rule: s.RuleNameWithinRuleGroup ?? "",
    responseCode: s.ResponseCodeSent ?? null,
  };
}

// Raw sampled requests as table rows — lets the operator see the individual
// suspicious requests behind the aggregates (newest first, capped at 300).
export async function listSampleRows(): Promise<WafSampleRow[]> {
  const { samples } = await fetchSampledRequests();
  return samples
    .map(toSampleRow)
    .sort((a, b) => (a.ts < b.ts ? 1 : -1))
    .slice(0, 300);
}

// One paste-ready block for Amazon Q: situation, current WebACL rules JSON,
// the recommended rule JSON, local simulation numbers, and the questions.
export function applyHistory(): ApplyHistoryEntry[] {
  return listWafHistory().map((h) => ({
    id: h.id,
    ts: new Date(h.ts).toISOString(),
    ruleName: h.rule_name,
    action: h.action,
    status: h.status,
    detail: h.detail,
    canRollback: h.status === "SUCCESS" && h.action !== "ROLLBACK",
  }));
}
