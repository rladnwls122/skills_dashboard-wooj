// WAF reads and the HTTP traffic summary.

import {
  GetSampledRequestsCommand,
  GetWebACLCommand,
  ListWebACLsCommand,
  type SampledHTTPRequest,
  type Scope,
  type WebACL,
} from "@aws-sdk/client-wafv2";

import { cached } from "../cache/cache.ts";
import { POLLING } from "../config/config.ts";
import { isIpConcentrated, isLowPriorityPath, isPathSuspicious } from "../config/paths.ts";
import { WAF_INSIGHTS_TTL_MS, WAF_LIMITS } from "../config/thresholds.ts";
import type {
  HttpSummary,
  IpStat,
  KeyCount,
  PathStat,
  ResolvedWindow,
  StatusDistribution,
  WafAclInfo,
  WafSampleRow,
} from "../../src/lib/types.ts";
import type { WafAclRule } from "../types/types.ts";
import { errMsg, type AWS } from "./clients.ts";
import {
  fmtBytes,
  runInsightsQuery,
  type InsightsParams,
  type InsightsResult,
  type InsightsRow,
} from "./insights.ts";

export interface AclHandle {
  webAcl: WebACL;
  lockToken: string;
  arn: string;
  /**
   * False when the configured name matched nothing and the first WebACL in the
   * account was taken instead. Reads may proceed on a substitute — an operator
   * who mistyped the name still wants to see something — but a write must not,
   * so the caller has to check.
   */
  exact: boolean;
}

export async function getAclHandle(a: AWS): Promise<AclHandle> {
  const client = a.wafClient(a.settings.wafRegion());
  const scope = a.settings.wafScope() as Scope;
  const list = await client.send(new ListWebACLsCommand({ Scope: scope }));
  const name = a.settings.wafWebAclName();
  const all = list.WebACLs ?? [];
  const match = all.find((w) => w.Name === name);
  const summary = match ?? all[0];
  if (!summary?.Name || !summary.Id || !summary.ARN) {
    throw new Error(`WebACL not found (scope=${scope}, name=${name})`);
  }
  const res = await client.send(
    new GetWebACLCommand({ Name: summary.Name, Id: summary.Id, Scope: scope }),
  );
  if (!res.WebACL || !res.LockToken) throw new Error("GetWebACL returned empty result");
  return {
    webAcl: res.WebACL,
    lockToken: res.LockToken,
    arn: summary.ARN,
    exact: match !== undefined,
  };
}

/**
 * The handle a write must use. Refuses the substitute getAclHandle falls back
 * to: rewriting the rule list of a WebACL the operator did not name is the one
 * mistake in this screen that cannot be undone from the screen itself, and the
 * grader evaluates whichever ACL is actually attached — so a "SUCCESS" against
 * the wrong one is worse than a refusal.
 */
export async function getAclHandleForWrite(a: AWS): Promise<AclHandle> {
  const h = await getAclHandle(a);
  if (!h.exact) {
    throw new Error(
      `WebACL "${a.settings.wafWebAclName()}" 을(를) 찾지 못했습니다 (scope=${a.settings.wafScope()}). ` +
        `계정에는 "${h.webAcl.Name}" 이(가) 있습니다 — 다른 WebACL 을 덮어쓰지 않도록 규칙 적용을 중단했습니다. ` +
        `설정에서 WAF_WEB_ACL_NAME 과 WAF_SCOPE 를 확인하세요.`,
    );
  }
  return h;
}

export async function getAclInfo(a: AWS): Promise<WafAclInfo> {
  const h = await getAclHandle(a);
  const acl = h.webAcl;
  const rules: WafAclRule[] = (acl.Rules ?? []).map((r) => {
    let action = "GROUP";
    if (r.Action?.Block) action = "BLOCK";
    else if (r.Action?.Count) action = "COUNT";
    else if (r.OverrideAction?.Count) action = "COUNT(override)";
    else if (r.Action?.Allow) action = "ALLOW";
    return { name: r.Name ?? "", priority: r.Priority ?? 0, action };
  });
  return {
    name: acl.Name ?? "",
    id: acl.Id ?? "",
    scope: a.settings.wafScope(),
    capacityUsed: acl.Capacity ?? 0,
    ruleCount: (acl.Rules ?? []).length,
    rules,
  };
}

// --- sampled requests --------------------------------------------------------

export interface SampleSet {
  samples: SampledHTTPRequest[];
  windowMinutes: number;
}

export function fetchSampledRequests(a: AWS): Promise<SampleSet> {
  return cached("waf:samples", 30_000, async () => {
    const client = a.wafClient(a.settings.wafRegion());
    const h = await getAclHandle(a);
    const end = new Date();
    const start = new Date(end.getTime() - WAF_LIMITS.sampleWindowMinutes * 60_000);

    // First-seen order, deduplicated: the WebACL's own metric name plus one per
    // rule.
    const order: string[] = [];
    const seen = new Set<string>();
    const add = (name: string | undefined): void => {
      if (!name || seen.has(name)) return;
      seen.add(name);
      order.push(name);
    };
    add(h.webAcl.VisibilityConfig?.MetricName);
    for (const r of h.webAcl.Rules ?? []) add(r.VisibilityConfig?.MetricName);

    const samples: SampledHTTPRequest[] = [];
    for (const metricName of order) {
      try {
        const res = await client.send(
          new GetSampledRequestsCommand({
            WebAclArn: h.arn,
            RuleMetricName: metricName,
            Scope: a.settings.wafScope() as Scope,
            TimeWindow: { StartTime: start, EndTime: end },
            MaxItems: 500,
          }),
        );
        samples.push(...(res.SampledRequests ?? []));
      } catch {
        // One rule's samples failing must not kill the whole set.
      }
    }
    return { samples, windowMinutes: WAF_LIMITS.sampleWindowMinutes };
  });
}

function sampleUri(s: SampledHTTPRequest): string {
  return s.Request?.URI ?? "";
}

function samplePath(s: SampledHTTPRequest): string {
  const uri = sampleUri(s);
  const i = uri.indexOf("?");
  return i >= 0 ? uri.slice(0, i) : uri;
}

function sampleQuery(s: SampledHTTPRequest): string {
  const uri = sampleUri(s);
  const i = uri.indexOf("?");
  return i >= 0 ? uri.slice(i + 1) : "";
}

function sampleHeader(s: SampledHTTPRequest, name: string): string {
  for (const h of s.Request?.Headers ?? []) {
    if ((h.Name ?? "").toLowerCase() === name) return h.Value ?? "";
  }
  return "";
}

const BORING_HEADERS = new Set([
  "host", "user-agent", "accept", "accept-encoding", "accept-language",
  "content-type", "content-length", "connection", "x-forwarded-for",
  "x-forwarded-proto", "x-forwarded-port", "x-amzn-trace-id", "via", "cookie",
  "authorization",
]);

/** Preserves first-seen order so ties sort deterministically. */
class Counter {
  readonly counts = new Map<string, number>();

  add(key: string, n: number): void {
    this.counts.set(key, (this.counts.get(key) ?? 0) + n);
  }

  set(key: string, n: number): void {
    this.counts.set(key, n);
  }

  top(n: number): KeyCount[] {
    const out: KeyCount[] = [];
    for (const [key, count] of this.counts) out.push({ key, count });
    out.sort((x, y) => y.count - x.count);
    return out.slice(0, n);
  }
}

/**
 * Explains an empty panel: GetSampledRequests only samples requests that a rule
 * matched, so "no samples" means "nothing was collected", not "nothing
 * suspicious is happening".
 */
export function emptySampleNotes(total: number): string[] {
  if (total > 0) return [];
  return [
    "샘플 0건 — 트래픽이 없다는 뜻이 아니라 수집되지 않았다는 뜻입니다. WAF GetSampledRequests 는 규칙에 매칭된 요청만 표본으로 남기므로, 아무 규칙도 매칭하지 않는 WebACL 에서는 항상 0건입니다.",
    "따라서 경로·IP·User-Agent 통계가 전부 비어 있고, 이 상태에서는 UA 규칙을 조립할 수 없습니다.",
    "채우는 방법 ①: WAF 로깅을 CloudWatch Logs 로 켜고 .env 의 WAF_LOG_GROUP 을 그 로그 그룹으로 지정 — 표본이 아닌 전수 집계로 바뀝니다.",
    "채우는 방법 ②: WebACL 에 광범위한 COUNT 규칙을 하나 추가 — 차단 없이 매칭만 시켜 표본을 만듭니다.",
    "앱 액세스 로그로는 대체할 수 없습니다 — 바이너리의 [GIN] 액세스 라인에는 User-Agent 가 없습니다(시각 · 상태 · 지연 · client IP · 메소드 · 경로만).",
  ];
}

export async function buildHttpSummary(
  a: AWS,
  statusDist: StatusDistribution | null,
  win: ResolvedWindow,
): Promise<HttpSummary> {
  // Real counts over the shared window when WAF logs are available; the
  // sampled-requests path below is the fallback and says so.
  const logGroup = a.settings.wafLogGroup();
  // Local, not module-level: two summaries can be in flight at once (the
  // metrics panel and the rule assembler both build one), and a shared slot
  // would let one request pin the other request.s failure onto its own
  // provenance line — the line whose whole job is to say whether the numbers
  // are a full count or a 500-per-rule sample.
  let insightsFallbackReason = "";
  if (logGroup !== "") {
    try {
      const agg = await fetchWafLogInsightsCached(a, win);
      return {
        totalSampled: agg.total,
        windowLabel: win.label,
        source:
          `WAF 로그 Logs Insights(${logGroup}) · 구간 ${win.label} · 스캔 ${fmtBytes(agg.bytesScanned)}` +
          ` · 표본이 아닌 전수 집계${insightsAgeNote(agg.coveredEndMs, Date.now())}`,
        byPath: agg.byPath,
        byIp: agg.byIp,
        byUa: agg.byUa,
        // Neither figure is derived here: the log fold is a path×action count, so
        // a per-UA verdict split and per-surface arrival counts would each need
        // their own query. Empty and null are the honest values — a zero that
        // reads as "observed none" is what the notes list exists to prevent.
        uaActions: [],
        surface: null,
        byMethod: agg.byMethod,
        queryPatterns: agg.queryPatterns,
        headerPatterns: [],
        blockedTotal: agg.blockedTotal,
        statusDist,
        detailedStatus: null,
        notes: [
          "헤더 패턴은 WAF 로그 집계에서 수집하지 않음 — 헤더는 요청마다 순서가 달라 인덱스로 집계할 수 없다. 샘플 모드(WAF_LOG_GROUP 미설정)에서만 나온다.",
          // Whichever secondary queries failed. Empty in the normal case, so the
          // note list reads exactly as it did before when nothing went wrong.
          ...agg.notes,
        ],
      };
    } catch (e) {
      // Fall through to sampling, but say why the better source is missing.
      insightsFallbackReason = errMsg(e);
    }
  }

  const set = await fetchSampledRequests(a);

  const byPathMap = new Map<string, { count: number; blocked: number }>();
  const byIp = new Counter();
  const byUa = new Counter();
  const byMethod = new Counter();
  const byQuery = new Counter();
  const byHeader = new Counter();

  for (const s of set.samples) {
    const path = samplePath(s);
    let entry = byPathMap.get(path);
    if (!entry) {
      entry = { count: 0, blocked: 0 };
      byPathMap.set(path, entry);
    }
    entry.count++;
    if (s.Action === "BLOCK") entry.blocked++;

    if (s.Request?.ClientIP) byIp.add(s.Request.ClientIP, 1);
    if (s.Request?.Method) byMethod.add(s.Request.Method, 1);

    byUa.add(sampleHeader(s, "user-agent") || "(empty UA)", 1);

    const query = sampleQuery(s);
    if (query !== "") byQuery.add(query.slice(0, 120), 1);

    for (const h of s.Request?.Headers ?? []) {
      const name = (h.Name ?? "").toLowerCase();
      if (name === "" || BORING_HEADERS.has(name)) continue;
      byHeader.add(`${name}: ${(h.Value ?? "").slice(0, 60)}`, 1);
    }
  }

  const total = set.samples.length;
  // Full-population blocked count, taken before byPath is truncated to 20.
  let blockedTotal = 0;
  for (const v of byPathMap.values()) blockedTotal += v.blocked;

  const pathStats: PathStat[] = [];
  for (const [path, v] of byPathMap) {
    pathStats.push({
      path,
      count: v.count,
      blocked: v.blocked,
      lowPriority: isLowPriorityPath(path),
      suspicious: isPathSuspicious(path, v.count, total),
    });
  }
  pathStats.sort((x, y) => y.count - x.count);

  let source = `WAF GetSampledRequests (최근 ${set.windowMinutes}분, 샘플 ${total}건 — 규칙당 500건 상한이라 전수가 아님, 선택한 구간을 따르지 않음)`;
  if (insightsFallbackReason !== "") {
    source += " · WAF 로그 집계 실패로 폴백: " + insightsFallbackReason;
  } else if (logGroup === "") {
    source += " · WAF_LOG_GROUP 을 설정하면 선택 구간의 전수 집계로 바뀜";
  }
  if (logGroup !== "") {
    try {
      for (const r of await fetchWafLogIpCounts(a)) {
        const cur = byIp.counts.get(r.key);
        if (cur === undefined || r.count > cur) byIp.set(r.key, r.count);
      }
      source += ` + WAF 로그(${logGroup})`;
    } catch {
      source += " (WAF 로그 조회 실패, 샘플만 사용)";
    }
  }

  const denom = total < 1 ? 1 : total;
  const ipStats: IpStat[] = byIp.top(10).map((r) => ({
    key: r.key,
    count: r.count,
    sharePct: Math.round((r.count / denom) * 100),
    concentrated: isIpConcentrated(r.count, total),
  }));

  return {
    totalSampled: total,
    windowLabel: `${set.windowMinutes}m`,
    source,
    byPath: pathStats.slice(0, 20),
    byIp: ipStats,
    byUa: byUa.top(10),
    // Sampled requests cannot answer either question: a sample is not a count,
    // so an arrival figure would understate every total next to it, and the
    // sample carries no allowed-vs-blocked split per client.
    uaActions: [],
    surface: null,
    byMethod: byMethod.top(8),
    queryPatterns: byQuery.top(10),
    headerPatterns: byHeader.top(10),
    blockedTotal,
    statusDist,
    detailedStatus: null,
    notes: emptySampleNotes(total),
  };
}

// --- WAF logs via Logs Insights ---------------------------------------------

interface WafLogAggregation {
  byPath: PathStat[];
  byIp: IpStat[];
  byUa: KeyCount[];
  byMethod: KeyCount[];
  queryPatterns: KeyCount[];
  total: number;
  blockedTotal: number;
  bytesScanned: number;
  /**
   * End of the span these numbers actually cover — a cached result is older than
   * the window the caller resolved, and the panel has to say so.
   */
  coveredEndMs: number;
  /**
   * Which of the secondary aggregations came back empty because their query
   * failed, rather than because the traffic had nothing in it. An empty table
   * with no explanation is the one thing this panel must never show.
   */
  notes: string[];
}

/**
 * Keyed by span alone: the aggregation groups by key, never by time bucket, so
 * the interval does not change the result.
 */
function fetchWafLogInsightsCached(a: AWS, win: ResolvedWindow): Promise<WafLogAggregation> {
  const key = `waf:insights:${a.settings.wafLogGroup()}:${win.windowMin}`;
  return cached(key, WAF_INSIGHTS_TTL_MS, () => fetchWafLogInsights(a, win), POLLING.logFailTtl);
}

interface Folded {
  count: number;
  blocked: number;
}

function rowCount(row: InsightsRow): number {
  const n = Number.parseFloat(row.cnt ?? "");
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

function foldByAction(rows: InsightsRow[], keyField: string): Map<string, Folded> {
  const out = new Map<string, Folded>();
  for (const r of rows) {
    const key = r[keyField] ?? "";
    let entry = out.get(key);
    if (!entry) {
      entry = { count: 0, blocked: 0 };
      out.set(key, entry);
    }
    const n = rowCount(r);
    entry.count += n;
    if ((r.action ?? "").toUpperCase() === "BLOCK") entry.blocked += n;
  }
  return out;
}

function insightsAgeNote(coveredEndMs: number, nowMs: number): string {
  const min = Math.floor((nowMs - coveredEndMs) / 60_000);
  return min >= 1 ? ` · ${min}분 전 집계` : "";
}

function topKeyCounts(rows: InsightsRow[], keyField: string, n: number): KeyCount[] {
  const out: KeyCount[] = [];
  for (const r of rows) {
    const key = r[keyField];
    if (key) out.push({ key, count: rowCount(r) });
  }
  out.sort((x, y) => y.count - x.count);
  return out.slice(0, n);
}

async function fetchWafLogInsights(a: AWS, win: ResolvedWindow): Promise<WafLogAggregation> {
  // The region matters and is not the workload region: a CLOUDFRONT-scope WAF
  // only writes its logs in us-east-1.
  const base: Omit<InsightsParams, "query"> = {
    region: a.settings.wafRegion(),
    logGroup: a.settings.wafLogGroup(),
    startMs: win.startMs,
    endMs: win.endMs,
  };
  const run = (query: string) => runInsightsQuery(a, { ...base, query });

  // Five independent aggregations over one log group, so they go out together.
  // Run in sequence they were five 20-second deadlines end to end — nearly two
  // minutes worst case, with metricsPanel awaiting this inline and every
  // concurrent caller parked on the same cached() promise for the whole of it,
  // which is a hung dashboard rather than a slow one. Actual concurrency is
  // still bounded by the Insights semaphore in clients.ts; what changes here is
  // only that the wall clock stops being the sum of the deadlines.
  //
  // The User-Agent lives inside httpRequest.headers[], whose index varies per
  // request, so it is pulled off the raw message rather than a JSON field.
  const [pathSettled, ipSettled, uaSettled, methodSettled, argsSettled] =
    await Promise.allSettled([
      run("stats count(*) as cnt by httpRequest.uri as path, action | sort cnt desc | limit 200"),
      run("stats count(*) as cnt by httpRequest.clientIp as ip, action | sort cnt desc | limit 100"),
      run(
        `parse @message /"name":"(?i)user-agent","value":"(?<ua>[^"]*)"/ | stats count(*) as cnt by ua | sort cnt desc | limit 20`,
      ),
      run("stats count(*) as cnt by httpRequest.httpMethod as method | sort cnt desc | limit 10"),
      run(
        "filter httpRequest.args != '' | stats count(*) as cnt by httpRequest.args as args | sort cnt desc | limit 20",
      ),
    ]);

  // The path query is load-bearing: `total` and `blockedTotal` are folded out of
  // it, and every share and suspicion threshold is measured against that total.
  // Reporting "0건" for a window that had traffic is worse than reporting
  // nothing, so its failure fails the whole aggregation and the caller drops to
  // the sampled-requests path, which states the downgrade on the panel.
  if (pathSettled.status === "rejected") throw asError(pathSettled.reason);
  const pathRes = pathSettled.value;

  // The other four only add columns. One of them timing out must not throw away
  // the four that came back — but it must not pass for "nothing observed"
  // either, so the loss is written down and travels to the panel's notes.
  const notes: string[] = [];
  const optional = (
    settled: PromiseSettledResult<InsightsResult>,
    what: string,
  ): InsightsResult => {
    if (settled.status === "fulfilled") return settled.value;
    notes.push(
      `${what} 집계 실패 — 해당 표가 비어 있는 것은 "관측 없음"이 아니라 조회 실패입니다: ` +
        errMsg(settled.reason),
    );
    return { rows: [], bytesScanned: 0, recordsMatched: 0, windowLabel: "" };
  };
  const ipRes = optional(ipSettled, "클라이언트 IP");
  const uaRes = optional(uaSettled, "User-Agent");
  const methodRes = optional(methodSettled, "HTTP 메소드");
  const argsRes = optional(argsSettled, "쿼리 문자열");

  const pathFolded = foldByAction(pathRes.rows, "path");
  let total = 0;
  let blockedTotal = 0;
  for (const v of pathFolded.values()) {
    total += v.count;
    blockedTotal += v.blocked;
  }

  const byPath: PathStat[] = [];
  for (const [path, v] of pathFolded) {
    byPath.push({
      path,
      count: v.count,
      blocked: v.blocked,
      lowPriority: isLowPriorityPath(path),
      suspicious: isPathSuspicious(path, v.count, total),
    });
  }
  byPath.sort((x, y) => y.count - x.count);

  const ipFolded = foldByAction(ipRes.rows, "ip");
  const denom = total < 1 ? 1 : total;
  const byIp: IpStat[] = [];
  for (const [key, v] of ipFolded) {
    if (key === "") continue;
    byIp.push({
      key,
      count: v.count,
      sharePct: Math.round((v.count / denom) * 100),
      concentrated: isIpConcentrated(v.count, total),
    });
  }
  byIp.sort((x, y) => y.count - x.count);

  const queryPatterns = topKeyCounts(argsRes.rows, "args", 10).map((r) => ({
    key: r.key.slice(0, 120),
    count: r.count,
  }));

  return {
    byPath: byPath.slice(0, 20),
    byIp: byIp.slice(0, 10),
    byUa: topKeyCounts(uaRes.rows, "ua", 10),
    byMethod: topKeyCounts(methodRes.rows, "method", 8),
    queryPatterns,
    total,
    blockedTotal,
    bytesScanned:
      pathRes.bytesScanned +
      ipRes.bytesScanned +
      uaRes.bytesScanned +
      methodRes.bytesScanned +
      argsRes.bytesScanned,
    coveredEndMs: win.endMs,
    notes,
  };
}

/** Promise rejection reasons are `unknown`; the callers all want an Error. */
function asError(reason: unknown): Error {
  return reason instanceof Error ? reason : new Error(String(reason));
}

/** The 15-minute top-IP merge used by the sampling fallback. */
async function fetchWafLogIpCounts(a: AWS): Promise<KeyCount[]> {
  const res = await runInsightsQuery(a, {
    region: a.settings.wafRegion(),
    logGroup: a.settings.wafLogGroup(),
    windowMs: 15 * 60_000,
    query: "stats count(*) as cnt by httpRequest.clientIp as ip | sort cnt desc | limit 10",
  });
  return res.rows.map((row) => ({ key: row.ip ?? "", count: rowCount(row) }));
}

// --- sample rows -------------------------------------------------------------

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

/** Raw sampled requests as table rows (newest first, capped at 300). */
export async function listSampleRows(a: AWS): Promise<WafSampleRow[]> {
  const set = await fetchSampledRequests(a);
  const rows = set.samples.map(toSampleRow);
  rows.sort((x, y) => (x.ts < y.ts ? 1 : x.ts > y.ts ? -1 : 0));
  return rows.slice(0, 300);
}
