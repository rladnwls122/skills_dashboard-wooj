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
import { ENV, WAF_LIMITS, isIpConcentrated, isLowPriorityPath, isPathSuspicious } from "./config";
import { logsClient, wafClient } from "./aws";
import { insertWafHistory, getWafHistory, listWafHistory } from "./db";
import { maskText } from "./mask";
import { classifyUa, queryHasBase64Blob } from "./threatsig";
import { runInsightsQuery } from "./logsinsights";
import { foldByAction, topKeyCounts, totals } from "./waflogagg";
import { errMsg } from "./cloudwatch";
import type {
  ApplyHistoryEntry,
  HttpSummary,
  IpStat,
  KeyCount,
  PathStat,
  ResolvedWindow,
  SimulationResult,
  StatusDistribution,
  WafAclInfo,
  WafRecommendation,
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
      const agg = await fetchWafLogInsights(win);
      return {
        totalSampled: agg.total,
        windowLabel: win.label,
        source: `WAF 로그 Logs Insights(${ENV.wafLogGroup}) · 구간 ${win.label} · 스캔 ${fmtBytes(agg.bytesScanned)} · 표본이 아닌 전수 집계`,
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
    notes: [],
  };
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
}

async function fetchWafLogInsights(win: ResolvedWindow): Promise<WafLogAggregation> {
  const bounds = { logGroup: ENV.wafLogGroup, startMs: win.startMs, endMs: win.endMs };
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

interface StoredRecommendation {
  rec: WafRecommendation;
  statement: Statement;
  isManagedGroup: boolean;
}

const recStore = new Map<string, StoredRecommendation>();

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// Competition directive: volumetric (rate-based) detection is disabled in this
// environment. The scenario's load generator drives heavy traffic at the served
// API surface from a single IP, and matching it on request volume would take
// down the scenario itself. No RateBasedStatement is ever recommended here —
// signature-based rules (UA / QueryString) and COUNT-only managed instrumentation
// remain. See APP_TRAFFIC_PATHS in config.ts.
export async function generateRecommendations(
  wafBlockedStatus: string,
  http4xxStatus: string,
  win: ResolvedWindow,
): Promise<WafRecommendation[]> {
  const summary = await buildHttpSummary(null, win);
  const recs: StoredRecommendation[] = [];
  const total = Math.max(summary.totalSampled, 1);

  const topUa = summary.byUa[0];
  const suspiciousUa =
    topUa &&
    (/(curl|python|wget|go-http|scanner|sqlmap|nikto|masscan|bot)/i.test(topUa.key) ||
      topUa.key === "(empty UA)");
  if (topUa && suspiciousUa && topUa.count >= 15 && topUa.count / total >= 0.2) {
    const sharePct = Math.round((topUa.count / total) * 100);
    const uaNeedle = topUa.key === "(empty UA)" ? "" : topUa.key.slice(0, 50);
    const id = `bytematch-ua-${Math.abs(hash(topUa.key))}`;
    if (uaNeedle) {
      recs.push({
        isManagedGroup: false,
        statement: {
          ByteMatchStatement: {
            SearchString: utf8(uaNeedle.toLowerCase()),
            FieldToMatch: { SingleHeader: { Name: "user-agent" } },
            TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
            PositionalConstraint: "CONTAINS",
          },
        },
        rec: {
          id,
          kind: "BYTE_MATCH",
          name: `dash-ua-match`,
          targetPattern: `User-Agent "${uaNeedle}" 반복 (${sharePct}%)`,
          criteria: { userAgent: uaNeedle },
          threshold: null,
          evaluationWindowSec: null,
          action: "COUNT",
          confidence: "MEDIUM",
          reason: `자동화 도구로 의심되는 User-Agent가 샘플의 ${sharePct}% 차지. ByteMatch(CONTAINS, lowercase)로 매칭.`,
          evidence: [`UA "${topUa.key}": ${topUa.count}/${total}건`],
          expectedImpact: `해당 UA 문자열 포함 요청 전부 매칭 — 동일 도구 사용 정상 사용자 존재 시 오탐 가능`,
          falsePositiveRisk: "MEDIUM",
          hasScopeDown: false,
        ruleJson: "",
        },
      });
    }
  }

  const topQuery = summary.queryPatterns[0];
  if (topQuery && topQuery.count >= 15 && topQuery.count / total >= 0.2) {
    const id = `bytematch-query-${Math.abs(hash(topQuery.key))}`;
    const needle = topQuery.key.slice(0, 60);
    recs.push({
      isManagedGroup: false,
      statement: {
        ByteMatchStatement: {
          SearchString: utf8(needle.toLowerCase()),
          FieldToMatch: { QueryString: {} },
          TextTransformations: [
            { Priority: 0, Type: "URL_DECODE" },
            { Priority: 1, Type: "LOWERCASE" },
          ],
          PositionalConstraint: "CONTAINS",
        },
      },
      rec: {
        id,
        kind: "BYTE_MATCH",
        name: `dash-query-match`,
        targetPattern: `QueryString 패턴 반복 "${needle.slice(0, 30)}…"`,
        criteria: { query: needle },
        threshold: null,
        evaluationWindowSec: null,
        action: "COUNT",
        confidence: "MEDIUM",
        reason: `동일 QueryString 패턴 반복 (${topQuery.count}건) — ByteMatch(QueryString, URL_DECODE+LOWERCASE).`,
        evidence: [`쿼리 "${needle}": ${topQuery.count}/${total}건`],
        expectedImpact: `동일 쿼리 파라미터 사용 요청 매칭. 정상 기능 쿼리라면 오탐 위험 높음 — COUNT 검증 필수.`,
        falsePositiveRisk: "HIGH",
        hasScopeDown: false,
        ruleJson: "",
      },
    });
  }

  // Unambiguous offensive-tool and spoofed-UA signatures get a Block rule, not
  // a Count one: these are never legitimate traffic. REQ-02 — ByteMatch is an
  // indexed, sub-millisecond match at the WAF edge returning a static 403, so
  // the backend never sees the request. The Go client is bypassed in classifyUa
  // (REQ-01); gobuster/zgrab still hit because a tool signature wins.
  const seenSig = new Set<string>();
  for (const ua of summary.byUa) {
    const hit = classifyUa(ua.key);
    if (!hit || seenSig.has(hit.label)) continue;
    // ByteMatch needs a literal that actually occurs in the header. SCANNER and
    // RECON labels are the tool name itself; a SPOOFED label ("base64-ua",
    // "injection-in-ua") is a category name that appears nowhere in the UA, so
    // a ByteMatch built from it would match nothing. Those need a regex — the
    // 규칙생성 탭 assembles one from threatsig.spoofedUaPatterns.
    if (hit.category === "SPOOFED") continue;
    seenSig.add(hit.label);
    const needle = hit.label;
    const id = `bytematch-threat-${Math.abs(hash(needle))}`;
    recs.push({
      isManagedGroup: false,
      statement: {
        ByteMatchStatement: {
          SearchString: utf8(needle),
          FieldToMatch: { SingleHeader: { Name: "user-agent" } },
          TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
          PositionalConstraint: "CONTAINS",
        },
      },
      rec: {
        id,
        kind: "BYTE_MATCH",
        name: "dash-threat-ua",
        targetPattern: `공격 시그니처 UA "${needle}" (${hit.category})`,
        criteria: { userAgent: needle },
        threshold: null,
        evaluationWindowSec: null,
        action: "BLOCK",
        confidence: "HIGH",
        reason: `알려진 ${hit.category === "SCANNER" ? "취약점 스캐너" : hit.category === "RECON" ? "정찰 스캐너" : "위조/난독"} 시그니처 "${needle}" 관측. ByteMatch(CONTAINS, lowercase) 인덱스 매칭으로 최전단에서 즉시 차단.`,
        evidence: [`UA "${ua.key}": ${ua.count}건`],
        expectedImpact: "정적 403 응답 — 백엔드 도달 전 WAF에서 종료되므로 응답 시간 영향 없음. 정상 Go/브라우저 트래픽은 매칭되지 않음.",
        falsePositiveRisk: "LOW",
        hasScopeDown: false,
        ruleJson: "",
      },
    });
  }

  const b64q = summary.queryPatterns.find((q) => queryHasBase64Blob(q.key));
  if (b64q) {
    const id = `bytematch-b64query-${Math.abs(hash(b64q.key))}`;
    recs.push({
      isManagedGroup: false,
      statement: {
        ByteMatchStatement: {
          SearchString: utf8(b64q.key.slice(0, 60)),
          FieldToMatch: { QueryString: {} },
          TextTransformations: [{ Priority: 0, Type: "URL_DECODE" }],
          PositionalConstraint: "CONTAINS",
        },
      },
      rec: {
        id,
        kind: "BYTE_MATCH",
        name: "dash-b64-query",
        targetPattern: `base64 난독 쿼리 "${b64q.key.slice(0, 40)}"`,
        criteria: { query: b64q.key.slice(0, 60) },
        threshold: null,
        evaluationWindowSec: null,
        action: "COUNT",
        confidence: "MEDIUM",
        reason: "쿼리 문자열에 base64로 인코딩된 페이로드 의심 패턴 관측. 우선 COUNT로 관찰 후 차단 권장 — 정상 base64 파라미터 오탐 가능.",
        evidence: [`쿼리 "${b64q.key.slice(0, 60)}": ${b64q.count}건`],
        expectedImpact: "해당 인코딩 문자열 포함 요청 계측 — 오탐 없음 확인 후 Block 전환.",
        falsePositiveRisk: "MEDIUM",
        hasScopeDown: false,
        ruleJson: "",
      },
    });
  }

  if (wafBlockedStatus !== "NORMAL") {
    recs.push({
      isManagedGroup: false,
      statement: {
        LabelMatchStatement: { Scope: "NAMESPACE", Key: "awswaf:managed:aws:" },
      },
      rec: {
        id: "label-managed-monitor",
        kind: "LABEL_MATCH",
        name: `dash-label-monitor`,
        targetPattern: "AWS 매니지드 룰 라벨 부착 요청",
        criteria: {},
        threshold: null,
        evaluationWindowSec: null,
        action: "COUNT",
        confidence: "LOW",
        reason: `BlockedRequests 증가 중 — 매니지드 룰(SQLi/KnownBadInputs)이 라벨링한 요청을 COUNT로 별도 계측해 차단 패턴 상세 파악.`,
        evidence: [`WAF BlockedRequests 상태: ${wafBlockedStatus}`],
        expectedImpact: `계측 전용(COUNT) — 트래픽 영향 없음`,
        falsePositiveRisk: "LOW",
        hasScopeDown: false,
        ruleJson: "",
      },
    });
    recs.push({
      isManagedGroup: true,
      statement: {
        ManagedRuleGroupStatement: {
          VendorName: "AWS",
          Name: "AWSManagedRulesAmazonIpReputationList",
        },
      },
      rec: {
        id: "managed-ip-reputation",
        kind: "MANAGED_GROUP",
        name: `dash-ip-reputation`,
        targetPattern: "AWS IP 평판 리스트 매칭 IP",
        criteria: {},
        threshold: null,
        evaluationWindowSec: null,
        action: "COUNT",
        confidence: "MEDIUM",
        reason: `차단 요청 증가 시 알려진 악성 IP 대역 여부 확인용. Override COUNT로 추가 — 차단 없이 매칭량만 계측.`,
        evidence: [`WAF BlockedRequests 상태: ${wafBlockedStatus}`],
        expectedImpact: `COUNT override — 트래픽 영향 없음. 매칭량 확인 후 차단 전환 판단.`,
        falsePositiveRisk: "LOW",
        hasScopeDown: false,
        ruleJson: "",
      },
    });
  }

  let nextPriority = 100;
  try {
    const { webAcl } = await getAclHandle();
    nextPriority =
      (webAcl.Rules ?? []).reduce((a, r) => Math.max(a, r.Priority ?? 0), 0) + 10;
  } catch {
    // priority preview falls back to 100 when the ACL is unreachable
  }
  for (const r of recs) {
    const ruleName = `${r.rec.name}-${r.rec.id.slice(0, 24)}`.slice(0, 128);
    r.rec.ruleJson = wafJson({
      Name: ruleName,
      Priority: nextPriority,
      Statement: r.statement,
      ...(r.isManagedGroup ? { OverrideAction: { Count: {} } } : { Action: { Count: {} } }),
      VisibilityConfig: {
        SampledRequestsEnabled: true,
        CloudWatchMetricsEnabled: true,
        MetricName: ruleName.replaceAll(/[^A-Za-z0-9_-]/g, "").slice(0, 128) || "dashRule",
      },
    });
    recStore.set(r.rec.id, r);
  }
  return recs.map((r) => r.rec);
}

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
export async function buildQHandoff(recommendationId: string): Promise<string> {
  const stored = recStore.get(recommendationId);
  if (!stored) throw new Error("recommendation expired — refresh the WAF panel");
  const rec = stored.rec;

  let aclName = ENV.wafWebAclName;
  let existingRulesJson = "[]";
  try {
    const { webAcl } = await getAclHandle();
    aclName = webAcl.Name ?? aclName;
    existingRulesJson = wafJson(
      (webAcl.Rules ?? []).map((r) => ({
        Name: r.Name,
        Priority: r.Priority,
        Statement: r.Statement,
        Action: r.Action,
        OverrideAction: r.OverrideAction,
      })),
    );
  } catch (e) {
    existingRulesJson = `조회 실패: ${e instanceof Error ? e.message : String(e)}`;
  }

  let simText = "시뮬레이션 미실행 (샘플 부족 또는 오류)";
  try {
    const sim = await simulateRecommendation(recommendationId, 0);
    simText = [
      `- 샘플 매칭: ${sim.matchedSampled}/${sim.totalSampled} (${sim.matchRatePct}%)`,
      `- 추정 매칭량 ${sim.estimatedMatched}건 / 추정 오탐 ${sim.estimatedFalsePositives}건 / 위험도 ${sim.riskLevel}`,
      ...sim.notes.map((n) => `- ${n}`),
    ].join("\n");
  } catch {
    // keep default text
  }

  const text = [
    `# WAF 규칙 추가 검토 요청`,
    ``,
    `AWS WAFv2 WebACL "${aclName}" (scope: ${ENV.wafScope})에 아래 규칙 추가를 검토 중이다.`,
    ``,
    `## 탐지 상황`,
    `- 대상 패턴: ${rec.targetPattern}`,
    `- 판단 근거: ${rec.reason}`,
    ...rec.evidence.map((e) => `- ${e}`),
    ``,
    `## 현재 WebACL 규칙 (JSON)`,
    "```json",
    existingRulesJson,
    "```",
    ``,
    `## 추가하려는 규칙 (COUNT 모드, JSON)`,
    "```json",
    rec.ruleJson,
    "```",
    ``,
    `## 로컬 시뮬레이션 결과 (GetSampledRequests 기반 추정)`,
    simText,
    ``,
    `## 질문`,
    `1. 이 규칙을 현재 WebACL에 추가하면 정상 트래픽을 차단할 위험이 있는가?`,
    `2. 조건(경로/임계치/scope-down)을 더 안전하게 만들려면 어떻게 수정해야 하는가? 수정안을 동일한 Rule JSON 형식으로 제시해달라.`,
    `3. 우선순위·WCU·기존 규칙과의 충돌 관점에서 문제가 있는가?`,
  ].join("\n");
  return maskText(text);
}

// ---------------------------------------------------------------------------
// Simulation (local evaluation against sampled requests — no WebACL change)
// ---------------------------------------------------------------------------

export async function simulateRecommendation(
  recommendationId: string,
  totalRequestsPerWindow: number,
): Promise<SimulationResult> {
  const stored = recStore.get(recommendationId);
  if (!stored) throw new Error("recommendation expired — refresh the WAF panel");
  const { samples, windowMinutes } = await fetchSampledRequests();
  const rec = stored.rec;
  const notes: string[] = [];

  const matches = samples.filter((s) => sampleMatches(s, rec));
  const totalSampled = Math.max(samples.length, 1);
  const matchRate = matches.length / totalSampled;
  const estimatedTotal = Math.max(totalRequestsPerWindow, samples.length);
  let estimatedMatched = Math.round(matchRate * estimatedTotal);

  if (rec.kind === "RATE_BASED" && rec.threshold !== null) {
    const estRatePer5m = Math.round((estimatedMatched / windowMinutes) * 5);
    if (estRatePer5m < rec.threshold) {
      notes.push(
        `추정 5분당 매칭률 ~${estRatePer5m}건 < 임계치 ${rec.threshold} — 현재 수준에서는 매칭 0건 예상`,
      );
      estimatedMatched = 0;
    } else {
      notes.push(`추정 5분당 매칭률 ~${estRatePer5m}건 ≥ 임계치 ${rec.threshold}`);
    }
  }

  const legitLooking = matches.filter(
    (s) =>
      /mozilla/i.test(sampleHeader(s, "user-agent")) &&
      !isLowPriorityPath(samplePath(s)) &&
      samplePath(s).startsWith("/v1/"),
  );
  const fpRate = matches.length > 0 ? legitLooking.length / matches.length : 0;
  const estimatedFalsePositives = Math.round(estimatedMatched * fpRate);
  const estimatedLegitBlocked = rec.action === "BLOCK" ? estimatedFalsePositives : 0;
  if (rec.action === "COUNT") {
    notes.push("COUNT 모드 — 실제 차단 0건, 매칭량 계측만 수행");
  }
  notes.push(
    `샘플 ${samples.length}건 기반 외삽 추정치 — 실제 값은 COUNT 적용 후 CloudWatch로 검증 필요`,
  );

  const riskLevel =
    fpRate > 0.3 ? "HIGH" : fpRate > 0.1 ? "MEDIUM" : "LOW";

  return {
    recommendationId,
    totalSampled: samples.length,
    matchedSampled: matches.length,
    matchRatePct: Math.round(matchRate * 1000) / 10,
    estimatedTotalRequests: estimatedTotal,
    estimatedMatched,
    estimatedFalsePositives,
    estimatedLegitBlocked,
    riskLevel,
    notes,
  };
}

function sampleMatches(s: SampledHTTPRequest, rec: WafRecommendation): boolean {
  const c = rec.criteria;
  if (c.ip && s.Request?.ClientIP !== c.ip) return false;
  if (c.path && !samplePath(s).toLowerCase().startsWith(c.path.toLowerCase())) return false;
  if (c.userAgent && !sampleHeader(s, "user-agent").toLowerCase().includes(c.userAgent.toLowerCase()))
    return false;
  if (c.query && !sampleQuery(s).toLowerCase().includes(c.query.toLowerCase())) return false;
  if (rec.kind === "LABEL_MATCH") return (s.Labels?.length ?? 0) > 0;
  if (rec.kind === "MANAGED_GROUP") return s.Action === "BLOCK";
  return Boolean(c.ip || c.path || c.userAgent || c.query);
}

// ---------------------------------------------------------------------------
// Apply / rollback (explicit approval only — spec §19-6, §19-7, §29)
// ---------------------------------------------------------------------------

export interface ApplyResult {
  historyId: number;
  ruleName: string;
  priority: number;
  mode: "COUNT" | "BLOCK";
  wcuAfter: number;
}

export async function applyRecommendation(
  recommendationId: string,
  mode: "COUNT" | "BLOCK",
): Promise<ApplyResult> {
  const stored = recStore.get(recommendationId);
  if (!stored) throw new Error("recommendation expired — refresh the WAF panel");
  const client = wafClient();
  const { webAcl, lockToken } = await getAclHandle();
  const existing = webAcl.Rules ?? [];
  const ruleName = `${stored.rec.name}-${recommendationId.slice(0, 24)}`.slice(0, 128);

  if (mode === "BLOCK") {
    const priorCount = listWafHistory().find(
      (h) => h.rule_name === ruleName && h.action === "COUNT" && h.status === "SUCCESS",
    );
    if (!priorCount) {
      throw new Error("BLOCK 전환은 동일 규칙의 COUNT 적용·검증 이력이 있어야 가능");
    }
  }

  if (existing.some((r) => r.Name === ruleName)) {
    throw new Error(`동일 이름 규칙이 이미 존재: ${ruleName}`);
  }
  const newStatementJson = JSON.stringify(stored.statement);
  if (existing.some((r) => JSON.stringify(r.Statement) === newStatementJson)) {
    throw new Error("동일 조건의 규칙이 이미 WebACL에 존재");
  }

  const maxPriority = existing.reduce((a, r) => Math.max(a, r.Priority ?? 0), 0);
  const priority = maxPriority + 10;

  const newRule: Rule = {
    Name: ruleName,
    Priority: priority,
    Statement: stored.statement,
    VisibilityConfig: {
      SampledRequestsEnabled: true,
      CloudWatchMetricsEnabled: true,
      MetricName: ruleName.replaceAll(/[^A-Za-z0-9_-]/g, "").slice(0, 128) || "dashRule",
    },
    ...(stored.isManagedGroup
      ? { OverrideAction: mode === "COUNT" ? { Count: {} } : { None: {} } }
      : { Action: mode === "COUNT" ? { Count: {} } : { Block: {} } }),
  };

  const capacity = await client.send(
    new CheckCapacityCommand({ Scope: ENV.wafScope, Rules: [...existing, newRule] }),
  );
  const wcuAfter = Number(capacity.Capacity ?? 0);
  if (wcuAfter > WAF_LIMITS.maxWcu) {
    throw new Error(`WCU 초과: ${wcuAfter} > ${WAF_LIMITS.maxWcu}`);
  }

  const priorRulesJson = JSON.stringify(existing);
  let historyId: number;
  try {
    await client.send(
      new UpdateWebACLCommand({
        Name: webAcl.Name,
        Id: webAcl.Id,
        Scope: ENV.wafScope,
        DefaultAction: webAcl.DefaultAction,
        Description: webAcl.Description,
        Rules: [...existing, newRule],
        VisibilityConfig: webAcl.VisibilityConfig,
        LockToken: lockToken,
      }),
    );
    historyId = insertWafHistory(
      ruleName,
      mode,
      "SUCCESS",
      `priority=${priority}, wcu=${wcuAfter}, kind=${stored.rec.kind}`,
      priorRulesJson,
    );
  } catch (e) {
    insertWafHistory(
      ruleName,
      mode,
      "FAILED",
      e instanceof Error ? e.message : String(e),
      priorRulesJson,
    );
    throw e;
  }
  return { historyId, ruleName, priority, mode, wcuAfter };
}

export async function rollbackWaf(historyId: number): Promise<void> {
  const row = getWafHistory(historyId);
  if (!row) throw new Error(`이력 없음: ${historyId}`);
  if (row.status !== "SUCCESS") throw new Error("성공한 적용 건만 롤백 가능");
  const priorRules = JSON.parse(row.prior_rules) as Rule[];
  const client = wafClient();
  const { webAcl, lockToken } = await getAclHandle();
  await client.send(
    new UpdateWebACLCommand({
      Name: webAcl.Name,
      Id: webAcl.Id,
      Scope: ENV.wafScope,
      DefaultAction: webAcl.DefaultAction,
      Description: webAcl.Description,
      Rules: priorRules,
      VisibilityConfig: webAcl.VisibilityConfig,
      LockToken: lockToken,
    }),
  );
  insertWafHistory(row.rule_name, "ROLLBACK", "SUCCESS", `rolled back history #${historyId}`, "[]");
}

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
