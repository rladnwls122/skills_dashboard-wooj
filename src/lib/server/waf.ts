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
import { ENV, WAF_LIMITS, isLowPriorityPath } from "./config";
import { logsClient, wafClient } from "./aws";
import { insertWafHistory, getWafHistory, listWafHistory } from "./db";
import type {
  ApplyHistoryEntry,
  HttpSummary,
  KeyCount,
  PathStat,
  SimulationResult,
  StatusDistribution,
  WafAclInfo,
  WafRecommendation,
} from "@/lib/types";

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
): Promise<HttpSummary> {
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

  const pathStats: PathStat[] = [...byPath.entries()]
    .map(([path, v]) => ({
      path,
      count: v.count,
      blocked: v.blocked,
      lowPriority: isLowPriorityPath(path),
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  let source = `WAF GetSampledRequests (최근 ${windowMinutes}분, 샘플 ${samples.length}건)`;
  if (ENV.wafLogGroup) {
    try {
      const logAgg = await fetchWafLogAggregation();
      for (const r of logAgg.byIp) byIp.set(r.key, Math.max(byIp.get(r.key) ?? 0, r.count));
      source += ` + WAF 로그(${ENV.wafLogGroup})`;
    } catch {
      source += " (WAF 로그 조회 실패, 샘플만 사용)";
    }
  }

  return {
    totalSampled: samples.length,
    windowLabel: `${windowMinutes}m`,
    source,
    byPath: pathStats,
    byIp: topCounts(byIp, 10),
    byUa: topCounts(byUa, 10),
    byMethod: topCounts(byMethod, 8),
    queryPatterns: topCounts(byQuery, 10),
    headerPatterns: topCounts(byHeader, 10),
    statusDist,
    detailedStatus: null,
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

function pathScopeDown(path: string): Statement {
  return {
    ByteMatchStatement: {
      SearchString: utf8(path),
      FieldToMatch: { UriPath: {} },
      TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
      PositionalConstraint: "STARTS_WITH",
    },
  };
}

export async function generateRecommendations(
  wafBlockedStatus: string,
  http4xxStatus: string,
): Promise<WafRecommendation[]> {
  const { samples, windowMinutes } = await fetchSampledRequests();
  const summary = await buildHttpSummary(null);
  const recs: StoredRecommendation[] = [];
  const total = Math.max(summary.totalSampled, 1);

  const topIp = summary.byIp[0];
  if (topIp && topIp.count >= 20 && topIp.count / total >= 0.3) {
    const sharePct = Math.round((topIp.count / total) * 100);
    const observedPer5m = Math.ceil((topIp.count / windowMinutes) * 5);
    const est = estimateTotalFactor(samples.length);
    const limit = Math.max(WAF_LIMITS.minRateLimit, observedPer5m * est * 2);
    const id = `rate-ip-${topIp.key.replaceAll(".", "-")}`;
    recs.push({
      isManagedGroup: false,
      statement: {
        RateBasedStatement: {
          Limit: limit,
          AggregateKeyType: "IP",
          EvaluationWindowSec: 300,
        },
      },
      rec: {
        id,
        kind: "RATE_BASED",
        name: `dash-rate-ip`,
        targetPattern: `IP ${topIp.key} 집중 (샘플 점유율 ${sharePct}%)`,
        criteria: { ip: topIp.key },
        threshold: limit,
        evaluationWindowSec: 300,
        action: "COUNT",
        confidence: sharePct >= 50 ? "HIGH" : "MEDIUM",
        reason: `단일 IP가 샘플 요청의 ${sharePct}%를 차지 — 과도한 요청 집중 가능성. Rate-based 규칙으로 5분당 ${limit}건 초과 시 매칭.`,
        evidence: [
          `IP ${topIp.key}: 샘플 ${topIp.count}/${total}건 (${windowMinutes}분)`,
          `추정 5분당 요청률: ~${observedPer5m * est}건`,
        ],
        expectedImpact: `임계치 초과 IP만 매칭 — 정상 저빈도 사용자는 영향 없을 것으로 추정 (검증 필요)`,
        falsePositiveRisk: "LOW",
        hasScopeDown: false,
      },
    });
  }

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
        },
      });
    }
  }

  const topPath = summary.byPath.find((p) => !p.lowPriority);
  if (topPath && topPath.count >= 30 && topPath.count / total >= 0.5 && http4xxStatus !== "NORMAL") {
    const sharePct = Math.round((topPath.count / total) * 100);
    const est = estimateTotalFactor(samples.length);
    const observedPer5m = Math.ceil((topPath.count / windowMinutes) * 5);
    const limit = Math.max(WAF_LIMITS.minRateLimit, observedPer5m * est * 2);
    const id = `rate-path-${Math.abs(hash(topPath.path))}`;
    recs.push({
      isManagedGroup: false,
      statement: {
        RateBasedStatement: {
          Limit: limit,
          AggregateKeyType: "IP",
          EvaluationWindowSec: 300,
          ScopeDownStatement: pathScopeDown(topPath.path),
        },
      },
      rec: {
        id,
        kind: "RATE_BASED",
        name: `dash-rate-path`,
        targetPattern: `경로 ${topPath.path} 집중 (${sharePct}%) + 4XX 증가`,
        criteria: { path: topPath.path },
        threshold: limit,
        evaluationWindowSec: 300,
        action: "COUNT",
        confidence: "MEDIUM",
        reason: `특정 경로에 트래픽 집중 + 4XX 상승 — 해당 경로 한정 rate-based (scope-down: UriPath STARTS_WITH).`,
        evidence: [
          `경로 ${topPath.path}: 샘플 ${topPath.count}/${total}건`,
          `4XX 상태: ${http4xxStatus}`,
        ],
        expectedImpact: `해당 경로 고빈도 IP만 매칭. 경로 외 트래픽 영향 없음.`,
        falsePositiveRisk: "LOW",
        hasScopeDown: true,
      },
    });
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
      },
    });
  }

  for (const r of recs) recStore.set(r.rec.id, r);
  return recs.map((r) => r.rec);
}

function estimateTotalFactor(sampleCount: number): number {
  // GetSampledRequests caps at 500 per rule — treat the sample as a lower
  // bound and keep the extrapolation factor conservative.
  return sampleCount >= 450 ? 3 : 1;
}

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
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
