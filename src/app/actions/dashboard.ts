"use server";

import { POLLING } from "@/lib/server/config";
import { cached, peekCached, putCached } from "@/lib/server/cache";
import { errMsg, fetchCoreMetrics, fetchTargetGroupMetrics } from "@/lib/server/cloudwatch";
import { fetchRequestLogRows } from "@/lib/server/applog";
import type { StatusClass } from "@/lib/server/applogquery";
import {
  countReadyNodes,
  getDeployment,
  listDeployments,
  listPods,
  listWarningEvents,
  patchDeployment,
  validatePatch,
  type DeploymentPatchRequest,
} from "@/lib/server/k8s";
import { fetchPodLogsInsights, fetchPodLogsKube } from "@/lib/server/podlogs";
import { defaultTestRequests, maliciousExampleRequests, testRule } from "@/lib/server/rulesim";
import { assembleRule } from "@/lib/server/ruleassemble";
import { probe } from "@/lib/server/probe";
import { resolveWindow, windowKey } from "@/lib/server/window";
import { fetchGradingPanel } from "@/lib/server/grading";
import {
  getNodeResourceUsage,
  getNodeScaling,
  getPodResourceUsage,
  getPodScaling,
  summarizePodStatus,
} from "@/lib/server/resources";
import { aggregateFingerprints } from "@/lib/server/fingerprint";
import { analyzeRequestLog } from "@/lib/server/requestlog";
import { detectAnomalies, type AnomalyInput } from "@/lib/server/anomaly";
import { buildTimeline, correlate } from "@/lib/server/correlation";
import {
  applyHistory,
  buildHttpSummary,
  getAclInfo,
  listSampleRows,
} from "@/lib/server/waf";
import {
  buildSnapshot,
  toJson,
  toMarkdown,
  toQPrompt,
  type IncidentSnapshot,
} from "@/lib/server/incident";
import {
  getDeployHistory,
  insertDeployHistory,
  listDeployHistory,
  updateDeployVerdict,
} from "@/lib/server/db";
import type {
  ActionResult,
  ApplyHistoryEntry,
  AssembledRule,
  AssembleKind,
  WindowSelection,
  DeployChangeEntry,
  DeploymentInfo,
  FingerprintEntry,
  GradingPanel,
  IncidentContextResult,
  KubePanel,
  MetricsPanel,
  MetricSummary,
  PodLogsResult,
  ProbeResult,
  RequestLogQueryResult,
  RuleTestResult,
  StatusDistribution,
  TestRequest,
  Verdict,
  VerificationResult,
  WafPanel,
  WafSampleRow,
} from "@/lib/types";

function ok<T>(data: T): ActionResult<T> {
  return { ok: true, data };
}

function fail<T>(e: unknown): ActionResult<T> {
  return { ok: false, error: errMsg(e) };
}

// Stand-in summary for the one assembly kind that reads no traffic at all.
const EMPTY_SUMMARY = {
  totalSampled: 0,
  windowLabel: "",
  source: "",
  byPath: [],
  byIp: [],
  byUa: [],
  byMethod: [],
  queryPatterns: [],
  headerPatterns: [],
  blockedTotal: 0,
  statusDist: null,
  detailedStatus: null,
  notes: [],
};

const VISIBLE_METRICS = [
  "targetResponseTime",
  "http4xx",
  "http5xx",
  "rdsClientConnections",
  "rdsDatabaseConnections",
  "wafBlocked",
  "wafAllowed",
];

// ---------------------------------------------------------------------------
// Kubernetes panel — 3s tier
// ---------------------------------------------------------------------------

export async function getKubePanelAction(): Promise<ActionResult<KubePanel>> {
  try {
    const data = await cached("panel:kube", POLLING.kubeTtlMs, async () => {
      const [pods, events, deployments, nodes] = await Promise.allSettled([
        listPods(),
        listWarningEvents(),
        listDeployments(),
        countReadyNodes(),
      ]);
      const podList = pods.status === "fulfilled" ? pods.value : [];
      const deploymentList = deployments.status === "fulfilled" ? deployments.value : [];
      const nodeTotal = nodes.status === "fulfilled" ? nodes.value.total : 0;

      const [podRes, nodeRes, podScale, nodeScale] = await Promise.allSettled([
        getPodResourceUsage(podList),
        getNodeResourceUsage(),
        getPodScaling(deploymentList),
        getNodeScaling(nodeTotal),
      ]);

      const panel: KubePanel = {
        pods: podList,
        events: events.status === "fulfilled" ? events.value : [],
        deployments: deploymentList,
        nodesReady: nodes.status === "fulfilled" ? nodes.value.ready : 0,
        nodesTotal: nodeTotal,
        statusBreakdown: summarizePodStatus(podList),
        podResources: podRes.status === "fulfilled" ? podRes.value.data : [],
        podResourceError:
          podRes.status === "fulfilled" ? podRes.value.error : errMsg(podRes.reason),
        nodeResources: nodeRes.status === "fulfilled" ? nodeRes.value.data : [],
        nodeResourceError:
          nodeRes.status === "fulfilled" ? nodeRes.value.error : errMsg(nodeRes.reason),
        podScaling: podScale.status === "fulfilled" ? podScale.value : [],
        nodeScaling: nodeScale.status === "fulfilled" ? nodeScale.value : [],
        scalingError:
          podScale.status === "rejected"
            ? errMsg(podScale.reason)
            : nodeScale.status === "rejected"
              ? errMsg(nodeScale.reason)
              : null,
      };
      if (pods.status === "rejected") throw pods.reason;
      return panel;
    });
    return ok(data);
  } catch (e) {
    return fail(e);
  }
}

// ---------------------------------------------------------------------------
// Metrics + analysis panel — 30s tier
// ---------------------------------------------------------------------------

export async function getMetricsPanelAction(
  sel?: WindowSelection,
): Promise<ActionResult<MetricsPanel>> {
  try {
    const win = resolveWindow(sel, Date.now());
    const data = await cached(`panel:metrics:${windowKey(win)}`, POLLING.metricsTtlMs, async () => {
      const { summaries: metricsSettled, errors: metricErrors } = await fetchCoreMetrics(win);
      const byKey = new Map(metricsSettled.map((m) => [m.key, m]));
      const statusDist: StatusDistribution | null = byKey.has("http2xx")
        ? (() => {
            const c2xx = byKey.get("http2xx")?.current ?? 0;
            const c3xx = byKey.get("http3xx")?.current ?? 0;
            const c4xx = byKey.get("http4xx")?.current ?? 0;
            const c5xx = byKey.get("http5xx")?.current ?? 0;
            return { c2xx, c3xx, c4xx, c5xx, total: c2xx + c3xx + c4xx + c5xx };
          })()
        : null;

      let httpSummary: MetricsPanel["httpSummary"] = null;
      let httpSummaryError: string | null = null;
      try {
        httpSummary = await buildHttpSummary(statusDist, win);
      } catch (e) {
        httpSummaryError = errMsg(e);
      }

      let targetGroupMetrics: MetricsPanel["targetGroupMetrics"] = [];
      let targetGroupError: string | null = null;
      try {
        targetGroupMetrics = await fetchTargetGroupMetrics(win);
      } catch (e) {
        targetGroupError = errMsg(e);
      }

      const kube = peekCached<KubePanel>("panel:kube");
      const fingerprints = peekCached<FingerprintEntry[]>("panel:fingerprints") ?? [];
      const input: AnomalyInput = {
        metrics: metricsSettled,
        httpSummary,
        pods: kube?.pods ?? [],
        events: kube?.events ?? [],
        fingerprints,
      };
      const anomalies = detectAnomalies(input);
      const correlations = correlate(input, anomalies);
      const timeline = buildTimeline(input, anomalies);

      const visible: MetricSummary[] = VISIBLE_METRICS.map((k) => byKey.get(k)).filter(
        (m): m is MetricSummary => m !== undefined,
      );
      const panel: MetricsPanel = {
        metrics: visible,
        metricErrors,
        targetGroupMetrics,
        targetGroupError,
        httpSummary,
        httpSummaryError,
        anomalies,
        correlations,
        timeline,
        window: win,
      };
      return panel;
    });
    return ok(data);
  } catch (e) {
    return fail(e);
  }
}

// ---------------------------------------------------------------------------
// Pod logs — on demand / 5s auto-refresh tier
// ---------------------------------------------------------------------------

// Log reads/aggregations go to CloudWatch Logs Insights (no local
// accumulation; Insights bills per byte scanned, so results are cached
// 30s and failures 10s). The k8s API remains only for previous-container
// logs and as a fallback when Insights is unavailable.
export async function getPodLogsAction(params: {
  pod: string;
  container: string;
  previous: boolean;
  tailLines: number;
  window?: WindowSelection;
}): Promise<ActionResult<PodLogsResult>> {
  try {
    const win = resolveWindow(params.window, Date.now());
    const fetched = await cached(
      `logs:${params.pod}:${params.container}:${params.previous}:${params.tailLines}:${windowKey(win)}`,
      POLLING.logCacheTtlMs,
      async () => {
        if (params.previous) return fetchPodLogsKube(params);
        try {
          return await fetchPodLogsInsights({ ...params, win });
        } catch {
          return fetchPodLogsKube(params);
        }
      },
      POLLING.logFailTtlMs,
    );
    const { lines } = fetched;
    const fingerprints = aggregateFingerprints([{ pod: params.pod, lines }]);
    const requestLog =
      fetched.analysis ?? {
        ...analyzeRequestLog(lines),
        basis: `tail ${params.tailLines} 샘플 (k8s API)`,
      };
    putCached("panel:fingerprints", 10 * 60_000, fingerprints);
    putCached(
      params.previous ? "panel:lastprevlogs" : "panel:lastlogs",
      10 * 60_000,
      { pod: params.pod, container: params.container, previous: params.previous, lines },
    );
    return ok({
      lines,
      container: params.container,
      previous: params.previous,
      fingerprints,
      requestLog,
      source: fetched.source,
      scannedBytes: fetched.scannedBytes,
      windowLabel: fetched.windowLabel,
    });
  } catch (e) {
    return fail(e);
  }
}

// ---------------------------------------------------------------------------
// WAF panel — 30s tier
// ---------------------------------------------------------------------------

export async function getWafPanelAction(
  sel?: WindowSelection,
): Promise<ActionResult<WafPanel>> {
  try {
    const win = resolveWindow(sel, Date.now());
    const data = await cached(`panel:waf:${windowKey(win)}`, POLLING.wafTtlMs, async () => {
      const metrics = peekCached<MetricsPanel>("panel:metrics");
      const [acl] = await Promise.allSettled([getAclInfo()]);
      const panel: WafPanel = {
        acl: acl.status === "fulfilled" ? acl.value : null,
        aclError: acl.status === "rejected" ? errMsg(acl.reason) : null,
        history: applyHistory(),
      };
      return panel;
    });
    return ok(data);
  } catch (e) {
    return fail(e);
  }
}

export async function getWafHistoryAction(): Promise<ActionResult<ApplyHistoryEntry[]>> {
  try {
    return ok(applyHistory());
  } catch (e) {
    return fail(e);
  }
}

export async function getWafSamplesAction(): Promise<ActionResult<WafSampleRow[]>> {
  try {
    return ok(await listSampleRows());
  } catch (e) {
    return fail(e);
  }
}

// ---------------------------------------------------------------------------
// Grading scorecard — what the load generator would score this environment at.
// One Insights pass over the app log; on-demand and cached like the rest.
// ---------------------------------------------------------------------------

export async function getGradingPanelAction(
  sel?: WindowSelection,
): Promise<ActionResult<GradingPanel>> {
  try {
    const win = resolveWindow(sel, Date.now());
    const metrics = peekCached<MetricsPanel>("panel:metrics");
    const wafBlocked = metrics?.httpSummary?.blockedTotal ?? 0;
    return ok(
      await cached(
        `panel:grading:${windowKey(win)}`,
        POLLING.logCacheTtlMs,
        () => fetchGradingPanel(win, wafBlocked),
        POLLING.logFailTtlMs,
      ),
    );
  } catch (e) {
    return fail(e);
  }
}

// ---------------------------------------------------------------------------
// App request log — on-demand status-code query (no polling; Insights bills
// per byte scanned)
// ---------------------------------------------------------------------------

export async function getRequestLogRowsAction(params: {
  statusClass: StatusClass;
  pathContains: string;
  window?: WindowSelection;
}): Promise<ActionResult<RequestLogQueryResult>> {
  try {
    return ok(
      await fetchRequestLogRows({ ...params, win: resolveWindow(params.window, Date.now()) }),
    );
  } catch (e) {
    return fail(e);
  }
}

// ---------------------------------------------------------------------------
// Deployment actions
// ---------------------------------------------------------------------------

export async function getDeploymentAction(params: {
  namespace: string;
  name: string;
}): Promise<ActionResult<DeploymentInfo>> {
  try {
    return ok(await getDeployment(params.namespace, params.name));
  } catch (e) {
    return fail(e);
  }
}

export async function previewPatchAction(
  req: DeploymentPatchRequest,
): Promise<ActionResult<{ current: DeploymentInfo }>> {
  try {
    const { deployment } = await validatePatch(req);
    return ok({ current: deployment });
  } catch (e) {
    return fail(e);
  }
}

export async function patchDeploymentAction(
  req: DeploymentPatchRequest,
): Promise<ActionResult<{ historyId: number; after: DeploymentInfo }>> {
  try {
    const metrics = peekCached<MetricsPanel>("panel:metrics");
    const kube = peekCached<KubePanel>("panel:kube");
    const before = {
      trt: metrics?.metrics.find((m) => m.key === "targetResponseTime")?.current ?? -1,
      c4xx: metrics?.metrics.find((m) => m.key === "http4xx")?.current ?? -1,
      c5xx: metrics?.metrics.find((m) => m.key === "http5xx")?.current ?? -1,
      restarts:
        kube?.pods
          .filter((p) => p.name.startsWith(req.name))
          .reduce((a, p) => a + p.totalRestarts, 0) ?? -1,
    };
    const changeDesc = [
      req.replicas !== undefined ? `replicas=${req.replicas}` : null,
      req.cpuLimit !== undefined ? `cpuLimit=${req.cpuLimit}` : null,
      req.memLimit !== undefined ? `memLimit=${req.memLimit}` : null,
    ]
      .filter(Boolean)
      .join(", ");
    const after = await patchDeployment(req);
    const historyId = insertDeployHistory(
      req.namespace,
      req.name,
      changeDesc,
      JSON.stringify(before),
    );
    return ok({ historyId, after });
  } catch (e) {
    return fail(e);
  }
}

export async function listDeployHistoryAction(): Promise<ActionResult<DeployChangeEntry[]>> {
  try {
    return ok(
      listDeployHistory().map((d) => ({
        id: d.id,
        ts: new Date(d.ts).toISOString(),
        namespace: d.namespace,
        name: d.name,
        change: d.change,
        verdict: d.verdict as DeployChangeEntry["verdict"],
      })),
    );
  } catch (e) {
    return fail(e);
  }
}

// Post-change verification (spec §23) — compares metrics/pods against the
// snapshot taken at patch time. Causality is never claimed.
export async function verifyActionAction(
  historyId: number,
): Promise<ActionResult<VerificationResult>> {
  try {
    const row = getDeployHistory(historyId);
    if (!row) throw new Error(`이력 없음: ${historyId}`);
    const details: string[] = [];
    const elapsed = Date.now() - row.ts;
    if (elapsed < POLLING.verificationDelayMs) {
      const wait = Math.ceil((POLLING.verificationDelayMs - elapsed) / 1000);
      const result: VerificationResult = {
        actionId: historyId,
        verdict: "INCONCLUSIVE",
        checkedAt: new Date().toISOString(),
        details: [`변경 후 ${Math.round(elapsed / 1000)}초 경과 — 롤아웃 안정화 대기 (약 ${wait}초 후 재검증)`],
      };
      return ok(result);
    }

    const before = JSON.parse(row.metrics_before) as {
      trt: number;
      c4xx: number;
      c5xx: number;
      restarts: number;
    };
    const metricsRes = await getMetricsPanelAction();
    const kubeRes = await getKubePanelAction();
    if (!metricsRes.ok) throw new Error(`CloudWatch 조회 실패: ${metricsRes.error}`);

    const now = {
      trt: metricsRes.data.metrics.find((m) => m.key === "targetResponseTime")?.current ?? -1,
      c4xx: metricsRes.data.metrics.find((m) => m.key === "http4xx")?.current ?? -1,
      c5xx: metricsRes.data.metrics.find((m) => m.key === "http5xx")?.current ?? -1,
      restarts: kubeRes.ok
        ? kubeRes.data.pods
            .filter((p) => p.name.startsWith(row.name))
            .reduce((a, p) => a + p.totalRestarts, 0)
        : -1,
    };

    const deployment = await getDeployment(row.namespace, row.name);
    const rolloutOk =
      deployment.readyReplicas >= deployment.replicas && deployment.replicas > 0;
    details.push(
      `Deployment ${row.name}: ready ${deployment.readyReplicas}/${deployment.replicas}${rolloutOk ? "" : " — 롤아웃 미완료"}`,
    );

    let improved = 0;
    let degraded = 0;
    const cmp = (label: string, b: number, n: number, lowerIsBetter: boolean): void => {
      if (b < 0 || n < 0) {
        details.push(`${label}: 이전 값 없음 — 비교 불가`);
        return;
      }
      const diff = n - b;
      const pct = b > 0 ? Math.round((diff / b) * 100) : diff > 0 ? 100 : 0;
      details.push(`${label}: ${b} → ${n} (${pct >= 0 ? "+" : ""}${pct}%)`);
      const meaningful = Math.abs(pct) >= 20;
      if (!meaningful) return;
      const better = lowerIsBetter ? diff < 0 : diff > 0;
      if (better) improved += 1;
      else degraded += 1;
    };
    cmp("TargetResponseTime", before.trt, now.trt, true);
    cmp("4XX/min", before.c4xx, now.c4xx, true);
    cmp("5XX/min", before.c5xx, now.c5xx, true);
    if (before.restarts >= 0 && now.restarts >= 0 && now.restarts > before.restarts) {
      degraded += 1;
      details.push(`재시작 수 증가: ${before.restarts} → ${now.restarts}`);
    }

    let verdict: Verdict;
    if (!rolloutOk) verdict = "INCONCLUSIVE";
    else if (degraded > 0 && degraded >= improved) verdict = "DEGRADED";
    else if (improved > 0) verdict = "IMPROVED";
    else verdict = "NO_CHANGE";
    details.push("주의: 메트릭 변화와 변경 조치의 인과관계는 확정할 수 없음");

    updateDeployVerdict(historyId, verdict);
    const result: VerificationResult = {
      actionId: historyId,
      verdict,
      checkedAt: new Date().toISOString(),
      details,
    };
    const prior = peekCached<VerificationResult[]>("panel:verifications") ?? [];
    putCached("panel:verifications", 60 * 60_000, [
      ...prior.filter((v) => v.actionId !== historyId),
      result,
    ]);
    return ok(result);
  } catch (e) {
    return fail(e);
  }
}

// ---------------------------------------------------------------------------
// Incident context (spec §17, §18)
// ---------------------------------------------------------------------------

export async function generateIncidentContextAction(): Promise<
  ActionResult<IncidentContextResult>
> {
  try {
    const metricsRes = await getMetricsPanelAction();
    const kubeRes = await getKubePanelAction();
    const metrics = metricsRes.ok ? metricsRes.data : null;
    const kube = kubeRes.ok ? kubeRes.data : null;
    const fingerprints = peekCached<FingerprintEntry[]>("panel:fingerprints") ?? [];
    const logs = peekCached<IncidentSnapshot["logs"]>("panel:lastlogs");
    const prevLogs = peekCached<IncidentSnapshot["previousLogs"]>("panel:lastprevlogs");
    const verifications = peekCached<VerificationResult[]>("panel:verifications") ?? [];

    const wafPanel = peekCached<WafPanel>("panel:waf");
    const snapshot = buildSnapshot({
      metrics: metrics?.metrics ?? [],
      httpSummary: metrics?.httpSummary ?? null,
      kube,
      anomalies: metrics?.anomalies ?? [],
      correlations: metrics?.correlations ?? [],
      timeline: metrics?.timeline ?? [],
      fingerprints,
      logs: logs ?? null,
      previousLogs: prevLogs
        ? { pod: prevLogs.pod, container: prevLogs.container, lines: prevLogs.lines }
        : null,
      verifications,
    });
    return ok({
      markdown: toMarkdown(snapshot),
      json: toJson(snapshot),
      qPrompt: toQPrompt(snapshot),
      generatedAt: snapshot.timestamp,
    });
  } catch (e) {
    return fail(e);
  }
}

// ---------------------------------------------------------------------------
// Rule sandbox — evaluates a pasted WAFv2 Rule against synthetic requests.
// Pure and local: nothing is sent to AWS and no WebACL is touched.
// ---------------------------------------------------------------------------

export async function getDefaultTestRequestsAction(): Promise<ActionResult<TestRequest[]>> {
  try {
    return ok(defaultTestRequests());
  } catch (e) {
    return fail(e);
  }
}

export async function getMaliciousExampleRequestsAction(): Promise<ActionResult<TestRequest[]>> {
  try {
    return ok(maliciousExampleRequests());
  } catch (e) {
    return fail(e);
  }
}

// Assembles a regex rule for one purpose (suspicious paths / threat UAs /
// SQLi) out of the current traffic summary. Nothing is applied — the result is
// rule JSON the operator reads, tests in the sandbox, then applies by hand.
export async function assembleRuleAction(
  kind: AssembleKind,
  sel?: WindowSelection,
): Promise<ActionResult<AssembledRule>> {
  try {
    // SQLi is a fixed signature set, so it must not fail when the WAF summary
    // is unavailable — only the observed kinds need live traffic.
    if (kind === "sqli") return ok(assembleRule("sqli", EMPTY_SUMMARY));
    return ok(assembleRule(kind, await buildHttpSummary(null, resolveWindow(sel, Date.now()))));
  } catch (e) {
    return fail(e);
  }
}

// One GET at the address the operator typed. Not cached, not scheduled, not
// stored: the whole point is that it answers "right now", which a cached value
// cannot. See server/probe.ts.
export async function probeUrlAction(
  url: string,
  expectStatus: number | null,
): Promise<ActionResult<ProbeResult>> {
  try {
    return ok(await probe(url, expectStatus));
  } catch (e) {
    // Only a malformed address lands here — a target that refused, timed out
    // or answered 500 comes back as a result, not as a failure.
    return fail(e);
  }
}

export async function testRuleJsonAction(params: {
  ruleJson: string;
  requests: TestRequest[];
}): Promise<ActionResult<RuleTestResult>> {
  try {
    return ok(testRule(params));
  } catch (e) {
    return fail(e);
  }
}
