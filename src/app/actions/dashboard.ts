"use server";

import { POLLING } from "@/lib/server/config";
import { cached, invalidateCached, peekCached, putCached } from "@/lib/server/cache";
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
  type DeploymentPatchRequest,
} from "@/lib/server/k8s";
import { fetchPodLogsInsights, fetchPodLogsKube } from "@/lib/server/podlogs";
import { assembleRule } from "@/lib/server/ruleassemble";
import { probe } from "@/lib/server/probe";
import { nodeCountPanel, type NodeCountProjection } from "@/lib/server/nodecount";
import { resolveWindow, windowKey } from "@/lib/server/window";
import { fetchGradingPanel } from "@/lib/server/grading";
import { loadResourceHistory, recordResourceSamples } from "@/lib/server/reshistory";
import { saveSettings, settingsView } from "@/lib/server/settings";
import { discover } from "@/lib/server/discover";
import { resetAwsClients } from "@/lib/server/aws";

import {
  getNodeResourceUsage,
  getNodeScaling,
  getPodResourceUsage,
  getPodScaling,
  summarizePodStatus,
} from "@/lib/server/resources";
import { aggregateFingerprints } from "@/lib/server/fingerprint";
import { analyzeRequestLog } from "@/lib/server/requestlog";
import {
  detectAnomalies,
  type AnomalyInput,
  type RecentRuleApply,
} from "@/lib/server/anomaly";
import {
  applyHistory,
  buildHttpSummary,
  getAclInfo,
  listSampleRows,
  setRuleAction,
} from "@/lib/server/waf";
import { countEvidence, type CountEvidence } from "@/lib/server/wafcountevidence";
import {
  getDeployHistory,
  insertDeployHistory,
  insertWafHistory,
  listDeployHistory,
  listWafHistory,
  updateDeployVerdict,
} from "@/lib/server/db";
import type {
  ActionResult,
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
  DiscoverKind,
  DiscoveryResult,
  RequestLogQueryResult,
  SettingsView,
  ResourceHistory,
  StatusDistribution,
  Verdict,
  VerificationResult,
  WafPanel,
  WafSampleRow,
} from "@/lib/types";

function ok<T>(data: T): ActionResult<T> {
  return { ok: true, data };
}

// Rule changes made from this screen in the last few minutes, with the grading
// snapshot each one carried. Feeds the false-block alarm; a row whose snapshot
// is unreadable is skipped rather than guessed at.
function recentRuleApplies(): RecentRuleApply[] {
  const cutoff = Date.now() - 10 * 60_000;
  return listWafHistory()
    .filter((h) => h.ts >= cutoff && h.status === "SUCCESS" && h.action !== "REMOVE")
    .flatMap((h) => {
      try {
        const snap = JSON.parse(h.detail) as { keys?: { label: string; pct: number }[] };
        if (!snap.keys?.length) return [];
        return [{ ruleName: h.rule_name, action: h.action, atMs: h.ts, keys: snap.keys }];
      } catch {
        return [];
      }
    });
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

// Exactly what the screen draws: four tiles on 성능 and the two WAF series on
// 트래픽. The status-code chart that needed 2XX/3XX is gone (03), and RDS
// DatabaseConnections said the same thing as ClientConnections.
const VISIBLE_METRICS = [
  "targetResponseTime",
  "http4xx",
  "http5xx",
  "rdsClientConnections",
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
      // metrics.k8s.io keeps no history, so the reading is appended here — on
      // the timer that already exists — and the charts read it back. Recording
      // must never break the panel: a full disk is not an outage.
      try {
        recordResourceSamples(panel.podResources, panel.nodeResources, Date.now());
      } catch {
        // best effort
      }
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

      let httpSummary: MetricsPanel["httpSummary"] = null;
      let httpSummaryError: string | null = null;
      try {
        httpSummary = await buildHttpSummary(null, win);
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
      const grading = peekCached<GradingPanel>(`panel:grading:${windowKey(win)}`);
      const input: AnomalyInput = {
        metrics: metricsSettled,
        httpSummary,
        pods: kube?.pods ?? [],
        events: kube?.events ?? [],
        fingerprints,
        recentApplies: recentRuleApplies(),
        gradingNow: (grading?.lines ?? []).map((l) => ({ label: l.label, pct: l.pct })),
      };
      const anomalies = detectAnomalies(input);

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

// Apply / promote / demote / remove, all one call (04). Every press is a
// person's press — nothing on this screen changes a WebACL on its own.
//
// The grading keys as they stood at the moment of the change go into the
// history row with it. That snapshot is what the false-block alarm compares
// against five minutes later, and it has to be taken here, before the rule can
// have moved anything.
export async function updateWafRuleAction(params: {
  ruleJson: string;
  action: "COUNT" | "BLOCK" | null;
  window?: WindowSelection;
}): Promise<ActionResult<{ ruleName: string; historyId: number }>> {
  try {
    // Whatever the 성능 tab last aggregated, over the same window it is showing.
    // Never re-queried here: a rule change is not a reason to spend an Insights
    // scan, and a five-minute-old baseline is still the baseline the operator
    // was looking at when they pressed the button.
    const win = resolveWindow(params.window, Date.now());
    const grading = peekCached<GradingPanel>(`panel:grading:${windowKey(win)}`);
    const snapshot = JSON.stringify({
      at: Date.now(),
      keys: (grading?.lines ?? []).map((l) => ({ label: l.label, pct: l.pct, total: l.total })),
    });
    const { ruleName, priorRules } = await setRuleAction(params.ruleJson, params.action);
    const historyId = insertWafHistory(
      ruleName,
      params.action ?? "REMOVE",
      "SUCCESS",
      snapshot,
      priorRules,
    );
    // The rule list on screen is read from the WebACL, so it has to be re-read
    // rather than patched locally.
    invalidateCached("panel:waf");
    return ok({ ruleName, historyId });
  } catch (e) {
    return fail(e);
  }
}

// What a COUNT rule actually matched, and whether the app answered those
// requests normally. SQLi rules only — a UA rule never sits in COUNT (04).
export async function getCountEvidenceAction(
  ruleName: string,
  sel?: WindowSelection,
): Promise<ActionResult<CountEvidence>> {
  try {
    const win = resolveWindow(sel, Date.now());
    return ok(await countEvidence(ruleName, win.startMs, win.endMs));
  } catch (e) {
    return fail(e);
  }
}

// Pod/node usage over the shared window. Read-only: the samples are written by
// the kube panel, so asking for a chart never triggers a cluster call.
export async function getResourceHistoryAction(
  sel?: WindowSelection,
): Promise<ActionResult<ResourceHistory>> {
  try {
    return ok(loadResourceHistory(resolveWindow(sel, Date.now())));
  } catch (e) {
    return fail(e);
  }
}

// --- settings --------------------------------------------------------------

export async function getSettingsAction(): Promise<ActionResult<SettingsView>> {
  try {
    return ok(settingsView());
  } catch (e) {
    return fail(e);
  }
}

// Saving changes which account and region every panel is reading, so anything
// cached against the previous selection is now describing the wrong thing, and
// the SDK clients still hold the old region.
export async function saveSettingsAction(
  patch: Record<string, string>,
): Promise<ActionResult<SettingsView>> {
  try {
    saveSettings(patch);
    resetAwsClients();
    // "" is a prefix of every key, so this clears the lot.
    invalidateCached("");
    return ok(settingsView());
  } catch (e) {
    return fail(e);
  }
}

export async function discoverAction(kind: DiscoverKind): Promise<ActionResult<DiscoveryResult>> {
  try {
    return ok(await discover(kind));
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

// Assembles a regex rule for one purpose (suspicious paths / threat UAs /
// SQLi) out of the current traffic summary. Nothing is applied — the result is
// rule JSON the operator reads, applies as COUNT, then promotes to BLOCK by
// hand once the live count shows no false positives.
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

// Node count over the scoring window — the cost grader's input, counted rather
// than estimated. Not cached: describe-instances has no per-byte charge, the
// poll is 30s, and a TTL here would only make the number older than it looks.
// The reading is recorded to SQLite inside the call, so this is also what keeps
// the running average fed. See server/nodecount.ts.
export async function getNodeCostAction(): Promise<ActionResult<NodeCountProjection>> {
  try {
    return ok(await nodeCountPanel(Date.now()));
  } catch (e) {
    return fail(e);
  }
}
