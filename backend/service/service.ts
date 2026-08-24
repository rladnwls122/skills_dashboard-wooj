// The dashboard's behaviour. Every method here maps 1:1 to a route of the HTTP
// layer above it, so that layer is a thin envelope and the UI contract does not
// move.

import { invalidate, peek, put } from "../cache/cache.ts";
import { POLLING, type Settings } from "../config/config.ts";
// Only the cluster-free patch rules, so the confirm screen and the apply cannot
// disagree about what a valid change is.
import { validatePatchRequest } from "../kube/kube.ts";
import type { MetricSampleBatchEntry, Sample, Store } from "../store/store.ts";
import type {
  ApplyHistoryEntry,
  AssembledRule,
  CountEvidence,
  CredentialsView,
  DeployChangeEntry,
  DeploymentInfo,
  DiscoveryResult,
  GradingPanel,
  IncidentContextResult,
  KubePanel,
  MetricPoint,
  MetricsPanel,
  NamedSeries,
  NodeCountProjection,
  NodeResourceUsage,
  PodLogsResult,
  PodResourceUsage,
  ProbeResult,
  RequestLogQueryResult,
  ResolvedWindow,
  ResourceHistory,
  RuleTestResult,
  SettingsView,
  TestRequest,
  Verdict,
  VerificationResult,
  WafLogQueryResult,
  WafPanel,
  WafSampleRow,
  WindowSelection,
} from "../../src/lib/types.ts";
import type { CredentialsResult, WafRuleUpdateResult } from "../types/types.ts";
import { probe } from "./probe.ts";
import {
  UnavailableProvider,
  type CredentialsInput,
  type DeploymentPatchRequest,
  type ImportCredentialsInput,
  type PodLogsParams,
  type Provider,
  type RequestLogParams,
  type RuleTestParams,
  type WafLogParams,
} from "./provider.ts";
import { defaultTestRequests, maliciousExampleRequests } from "./sandbox.ts";
import { resolveWindow } from "./window.ts";

export interface PatchResult {
  historyId: number;
  after: DeploymentInfo;
}

/**
 * The metric reading at change time. -1 means "not known", which the comparison
 * reports as "비교 불가" rather than treating as zero.
 */
interface BeforeSnapshot {
  trt: number;
  c4xx: number;
  c5xx: number;
  restarts: number;
}

/**
 * Pod and node usage over time live under this key prefix. metrics.k8s.io
 * answers "what is it right now" and keeps no history, so the kube poll appends
 * readings to SQLite and the charts read them back over the shared window.
 */
const RES_PREFIX = "res:";

export class Service {
  readonly store: Store;
  readonly settings: Settings;
  readonly provider: Provider;
  /**
   * Injectable so window resolution and the verification delay are testable
   * without sleeping.
   */
  now: () => number = () => Date.now();

  constructor(store: Store, settings: Settings, provider: Provider | null) {
    this.store = store;
    this.settings = settings;
    this.provider = provider ?? new UnavailableProvider();
  }

  private window(sel: WindowSelection | null | undefined): ResolvedWindow {
    return resolveWindow(sel, this.now());
  }

  // --- cloud-backed panels ---------------------------------------------------

  kubePanel(): Promise<KubePanel> {
    return this.provider.kubePanel();
  }

  metricsPanel(sel: WindowSelection | null): Promise<MetricsPanel> {
    return this.provider.metricsPanel(this.window(sel));
  }

  wafPanel(sel: WindowSelection | null): Promise<WafPanel> {
    return this.provider.wafPanel(this.window(sel));
  }

  wafSamples(): Promise<WafSampleRow[]> {
    return this.provider.wafSamples();
  }

  gradingPanel(sel: WindowSelection | null): Promise<GradingPanel> {
    return this.provider.gradingPanel(this.window(sel));
  }

  podLogs(p: PodLogsParams): Promise<PodLogsResult> {
    return this.provider.podLogs(p, this.window(p.window));
  }

  requestLogRows(p: RequestLogParams): Promise<RequestLogQueryResult> {
    return this.provider.requestLogRows(p, this.window(p.window));
  }

  discover(kind: string): Promise<DiscoveryResult> {
    return this.provider.discover(kind);
  }

  incidentContext(): Promise<IncidentContextResult> {
    return this.provider.incidentContext();
  }

  assembleRule(kind: string, sel: WindowSelection | null): Promise<AssembledRule> {
    return this.provider.assembleRule(kind, this.window(sel));
  }

  testRule(p: RuleTestParams): Promise<RuleTestResult> {
    return this.provider.testRule(p);
  }

  updateWafRule(
    ruleJson: string,
    action: string | null,
    sel: WindowSelection | null,
  ): Promise<WafRuleUpdateResult> {
    return this.provider.updateWafRule(ruleJson, action, this.window(sel));
  }

  countEvidence(ruleName: string, sel: WindowSelection | null): Promise<CountEvidence> {
    return this.provider.countEvidence(ruleName, this.window(sel));
  }

  wafLogRows(p: WafLogParams): Promise<WafLogQueryResult> {
    return this.provider.wafLogRows(p, this.window(p.window));
  }

  nodeCost(): Promise<NodeCountProjection> {
    return this.provider.nodeCost();
  }

  // --- AWS credentials -------------------------------------------------------
  //
  // The keys never travel back to the browser: every method here answers with
  // the masked view, and the input is one-way.

  credentials(): CredentialsView {
    return this.provider.credentialsView(this.now());
  }

  /**
   * What every credential change returns. Injecting changes which account every
   * panel is reading, so the SDK clients and every cached answer taken with the
   * previous identity have to go — the same reasoning as a settings save.
   */
  private async applied(): Promise<CredentialsResult> {
    this.provider.reset();
    invalidate("");
    return {
      view: this.provider.credentialsView(this.now()),
      check: await this.provider.checkCredentials(),
    };
  }

  async saveCredentials(input: CredentialsInput): Promise<CredentialsResult> {
    await this.provider.saveCredentials(input);
    return this.applied();
  }

  async importCredentials(input: ImportCredentialsInput): Promise<CredentialsResult> {
    await this.provider.importCredentials(input);
    return this.applied();
  }

  async clearCredentials(): Promise<CredentialsResult> {
    await this.provider.clearCredentials();
    return this.applied();
  }

  /**
   * Makes the probe call without changing anything, so the caches other panels
   * are serving from are left alone.
   */
  async checkCredentials(): Promise<CredentialsResult> {
    return {
      view: this.provider.credentialsView(this.now()),
      check: await this.provider.checkCredentials(),
    };
  }

  // --- local: history, settings, sandbox data, probe -------------------------

  wafHistory(): ApplyHistoryEntry[] {
    return this.store.applyHistory();
  }

  settingsView(): SettingsView {
    return this.settings.view();
  }

  /**
   * Changes which account and region every panel reads, so anything cached
   * against the previous selection is now describing the wrong thing, and the
   * SDK clients still hold the old region — both are dropped.
   */
  saveSettings(patch: Record<string, string>): SettingsView {
    this.settings.save(patch);
    this.provider.reset();
    // "" is a prefix of every key, so this clears the lot.
    invalidate("");
    return this.settings.view();
  }

  defaultTestRequests(): TestRequest[] {
    return defaultTestRequests();
  }

  maliciousTestRequests(): TestRequest[] {
    return maliciousExampleRequests();
  }

  probe(url: string, expectStatus: number | null): Promise<ProbeResult> {
    return probe(url, expectStatus);
  }

  listDeployHistory(): DeployChangeEntry[] {
    return this.store.listDeployHistory().map((r) => ({
      id: r.id,
      ts: new Date(r.ts).toISOString(),
      namespace: r.namespace,
      name: r.name,
      change: r.change,
      verdict: r.verdict,
    }));
  }

  // --- deployments -----------------------------------------------------------

  /**
   * Rejects before anything is sent to the cluster (spec §22): the namespace is
   * pinned to the configured one, names must be DNS labels, the replica count is
   * a whole number bounded by MAX_REPLICAS, and CPU/memory limits must be
   * quantities Kubernetes will accept.
   *
   * Delegated rather than restated. This method used to carry its own, weaker
   * copy of the rules — and previewPatch below calls only this one, so the
   * confirm screen said "적용하시겠습니까?" for `replicas: 2.5` and a malformed
   * cpuLimit, and the apply the operator then authorised failed at the cluster.
   * The preview and the apply now answer from the same list.
   */
  validate(req: DeploymentPatchRequest): void {
    validatePatchRequest(req, this.settings.targetNamespace(), this.settings.maxReplicas());
  }

  deployment(namespace: string, name: string): Promise<DeploymentInfo> {
    return this.provider.deployment(namespace, name);
  }

  /**
   * Validates and reads back the current state without changing anything — the
   * confirm screen's data.
   */
  previewPatch(req: DeploymentPatchRequest): Promise<DeploymentInfo> {
    this.validate(req);
    return this.provider.deployment(req.namespace, req.name);
  }

  /**
   * Records the metric snapshot taken at change time, so the verification below
   * has something to compare against.
   */
  async patchDeployment(req: DeploymentPatchRequest): Promise<PatchResult> {
    this.validate(req);
    const before = await this.snapshotBefore(req.name);
    const parts: string[] = [];
    if (req.replicas !== undefined) parts.push(`replicas=${req.replicas}`);
    if (req.cpuLimit !== undefined) parts.push("cpuLimit=" + req.cpuLimit);
    if (req.memLimit !== undefined) parts.push("memLimit=" + req.memLimit);

    const after = await this.provider.patchDeployment(req);
    const historyId = this.store.insertDeployHistory(
      req.namespace,
      req.name,
      parts.join(", "),
      JSON.stringify(before),
      this.now(),
    );
    return { historyId, after };
  }

  private async snapshotBefore(deployName: string): Promise<BeforeSnapshot> {
    const snap: BeforeSnapshot = { trt: -1, c4xx: -1, c5xx: -1, restarts: -1 };
    try {
      const m = await this.provider.metricsPanel(this.window(null));
      snap.trt = metricValue(m, "targetResponseTime");
      snap.c4xx = metricValue(m, "http4xx");
      snap.c5xx = metricValue(m, "http5xx");
    } catch {
      // Leave the -1 sentinels: an unavailable metric is "not known", not zero.
    }
    try {
      const k = await this.provider.kubePanel();
      snap.restarts = k.pods
        .filter((p) => p.name.startsWith(deployName))
        .reduce((acc, p) => acc + p.totalRestarts, 0);
    } catch {
      // ditto
    }
    return snap;
  }

  /**
   * Compares metrics and pods against the snapshot taken at patch time
   * (spec §23). Causality is never claimed.
   */
  async verify(historyId: number): Promise<VerificationResult> {
    const row = this.store.getDeployHistory(historyId);
    if (!row) throw new Error(`이력 없음: ${historyId}`);

    const nowMs = this.now();
    const elapsed = nowMs - row.ts;
    if (elapsed < POLLING.verificationDelay) {
      const wait = Math.ceil((POLLING.verificationDelay - elapsed) / 1000);
      return {
        actionId: historyId,
        verdict: "INCONCLUSIVE",
        checkedAt: new Date(nowMs).toISOString(),
        details: [
          `변경 후 ${Math.round(elapsed / 1000)}초 경과 — 롤아웃 안정화 대기 (약 ${wait}초 후 재검증)`,
        ],
      };
    }

    const before = JSON.parse(row.metricsBefore) as BeforeSnapshot;

    let metrics: MetricsPanel;
    try {
      metrics = await this.provider.metricsPanel(this.window(null));
    } catch (e) {
      throw new Error(`CloudWatch 조회 실패: ${(e as Error).message}`);
    }
    const nowSnap: BeforeSnapshot = {
      trt: metricValue(metrics, "targetResponseTime"),
      c4xx: metricValue(metrics, "http4xx"),
      c5xx: metricValue(metrics, "http5xx"),
      restarts: -1,
    };
    try {
      const k = await this.provider.kubePanel();
      nowSnap.restarts = k.pods
        .filter((p) => p.name.startsWith(row.name))
        .reduce((acc, p) => acc + p.totalRestarts, 0);
    } catch {
      // restarts stay unknown
    }

    const deployment = await this.provider.deployment(row.namespace, row.name);
    const rolloutOk = deployment.readyReplicas >= deployment.replicas && deployment.replicas > 0;
    const details = [
      `Deployment ${row.name}: ready ${deployment.readyReplicas}/${deployment.replicas}${rolloutOk ? "" : " — 롤아웃 미완료"}`,
    ];

    let improved = 0;
    let degraded = 0;
    const cmp = (label: string, b: number, n: number): void => {
      if (b < 0 || n < 0) {
        details.push(label + ": 이전 값 없음 — 비교 불가");
        return;
      }
      const diff = n - b;
      let pct = 0;
      if (b > 0) pct = Math.round((diff / b) * 100);
      else if (diff > 0) pct = 100;
      details.push(`${label}: ${b} → ${n} (${pct >= 0 ? "+" : ""}${pct}%)`);
      // Below 20% is noise on a dashboard reading one-minute buckets.
      if (pct > -20 && pct < 20) return;
      if (diff < 0) improved++;
      else degraded++;
    };
    cmp("TargetResponseTime", before.trt, nowSnap.trt);
    cmp("4XX/min", before.c4xx, nowSnap.c4xx);
    cmp("5XX/min", before.c5xx, nowSnap.c5xx);
    if (before.restarts >= 0 && nowSnap.restarts >= 0 && nowSnap.restarts > before.restarts) {
      degraded++;
      details.push(`재시작 수 증가: ${before.restarts} → ${nowSnap.restarts}`);
    }

    let verdict: Verdict = "NO_CHANGE";
    if (!rolloutOk) verdict = "INCONCLUSIVE";
    else if (degraded > 0 && degraded >= improved) verdict = "DEGRADED";
    else if (improved > 0) verdict = "IMPROVED";

    details.push("주의: 메트릭 변화와 변경 조치의 인과관계는 확정할 수 없음");
    this.store.updateDeployVerdict(historyId, verdict);

    const result: VerificationResult = {
      actionId: historyId,
      verdict,
      checkedAt: new Date(nowMs).toISOString(),
      details,
    };
    // Kept for the incident report, replacing any earlier verdict for the same
    // action.
    const prior = peek<VerificationResult[]>("panel:verifications") ?? [];
    put("panel:verifications", 60 * 60_000, [
      ...prior.filter((v) => v.actionId !== historyId),
      result,
    ]);
    return result;
  }

  // --- resource history ------------------------------------------------------

  /**
   * Read-only: asking for a chart never triggers a cluster call.
   */
  resourceHistory(sel: WindowSelection | null): ResourceHistory {
    const win = this.window(sel);
    const out: ResourceHistory = { podCpu: [], podMem: [], nodeCpu: [], nodeMem: [] };

    for (const key of this.store.listMetricKeys(RES_PREFIX, win.startMs)) {
      const parsed = parseSampleKey(key);
      if (!parsed) continue;
      const points: MetricPoint[] = [];
      for (const r of this.store.loadMetricSamples(key, win.startMs)) {
        if (r.t < win.startMs || r.t > win.endMs) continue;
        points.push({ t: new Date(r.t).toISOString(), v: Math.round(r.v * 10) / 10 });
      }
      // A series with nothing in the window is dropped rather than returned
      // empty — an empty line in a legend is a name with no data behind it.
      if (points.length === 0) continue;

      const series: NamedSeries = { label: parsed.name, points };
      if (parsed.kind === "pod") {
        (parsed.metric === "cpu" ? out.podCpu : out.podMem).push(series);
      } else {
        (parsed.metric === "cpu" ? out.nodeCpu : out.nodeMem).push(series);
      }
    }

    for (const list of [out.podCpu, out.podMem, out.nodeCpu, out.nodeMem]) {
      list.sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
    }
    return out;
  }

  recordResourceSamples(
    pods: PodResourceUsage[],
    nodes: NodeResourceUsage[],
    nowMs: number,
  ): void {
    recordResourceSamplesTo(this.store, pods, nodes, nowMs);
  }
}

function metricValue(m: MetricsPanel, key: string): number {
  return m.metrics.find((x) => x.key === key)?.current ?? -1;
}

/**
 * Names can contain almost anything, so the name goes last and the parser splits
 * on a fixed number of leading fields rather than on every colon.
 */
function parseSampleKey(
  key: string,
): { kind: "pod" | "node"; metric: "cpu" | "mem"; name: string } | null {
  if (!key.startsWith(RES_PREFIX)) return null;
  const rest = key.slice(RES_PREFIX.length);
  const first = rest.indexOf(":");
  if (first < 0) return null;
  const second = rest.indexOf(":", first + 1);
  if (second < 0) return null;

  const kind = rest.slice(0, first);
  const metric = rest.slice(first + 1, second);
  const name = rest.slice(second + 1);
  if (name === "") return null;
  if (kind !== "pod" && kind !== "node") return null;
  if (metric !== "cpu" && metric !== "mem") return null;
  return { kind, metric, name };
}

/**
 * Appends one reading per series, floored to a 10-second grid: the kube panel
 * polls every 3s, and three rows per pod per 10 seconds is detail nobody reads
 * at three times the table size. The primary key is (key, t), so the floor makes
 * repeated writes within one bucket idempotent.
 *
 * Every series of one poll goes down as a single batch. Writing them one call at
 * a time meant one SQLite transaction — and one retention sweep — per pod per
 * metric, which on a 20-pod cluster was ~40 write-lock acquisitions every three
 * seconds, blocking the settings and credential reads that share the file.
 */
export function recordResourceSamplesTo(
  store: Store,
  pods: PodResourceUsage[],
  nodes: NodeResourceUsage[],
  nowMs: number,
): void {
  const GRID_MS = 10_000;
  const t = Math.floor(nowMs / GRID_MS) * GRID_MS;
  const batch: MetricSampleBatchEntry[] = [];
  const write = (kind: string, metric: string, name: string, v: number | null): void => {
    // A pod with no limit set has no percentage. Writing 0 would draw a floor
    // that reads as "idle" when it means "not measurable".
    if (v === null || !Number.isFinite(v)) return;
    const rows: Sample[] = [{ t, v }];
    batch.push({ key: `${RES_PREFIX}${kind}:${metric}:${name}`, points: rows });
  };
  for (const p of pods) {
    write("pod", "cpu", p.pod, p.cpuPct);
    write("pod", "mem", p.pod, p.memPct);
  }
  for (const n of nodes) {
    write("node", "cpu", n.name, n.cpuPct);
    write("node", "mem", n.name, n.memPct);
  }
  store.saveMetricSampleBatch(batch);
}
