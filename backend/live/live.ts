// The real Provider: AWS reads through awsx, Kubernetes through kube, the rule
// engine through rules. It also owns the panel-level TTL caches (kube 3s tier,
// metrics 30s tier, log reads 30s), including the cross-panel peeks the anomaly
// detector and the incident report depend on.

import { detectAnomalies, type AnomalyInput } from "../analysis/anomaly.ts";
import {
  buildTimeline,
  correlate,
  type HistoryInput,
} from "../analysis/correlation.ts";
import { AWS, errMsg } from "../awsx/clients.ts";
import { discoverNodeGroupScaling } from "../awsx/alb.ts";
import { fetchCoreMetrics, fetchTargetGroupMetrics } from "../awsx/cloudwatch.ts";
import { checkCredentials as awsCheckCredentials } from "../awsx/credcheck.ts";
import { discover as awsDiscover } from "../awsx/discover.ts";
import { fetchGradingPanel } from "../awsx/grading.ts";
import { buildHttpSummary, getAclInfo, listSampleRows } from "../awsx/waf.ts";
import { setRuleAction } from "../awsx/wafupdate.ts";
import { cached, invalidate, peek, put } from "../cache/cache.ts";
import { POLLING, type Settings } from "../config/config.ts";
import { Manager, defaultProfile } from "../creds/manager.ts";
import { Kube, readyNodeCounts, summarizePodStatus } from "../kube/kube.ts";
import { assembleRule as buildAssembledRule } from "../rules/assemble.ts";
import { testRule as runTestRule } from "../rules/sim.ts";
import { recordResourceSamplesTo } from "../service/service.ts";
import type {
  AssembledRule,
  CountEvidence,
  CredentialCheck,
  CredentialsView,
  DeployChangeEntry,
  DeploymentInfo,
  DiscoveryResult,
  FingerprintEntry,
  GradingPanel,
  HttpSummary,
  IncidentContextResult,
  KubePanel,
  MetricsPanel,
  MetricSummary,
  NodeCountProjection,
  PodLogsResult,
  RequestLogQueryResult,
  ResolvedWindow,
  RuleTestResult,
  ScaleInfo,
  StatusDistribution,
  TargetGroupMetrics,
  WafLogQueryResult,
  WafPanel,
  WafSampleRow,
} from "../../src/lib/types.ts";
import type { MetricsPanelFull, WafRuleUpdateResult } from "../types/types.ts";
import { isComplete, parseCredentialBlob } from "../../src/lib/awscreds.ts";
import type { Store } from "../store/store.ts";
import type {
  CredentialsInput,
  DeploymentPatchRequest,
  ImportCredentialsInput,
  PodLogsParams,
  Provider,
  RequestLogParams,
  RuleTestParams,
  WafLogParams,
} from "../service/provider.ts";
import { countEvidence } from "./countevidence.ts";
import { incidentContext } from "./incident.ts";
import { BackfillState, nodeCost } from "./nodecost.ts";
import { podLogs, requestLogRows } from "./podlogs.ts";
import { windowKey } from "./shared.ts";
import { wafLogRows } from "./waflog.ts";

/** Mirrors VISIBLE_METRICS on the dashboard. */
const VISIBLE_METRICS = [
  "targetResponseTime",
  "http4xx",
  "http5xx",
  "rdsClientConnections",
  "rdsDatabaseConnections",
  "wafBlocked",
  "wafAllowed",
];

/** The stand-in for the one assembly kind that reads no traffic at all. */
const EMPTY_SUMMARY: HttpSummary = {
  totalSampled: 0,
  windowLabel: "",
  source: "",
  byPath: [],
  byIp: [],
  byUa: [],
  uaActions: [],
  surface: null,
  byMethod: [],
  queryPatterns: [],
  headerPatterns: [],
  blockedTotal: 0,
  statusDist: null,
  detailedStatus: null,
  notes: [],
};

export class LiveProvider implements Provider {
  readonly aws: AWS;
  readonly kube: Kube;
  readonly store: Store;
  readonly settings: Settings;
  readonly creds: Manager;
  /** Injectable clock, so window resolution is testable without waiting. */
  now: () => number = () => Date.now();

  /** Guards the one-shot CloudTrail backfill behind the node-count panel. */
  readonly backfill = new BackfillState();

  constructor(settings: Settings, store: Store) {
    this.settings = settings;
    this.store = store;
    this.creds = new Manager(store);
    this.aws = new AWS(settings, store, this.creds);
    // The credential manager goes to Kubernetes too: the kubeconfig's exec-auth
    // plugin spawns `aws eks get-token`, and a key injected on the 설정 화면
    // reaches a child process only if it is put in that spawn's environment.
    this.kube = new Kube(settings, store, this.creds);
  }

  /**
   * Everything memoized against the previous identity or region.
   *
   * Both halves, deliberately. This used to reset only the AWS clients, so after
   * pasting keys the CloudWatch and WAF panels recovered within one poll while
   * Kubernetes went on failing with the error it had before — for the life of
   * the process, and re-injecting could not clear it. That asymmetry is worse
   * than a flat failure: it tells the operator the injection worked.
   */
  reset(): void {
    this.aws.reset();
    this.kube.reset();
  }

  /**
   * Makes a fresh start behave like pressing the 설정 화면's CLI 불러오기 button
   * once: when nothing else supplies a key — no persisted injection from a
   * previous run, no environment key — the local `aws` CLI's profile is imported
   * session-only. Best-effort by design: a machine with no aws CLI configured
   * logs one line and runs exactly as before, with the settings screen still
   * available to inject by hand.
   */
  async bootstrapCredentials(): Promise<void> {
    if (this.creds.injected()) {
      // A persisted injection from a previous run is already in force, and it
      // was a deliberate choice — do not shadow it with the CLI session.
      return;
    }
    const env = {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? "",
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? "",
      sessionToken: "",
      expiration: "",
    };
    if (isComplete(env)) {
      // The environment is in charge; importProfile would refuse anyway.
      return;
    }
    const profile = defaultProfile();
    try {
      await this.creds.importProfile(profile, false);
    } catch (e) {
      console.log(
        `CLI 자격증명 자동 불러오기 실패 (profile "${profile}"): ${errMsg(e)} — 설정 탭에서 직접 불러올 수 있습니다`,
      );
      return;
    }
    // SDK clients capture the credential provider at construction and the
    // kubeconfig captures the exec-auth environment; anything built before this
    // import must be rebuilt.
    this.reset();
    console.log(`CLI 자격증명 자동 불러오기 완료 (profile "${profile}", 세션 한정)`);
  }

  // --- Kubernetes panel — 3s tier -------------------------------------------

  kubePanel(): Promise<KubePanel> {
    return cached("panel:kube", POLLING.kubeTtl, async () => {
      // Two waves, not eight sequential awaits. On EKS every call carries
      // exec-auth (~300ms), so eight in a row took longer than the 3s TTL this
      // is cached under — the cache never went warm, every poll paid the full
      // cost, and the 화면 lagged the cluster by the length of the chain. The
      // reads inside each wave are independent; the only real ordering is that
      // pod usage needs the pod list and pod scaling needs the deployments.
      //
      // Failure handling is unchanged and has to stay that way: listPods is
      // wrapped rather than caught so its error can be re-thrown *after* the
      // panel object exists, and every other read keeps the default it degraded
      // to before.
      const [podsResult, events, deployments, nodesResult] = await Promise.all([
        this.kube.listPods().then(
          (v) => ({ ok: true as const, v }),
          (e: unknown) => ({ ok: false as const, e }),
        ),
        this.kube.listWarningEvents().catch(() => []),
        this.kube.listDeployments().catch(() => []),
        this.kube.listNodes().then(
          (v) => ({ ok: true as const, v }),
          () => ({ ok: false as const, v: [] }),
        ),
      ]);
      const pods = podsResult.ok ? podsResult.v : [];
      const nodes = nodesResult.ok ? readyNodeCounts(nodesResult.v) : { ready: 0, total: 0 };

      const [podUsage, nodeUsage, podScaling, nodeScaling] = await Promise.all([
        this.kube.getPodResourceUsage(pods),
        // The listing above when it worked; undefined when it did not, so the
        // usage read fails with the real reason instead of dividing every
        // percentage by a capacity of zero and drawing an idle cluster.
        this.kube.getNodeResourceUsage(nodesResult.ok ? nodesResult.v : undefined),
        this.kube.getPodScaling(deployments),
        this.nodeScaling(nodes.total),
      ]);

      const panel: KubePanel = {
        pods,
        events,
        deployments,
        nodesReady: nodes.ready,
        nodesTotal: nodes.total,
        statusBreakdown: summarizePodStatus(pods),
        podResources: podUsage.data,
        podResourceError: podUsage.error,
        nodeResources: nodeUsage.data,
        nodeResourceError: nodeUsage.error,
        podScaling,
        nodeScaling,
        scalingError: null,
      };
      if (!podsResult.ok) throw podsResult.e as Error;

      // metrics.k8s.io keeps no history, so the reading is appended here — on
      // the poll that already exists. Recording must never break the panel.
      try {
        recordResourceSamplesTo(this.store, panel.podResources, panel.nodeResources, this.now());
      } catch {
        // ignored
      }
      return panel;
    });
  }

  private async nodeScaling(currentNodeCount: number): Promise<ScaleInfo[]> {
    let groups;
    try {
      groups = await discoverNodeGroupScaling(this.aws);
    } catch (e) {
      return [
        {
          name: "cluster",
          current: currentNodeCount,
          min: null,
          max: null,
          source: "조회 실패: " + errMsg(e),
        },
      ];
    }
    if (groups.length === 0) {
      return [
        {
          name: "cluster",
          current: currentNodeCount,
          min: null,
          max: null,
          source: "managed nodegroup 없음 (Karpenter 등 — min/max 미검출)",
        },
      ];
    }
    return groups.map((g) => ({
      name: g.name,
      current: g.desiredSize,
      min: g.minSize,
      max: g.maxSize,
      source: "EKS Managed Nodegroup",
    }));
  }

  // --- metrics + analysis panel — 30s tier ----------------------------------

  async metricsPanel(win: ResolvedWindow): Promise<MetricsPanelFull> {
    const panel = await cached(
      "panel:metrics:" + windowKey(win),
      POLLING.metricsTtl,
      async () => {
        const core = await fetchCoreMetrics(this.aws, win);
        const byKey = new Map<string, MetricSummary>(core.summaries.map((m) => [m.key, m]));

        let statusDist: StatusDistribution | null = null;
        const c2 = byKey.get("http2xx");
        if (c2) {
          const c3 = byKey.get("http3xx")?.current ?? 0;
          const c4 = byKey.get("http4xx")?.current ?? 0;
          const c5 = byKey.get("http5xx")?.current ?? 0;
          statusDist = {
            c2xx: c2.current,
            c3xx: c3,
            c4xx: c4,
            c5xx: c5,
            total: c2.current + c3 + c4 + c5,
          };
        }

        let httpSummary: HttpSummary | null = null;
        let httpSummaryError: string | null = null;
        try {
          httpSummary = await buildHttpSummary(this.aws, statusDist, win);
        } catch (e) {
          httpSummaryError = errMsg(e);
        }

        let targetGroupMetrics: TargetGroupMetrics[] = [];
        let targetGroupError: string | null = null;
        try {
          targetGroupMetrics = await fetchTargetGroupMetrics(this.aws, win);
        } catch (e) {
          targetGroupError = errMsg(e);
        }

        const kubePanel = peek<KubePanel>("panel:kube");
        const input: AnomalyInput = {
          metrics: core.summaries,
          httpSummary,
          pods: kubePanel?.pods ?? [],
          events: kubePanel?.events ?? [],
          fingerprints: peek<FingerprintEntry[]>("panel:fingerprints") ?? [],
        };
        const now = new Date(this.now());
        const anomalies = detectAnomalies(input, now);

        return {
          metrics: VISIBLE_METRICS.map((k) => byKey.get(k)).filter(
            (m): m is MetricSummary => m !== undefined,
          ),
          metricErrors: core.errors,
          targetGroupMetrics,
          targetGroupError,
          httpSummary,
          httpSummaryError,
          anomalies,
          correlations: correlate(anomalies),
          timeline: buildTimeline(input, anomalies, this.historyInput(), now),
          window: win,
        };
      },
    );
    // The window-free alias other panels peek (the incident report).
    put("panel:metrics:latest", POLLING.metricsTtl, panel);
    return panel;
  }

  /**
   * Folds SQLite history into the timeline; a missing DB must not take the panel
   * down.
   */
  private historyInput(): HistoryInput {
    const h: HistoryInput = { restartEvents: [], deployHistory: [], wafHistory: [] };
    try {
      h.restartEvents = this.store.recentRestartEvents(this.now() - 60 * 60_000);
    } catch {
      // ignored
    }
    try {
      h.deployHistory = this.store.listDeployHistory().map(
        (r): DeployChangeEntry => ({
          id: r.id,
          ts: new Date(r.ts).toISOString(),
          namespace: r.namespace,
          name: r.name,
          change: r.change,
          verdict: r.verdict,
        }),
      );
    } catch {
      // ignored
    }
    try {
      h.wafHistory = this.store.listWafHistoryRows();
    } catch {
      // ignored
    }
    return h;
  }

  // --- WAF panel — 30s tier --------------------------------------------------

  wafPanel(win: ResolvedWindow): Promise<WafPanel> {
    return cached("panel:waf:" + windowKey(win), POLLING.wafTtl, async () => {
      const panel: WafPanel = { acl: null, aclError: null, history: [] };
      try {
        panel.acl = await getAclInfo(this.aws);
      } catch (e) {
        panel.aclError = errMsg(e);
      }
      try {
        panel.history = this.store.applyHistory();
      } catch {
        // The rule list is the point of this panel; history is a bonus.
      }
      return panel;
    });
  }

  wafSamples(): Promise<WafSampleRow[]> {
    return listSampleRows(this.aws);
  }

  // --- grading — on-demand, cached like every other Insights read ------------

  gradingPanel(win: ResolvedWindow): Promise<GradingPanel> {
    return cached(
      "panel:grading:" + windowKey(win),
      POLLING.logCacheTtl,
      () => fetchGradingPanel(this.aws, win),
      POLLING.logFailTtl,
    );
  }

  // --- logs ------------------------------------------------------------------

  podLogs(p: PodLogsParams, win: ResolvedWindow): Promise<PodLogsResult> {
    return podLogs(this, p, win);
  }

  requestLogRows(p: RequestLogParams, win: ResolvedWindow): Promise<RequestLogQueryResult> {
    return requestLogRows(this, p, win);
  }

  wafLogRows(p: WafLogParams, win: ResolvedWindow): Promise<WafLogQueryResult> {
    return wafLogRows(this, p, win);
  }

  countEvidence(ruleName: string, win: ResolvedWindow): Promise<CountEvidence> {
    return countEvidence(this, ruleName, win);
  }

  incidentContext(): Promise<IncidentContextResult> {
    return incidentContext(this);
  }

  nodeCost(): Promise<NodeCountProjection> {
    return nodeCost(this);
  }

  // --- deployments -----------------------------------------------------------

  deployment(namespace: string, name: string): Promise<DeploymentInfo> {
    return this.kube.getDeployment(namespace, name);
  }

  patchDeployment(req: DeploymentPatchRequest): Promise<DeploymentInfo> {
    return this.kube.patchDeployment(req);
  }

  // --- discovery / rules -----------------------------------------------------

  discover(kind: string): Promise<DiscoveryResult> {
    return awsDiscover(this.aws, kind);
  }

  async assembleRule(kind: string, win: ResolvedWindow): Promise<AssembledRule> {
    const env = {
      wafScope: this.settings.wafScope(),
      wafRegion: this.settings.wafRegion(),
    };
    // SQLi is a fixed signature set, so it must not fail when the WAF summary is
    // unavailable — only the observed kinds need live traffic.
    if (kind === "sqli") return buildAssembledRule("sqli", EMPTY_SUMMARY, env);
    const summary = await buildHttpSummary(this.aws, null, win);
    return buildAssembledRule(kind, summary, env);
  }

  testRule(p: RuleTestParams): Promise<RuleTestResult> {
    return Promise.resolve(runTestRule(p.ruleJson, p.requests));
  }

  // --- WAF rule apply --------------------------------------------------------

  /**
   * Apply, promote, demote and remove — one call, because the rule is keyed by
   * its Name and "promote" is "put it back at the other action". Every press is
   * a person's press; nothing on this screen changes a WebACL on its own.
   *
   * The grading keys as they stood at the moment of the change go into the
   * history row with it. That snapshot is what the false-block alarm compares
   * against five minutes later, and it has to be taken here, before the rule can
   * have moved anything.
   */
  async updateWafRule(
    ruleJson: string,
    action: string | null,
    win: ResolvedWindow,
  ): Promise<WafRuleUpdateResult> {
    const want = action ?? "";
    const snapshot = this.gradingSnapshot(win);
    let update;
    try {
      update = await setRuleAction(this.aws, ruleJson, want);
    } catch (e) {
      // The attempt is recorded either way: an operator who pressed the button
      // and saw an error still changed nothing, and the history is what the
      // incident report reads.
      try {
        this.store.insertWafHistory(
          nameOrPasted(ruleJson),
          actionLabel(want),
          "FAILED",
          errMsg(e),
          "",
          this.now(),
        );
      } catch {
        // ignored
      }
      invalidate("panel:waf");
      throw e;
    }
    const historyId = this.store.insertWafHistory(
      update.ruleName,
      actionLabel(want),
      "SUCCESS",
      snapshot,
      update.priorRules,
      this.now(),
    );
    // The rule list on screen is read from the WebACL, so it has to be re-read
    // rather than patched locally.
    invalidate("panel:waf");
    return { ruleName: update.ruleName, historyId };
  }

  /**
   * Whatever the 성능 tab last aggregated, over the same window it is showing.
   * Never re-queried here: a rule change is not a reason to spend an Insights
   * scan, and a five-minute-old baseline is still the baseline the operator was
   * looking at when they pressed the button.
   */
  private gradingSnapshot(win: ResolvedWindow): string {
    const grading = peek<GradingPanel>("panel:grading:" + windowKey(win));
    return JSON.stringify({
      at: this.now(),
      keys: (grading?.lines ?? []).map((l) => ({
        label: l.label,
        pct: l.pct,
        total: l.total,
      })),
    });
  }

  // --- AWS credentials -------------------------------------------------------
  //
  // The keys never travel back to the browser: every method here returns the
  // masked view, and the input is one-way.

  credentialsView(nowMs: number): CredentialsView {
    return this.creds.view(nowMs);
  }

  saveCredentials(input: CredentialsInput): Promise<void> {
    // The blob is parsed on the server as well as in the browser so a paste that
    // only the server sees (autofill, a form post) lands the same way.
    const pasted =
      (input.blob ?? "").trim() !== ""
        ? parseCredentialBlob(input.blob)
        : { accessKeyId: "", secretAccessKey: "", sessionToken: "", expiration: "" };
    const pick = (typed: string, fromBlob: string): string =>
      (typed ?? "").trim() !== "" ? typed : fromBlob;

    this.creds.set({
      accessKeyId: pick(input.accessKeyId, pasted.accessKeyId),
      secretAccessKey: pick(input.secretAccessKey, pasted.secretAccessKey),
      sessionToken: pick(input.sessionToken, pasted.sessionToken),
      expiration: pasted.expiration,
      origin: "paste",
      persist: input.persist,
    });
    return Promise.resolve();
  }

  /**
   * Resolves the session the local `aws` profile is holding — SSO included — and
   * injects it. This is the path that keeps working on its own: the provider
   * re-reads the profile as the session token expires.
   */
  async importCredentials(input: ImportCredentialsInput): Promise<void> {
    await this.creds.importProfile(input.profile, input.persist);
  }

  clearCredentials(): Promise<void> {
    this.creds.clear();
    return Promise.resolve();
  }

  checkCredentials(): Promise<CredentialCheck> {
    return awsCheckCredentials(this.aws);
  }
}

function actionLabel(action: string): string {
  return action === "" ? "REMOVE" : action;
}

/**
 * The best name available for a failed apply: the rule's own Name when the JSON
 * parsed, and a placeholder when it did not.
 */
function nameOrPasted(ruleJson: string): string {
  try {
    const doc = JSON.parse(ruleJson) as { Name?: unknown };
    if (typeof doc.Name === "string" && doc.Name !== "") return doc.Name;
  } catch {
    // fall through
  }
  return "(이름 없음)";
}
