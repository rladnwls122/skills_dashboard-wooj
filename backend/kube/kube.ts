// The Kubernetes-touching layer. Clients are built once and reused.

import {
  AppsV1Api,
  AutoscalingV2Api,
  CoreV1Api,
  Metrics,
  PatchStrategy,
  setHeaderOptions,
  type V1Container,
  type V1ContainerStatus,
  type V1Deployment,
  type V1Node,
  type V1Pod,
} from "@kubernetes/client-node";

import { maskLines } from "../analysis/mask.ts";
import type { Settings } from "../config/config.ts";
import type { Manager } from "../creds/manager.ts";
import type { Store } from "../store/store.ts";
import type {
  ContainerInfo,
  ContainerResourceUsage,
  DeploymentInfo,
  NodeResourceUsage,
  PodInfo,
  PodResourceUsage,
  PodStatusBreakdown,
  ScaleInfo,
  WarningEvent,
} from "../../src/lib/types.ts";
import { kubeConfig, resetKubeConfig, type ExecEnvironmentEntry } from "./kubeconfig.ts";

const HIGHLIGHT_REASONS =
  /(failed|backoff|failedmount|failedscheduling|unhealthy|oom|evicted|killing)/i;

function containerState(cs: V1ContainerStatus): {
  state: string;
  reason: string;
  message: string;
} {
  if (cs.state?.waiting) {
    return {
      state: "Waiting",
      reason: cs.state.waiting.reason ?? "",
      message: cs.state.waiting.message ?? "",
    };
  }
  if (cs.state?.terminated) {
    return {
      state: "Terminated",
      reason: cs.state.terminated.reason ?? "",
      message: cs.state.terminated.message ?? "",
    };
  }
  if (cs.state?.running) return { state: "Running", reason: "", message: "" };
  return { state: "Unknown", reason: "", message: "" };
}

function podStatusLabel(pod: V1Pod): string {
  const statuses = pod.status?.containerStatuses ?? [];
  for (const cs of statuses) {
    const waiting = cs.state?.waiting?.reason;
    if (waiting) return waiting;
    const lastTerm = cs.lastState?.terminated?.reason;
    if (lastTerm === "OOMKilled" && (cs.restartCount ?? 0) > 0 && !cs.ready) return "OOMKilled";
  }
  const phase = pod.status?.phase ?? "Unknown";
  if (phase === "Running") {
    const allReady = statuses.length > 0 && statuses.every((cs) => cs.ready);
    return allReady ? "Running" : "NotReady";
  }
  return phase;
}

function specContainer(pod: V1Pod, name: string): V1Container | undefined {
  return pod.spec?.containers.find((c) => c.name === name);
}

// Kubernetes resource.Quantity parsers (metrics.k8s.io reports usage as Quantity
// strings — not necessarily the same suffix family as requests/limits).
export function parseCpuMilli(qty: string): number {
  const m = /^(\d+(?:\.\d+)?)([nu]?m?)$/.exec(qty);
  if (!m) return 0;
  const value = Number(m[1]);
  switch (m[2]) {
    case "n":
      return value / 1_000_000;
    case "u":
      return value / 1_000;
    case "m":
      return value;
    default:
      return value * 1000;
  }
}

const MEM_UNITS: Record<string, number> = {
  Ki: 1024,
  Mi: 1024 ** 2,
  Gi: 1024 ** 3,
  Ti: 1024 ** 4,
  Pi: 1024 ** 5,
  Ei: 1024 ** 6,
  K: 1000,
  M: 1000 ** 2,
  G: 1000 ** 3,
  T: 1000 ** 4,
  P: 1000 ** 5,
  E: 1000 ** 6,
};

export function parseMemBytes(qty: string): number {
  const m = /^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|Pi|Ei|K|M|G|T|P|E)?$/.exec(qty);
  if (!m) return 0;
  const value = Number(m[1]);
  const suffix = m[2];
  return suffix ? value * (MEM_UNITS[suffix] ?? 1) : value;
}

// metrics.k8s.io answering 404 because the addon is not installed is the usual
// cause here, but the same call also fails on kubeconfig/auth problems — and
// pinning those on the addon sends the operator to install something that is
// already there. So the hint is attached only when the cause is not one of the
// connection-side failures the message already names.
const NOT_A_METRICS_PROBLEM =
  /spawn|ENOENT|EINVAL|ECONNREFUSED|ETIMEDOUT|kubeconfig|Unauthorized|Forbidden|401|403/i;

function metricsErr(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  return NOT_A_METRICS_PROBLEM.test(msg) ? msg : `${msg} (metrics-server addon 필요)`;
}

function pct(usage: number, limit: number | null): number | null {
  if (limit === null || limit <= 0) return null;
  return Math.round((usage / limit) * 1000) / 10;
}

export interface PatchRequest {
  namespace: string;
  name: string;
  replicas?: number;
  containerName?: string;
  cpuLimit?: string;
  memLimit?: string;
}

interface JsonPatchOp {
  op: "add" | "replace";
  path: string;
  value: unknown;
}

const NAME_RE = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const CPU_RE = /^\d+m$|^\d+(\.\d+)?$/;
const MEM_RE = /^\d+(Mi|Gi|M|G)$/;

/**
 * Every rule a patch can be refused by without asking the cluster anything.
 *
 * Pulled out of validatePatch and exported because the service layer has to
 * apply exactly these rules on the preview (확인 화면) path, where there is no
 * Kube instance to reach for. It had its own weaker copy — no integer check on
 * replicas, no quantity regexes — so the confirm screen accepted `replicas: 2.5`
 * and a malformed cpuLimit, and the operator only found out when the apply that
 * followed failed at the API server. One list of rules, one verdict, whichever
 * screen asks.
 */
export function validatePatchRequest(
  req: PatchRequest,
  targetNamespace: string,
  maxReplicas: number,
): void {
  if (!NAME_RE.test(req.namespace)) throw new Error(`invalid namespace: ${req.namespace}`);
  if (req.namespace !== targetNamespace) {
    throw new Error(`namespace must be ${targetNamespace}`);
  }
  if (!NAME_RE.test(req.name)) throw new Error(`invalid deployment name: ${req.name}`);

  if (req.replicas !== undefined) {
    // 2.5 replicas is not a small mistake the API server rounds off: it is a
    // 422 after the operator has already confirmed the change.
    if (!Number.isInteger(req.replicas)) throw new Error("replicas must be an integer");
    if (req.replicas < 0 || req.replicas > maxReplicas) {
      throw new Error(`replicas out of safe range 0..${maxReplicas}`);
    }
  }

  if (req.cpuLimit !== undefined || req.memLimit !== undefined) {
    if (!req.containerName) throw new Error("containerName required for resource change");
    if (req.cpuLimit !== undefined && !CPU_RE.test(req.cpuLimit)) {
      throw new Error(`invalid CPU quantity: ${req.cpuLimit} (e.g. 500m, 1)`);
    }
    if (req.memLimit !== undefined && !MEM_RE.test(req.memLimit)) {
      throw new Error(`invalid memory quantity: ${req.memLimit} (e.g. 256Mi, 1Gi)`);
    }
  }
}

export class Kube {
  private readonly settings: Settings;
  private readonly store: Store | null;
  /**
   * The credentials the 설정 screen injected, or null when this build has no
   * credential manager. Held here for one reason: the kubeconfig's exec-auth
   * plugin is a child process, so the only way an injected key reaches it is as
   * an environment entry attached to the spawn.
   */
  private readonly credentials: Manager | null;

  private core: CoreV1Api | null = null;
  private apps: AppsV1Api | null = null;
  private autoscaling: AutoscalingV2Api | null = null;
  private metrics: Metrics | null = null;

  constructor(settings: Settings, store: Store | null, credentials: Manager | null = null) {
    this.settings = settings;
    this.store = store;
    this.credentials = credentials;
  }

  /**
   * The injected keys in the shape the exec plugin's spawn takes, or an empty
   * list to leave the inherited environment alone — which is exactly how this
   * behaved before injection existed, so an environment that already works keeps
   * working untouched.
   */
  private execEnvironment(): ExecEnvironmentEntry[] {
    const injected = this.credentials?.injected();
    if (!injected) return [];
    return [
      { name: "AWS_ACCESS_KEY_ID", value: injected.accessKeyId },
      { name: "AWS_SECRET_ACCESS_KEY", value: injected.secretAccessKey },
      // Written even when empty — see applyExecEnvironment in kubeconfig.ts.
      { name: "AWS_SESSION_TOKEN", value: injected.sessionToken },
    ];
  }

  /**
   * Drops the memoized API clients and the loaded kubeconfig.
   *
   * The mirror of AWS.reset(): a credential injection or a settings save changes
   * which identity and which cluster every panel reads, and a client built
   * before the change keeps its old bearer token. Without this, injecting keys
   * healed the AWS panels while Kubernetes stayed broken for the life of the
   * process — and re-injecting could not fix it, because nothing in the
   * Kubernetes path was ever rebuilt.
   */
  reset(): void {
    this.core = null;
    this.apps = null;
    this.autoscaling = null;
    this.metrics = null;
    resetKubeConfig();
  }

  private clients(): { core: CoreV1Api; apps: AppsV1Api; autoscaling: AutoscalingV2Api } {
    if (!this.core || !this.apps || !this.autoscaling) {
      const kc = kubeConfig(this.execEnvironment());
      this.core = kc.makeApiClient(CoreV1Api);
      this.apps = kc.makeApiClient(AppsV1Api);
      this.autoscaling = kc.makeApiClient(AutoscalingV2Api);
    }
    return { core: this.core, apps: this.apps, autoscaling: this.autoscaling };
  }

  private metricsClient(): Metrics {
    this.metrics ??= new Metrics(kubeConfig(this.execEnvironment()));
    return this.metrics;
  }

  private ns(): string {
    return this.settings.targetNamespace();
  }

  async listPods(): Promise<PodInfo[]> {
    const { core } = this.clients();
    const ns = this.ns();
    const res = await core.listNamespacedPod({ namespace: ns });
    const nowMs = Date.now();

    return res.items.map((pod) => {
      const statuses = pod.status?.containerStatuses ?? [];
      const containers: ContainerInfo[] = statuses.map((cs) => {
        const spec = specContainer(pod, cs.name);
        const st = containerState(cs);
        return {
          name: cs.name,
          cpuRequest: spec?.resources?.requests?.["cpu"] ?? "-",
          cpuLimit: spec?.resources?.limits?.["cpu"] ?? "-",
          memRequest: spec?.resources?.requests?.["memory"] ?? "-",
          memLimit: spec?.resources?.limits?.["memory"] ?? "-",
          restartCount: cs.restartCount ?? 0,
          state: st.state,
          reason: st.reason,
          message: st.message,
        };
      });
      const totalRestarts = containers.reduce((a, c) => a + c.restartCount, 0);
      const podKey = `${pod.metadata?.namespace ?? ns}/${pod.metadata?.name ?? ""}`;
      let recentRestartIncrease = 0;
      try {
        recentRestartIncrease = this.store?.trackRestarts(podKey, totalRestarts, nowMs) ?? 0;
      } catch {
        // A locked history DB must not empty the pod list.
        recentRestartIncrease = 0;
      }
      const readyCount = statuses.filter((cs) => cs.ready).length;
      return {
        namespace: pod.metadata?.namespace ?? ns,
        name: pod.metadata?.name ?? "",
        phase: pod.status?.phase ?? "Unknown",
        ready: `${readyCount}/${statuses.length}`,
        statusLabel: podStatusLabel(pod),
        containers,
        totalRestarts,
        recentRestartIncrease,
        reason: pod.status?.reason || (containers.find((c) => c.reason)?.reason ?? ""),
        message: pod.status?.message || (containers.find((c) => c.message)?.message ?? ""),
        podIP: pod.status?.podIP ?? "",
        nodeName: pod.spec?.nodeName ?? "",
      };
    });
  }

  async listWarningEvents(): Promise<WarningEvent[]> {
    const { core } = this.clients();
    const ns = this.ns();
    const res = await core.listNamespacedEvent({ namespace: ns, fieldSelector: "type=Warning" });
    const events: WarningEvent[] = res.items.map((ev) => {
      const reason = ev.reason ?? "";
      return {
        timestamp:
          ev.lastTimestamp?.toISOString() ??
          ev.eventTime?.toISOString() ??
          ev.firstTimestamp?.toISOString() ??
          "",
        namespace: ev.metadata.namespace ?? ns,
        kind: ev.involvedObject.kind ?? "",
        name: ev.involvedObject.name ?? "",
        reason,
        message: ev.message ?? "",
        count: ev.count ?? 1,
        isPod: ev.involvedObject.kind === "Pod",
        highlighted: HIGHLIGHT_REASONS.test(reason),
      };
    });
    return events.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
  }

  /**
   * The node listing, once. Two panel fields need it — the ready/total counter
   * and the per-node capacity the usage percentages divide by — and each used to
   * fetch its own copy, which on EKS exec-auth is a second `aws eks get-token`
   * round trip for a response the process already had in hand.
   */
  async listNodes(): Promise<V1Node[]> {
    const { core } = this.clients();
    const res = await core.listNode();
    return res.items;
  }

  async countReadyNodes(): Promise<{ ready: number; total: number }> {
    return readyNodeCounts(await this.listNodes());
  }

  private toDeploymentInfo(d: V1Deployment): DeploymentInfo {
    return {
      namespace: d.metadata?.namespace ?? this.ns(),
      name: d.metadata?.name ?? "",
      replicas: d.spec?.replicas ?? 0,
      readyReplicas: d.status?.readyReplicas ?? 0,
      updatedReplicas: d.status?.updatedReplicas ?? 0,
      availableReplicas: d.status?.availableReplicas ?? 0,
      containers: (d.spec?.template.spec?.containers ?? []).map((c) => ({
        name: c.name,
        image: c.image ?? "",
        cpuRequest: c.resources?.requests?.["cpu"] ?? "-",
        cpuLimit: c.resources?.limits?.["cpu"] ?? "-",
        memRequest: c.resources?.requests?.["memory"] ?? "-",
        memLimit: c.resources?.limits?.["memory"] ?? "-",
      })),
    };
  }

  async listDeployments(): Promise<DeploymentInfo[]> {
    const { apps } = this.clients();
    const res = await apps.listNamespacedDeployment({ namespace: this.ns() });
    return res.items.map((d) => this.toDeploymentInfo(d));
  }

  async getDeployment(namespace: string, name: string): Promise<DeploymentInfo> {
    const { apps } = this.clients();
    return this.toDeploymentInfo(await apps.readNamespacedDeployment({ name, namespace }));
  }

  /**
   * The direct Kubernetes tail — previous-container forensics and the fallback
   * when Insights is unavailable. Lines are masked before leaving.
   */
  async getPodLogs(
    pod: string,
    container: string,
    previous: boolean,
    tailLines: number,
  ): Promise<string[]> {
    const { core } = this.clients();
    const text = await core.readNamespacedPodLog({
      name: pod,
      namespace: this.ns(),
      container,
      previous,
      tailLines: Math.min(Math.max(tailLines, 10), 2000),
      timestamps: true,
    });
    return maskLines((text ?? "").split("\n").filter((l) => l.length > 0));
  }

  // --- patch -----------------------------------------------------------------

  /**
   * Rejects before touching the API (spec §22). The cluster-free rules run
   * first, through the same validatePatchRequest the preview path uses — a
   * request the confirm screen accepted must never be refused here, and a
   * request it refused must never be accepted here.
   */
  async validatePatch(
    req: PatchRequest,
  ): Promise<{ deployment: DeploymentInfo; containerIndex: number }> {
    validatePatchRequest(req, this.ns(), this.settings.maxReplicas());

    const deployment = await this.getDeployment(req.namespace, req.name);

    // The only check that genuinely needs the cluster: whether the named
    // container is in this deployment's pod template.
    let containerIndex = -1;
    if (req.cpuLimit !== undefined || req.memLimit !== undefined) {
      containerIndex = deployment.containers.findIndex((c) => c.name === req.containerName);
      if (containerIndex < 0) throw new Error(`container not found: ${req.containerName}`);
    }
    return { deployment, containerIndex };
  }

  async patchDeployment(req: PatchRequest): Promise<DeploymentInfo> {
    const { apps } = this.clients();
    const { containerIndex } = await this.validatePatch(req);

    const ops: JsonPatchOp[] = [];
    if (req.replicas !== undefined) {
      ops.push({ op: "replace", path: "/spec/replicas", value: req.replicas });
    }
    if (containerIndex >= 0) {
      const current = await apps.readNamespacedDeployment({
        name: req.name,
        namespace: req.namespace,
      });
      const container = current.spec?.template.spec?.containers[containerIndex];
      if (!container) throw new Error("container disappeared during validation");
      const resources = {
        requests: { ...(container.resources?.requests ?? {}) },
        limits: { ...(container.resources?.limits ?? {}) } as Record<string, string>,
      };
      if (req.cpuLimit !== undefined) resources.limits["cpu"] = req.cpuLimit;
      if (req.memLimit !== undefined) resources.limits["memory"] = req.memLimit;
      ops.push({
        op: "add",
        path: `/spec/template/spec/containers/${containerIndex}/resources`,
        value: resources,
      });
    }
    if (ops.length === 0) throw new Error("no changes requested");

    const patched = await apps.patchNamespacedDeployment(
      { name: req.name, namespace: req.namespace, body: ops },
      setHeaderOptions("Content-Type", PatchStrategy.JsonPatch),
    );
    return this.toDeploymentInfo(patched);
  }

  // --- resource usage (metrics.k8s.io) ---------------------------------------

  async getPodResourceUsage(
    pods: PodInfo[],
  ): Promise<{ data: PodResourceUsage[]; error: string | null }> {
    try {
      const res = await this.metricsClient().getPodMetrics(this.ns());
      const podByName = new Map(pods.map((p) => [p.name, p]));
      const data: PodResourceUsage[] = res.items.map((pm) => {
        const podInfo = podByName.get(pm.metadata.name);
        let cpuTotal = 0;
        let memTotal = 0;
        let cpuLimitTotal = 0;
        let memLimitTotal = 0;
        let allCpuLimits = true;
        let allMemLimits = true;

        const containers: ContainerResourceUsage[] = pm.containers.map((cm) => {
          const spec = podInfo?.containers.find((c) => c.name === cm.name);
          const cpuLimit =
            spec && spec.cpuLimit !== "" && spec.cpuLimit !== "-"
              ? parseCpuMilli(spec.cpuLimit)
              : null;
          const memLimit =
            spec && spec.memLimit !== "" && spec.memLimit !== "-"
              ? parseMemBytes(spec.memLimit)
              : null;
          const cpuUsage = parseCpuMilli(cm.usage.cpu);
          const memUsage = parseMemBytes(cm.usage.memory);

          if (cpuLimit === null) allCpuLimits = false;
          else cpuLimitTotal += cpuLimit;
          if (memLimit === null) allMemLimits = false;
          else memLimitTotal += memLimit;
          cpuTotal += cpuUsage;
          memTotal += memUsage;

          return {
            container: cm.name,
            cpuUsage: cm.usage.cpu,
            cpuUsageMilli: cpuUsage,
            memUsage: cm.usage.memory,
            memUsageBytes: memUsage,
            cpuLimitMilli: cpuLimit,
            memLimitBytes: memLimit,
            cpuPct: pct(cpuUsage, cpuLimit),
            memPct: pct(memUsage, memLimit),
          };
        });

        return {
          pod: pm.metadata.name,
          containers,
          cpuUsageMilli: cpuTotal,
          memUsageBytes: memTotal,
          cpuPct: allCpuLimits && containers.length > 0 ? pct(cpuTotal, cpuLimitTotal) : null,
          memPct: allMemLimits && containers.length > 0 ? pct(memTotal, memLimitTotal) : null,
        };
      });
      return { data, error: null };
    } catch (e) {
      return { data: [], error: metricsErr(e) };
    }
  }

  /**
   * Node usage against node capacity.
   *
   * `nodes` is the listing the caller already fetched. Passing it in is what
   * lets the kube panel read the node list once instead of twice; leaving it out
   * keeps the self-contained behaviour every other caller relies on. Deliberately
   * not "pass [] when the shared listing failed": with no capacities every
   * percentage divides by zero and renders as 0%, which reads as an idle cluster
   * rather than as a failed read — so a caller whose listing failed passes
   * nothing and lets this method fail on its own terms.
   */
  async getNodeResourceUsage(
    nodes?: V1Node[],
  ): Promise<{ data: NodeResourceUsage[]; error: string | null }> {
    try {
      const [metricsRes, nodeItems] = await Promise.all([
        this.metricsClient().getNodeMetrics(),
        nodes ?? this.listNodes(),
      ]);
      const capByName = new Map(
        nodeItems.map((n) => [
          n.metadata?.name ?? "",
          {
            cpuMilli: parseCpuMilli(n.status?.allocatable?.["cpu"] ?? "0"),
            memBytes: parseMemBytes(n.status?.allocatable?.["memory"] ?? "0"),
          },
        ]),
      );
      const data: NodeResourceUsage[] = metricsRes.items.map((nm) => {
        const cap = capByName.get(nm.metadata.name) ?? { cpuMilli: 0, memBytes: 0 };
        const cpuUsage = parseCpuMilli(nm.usage.cpu);
        const memUsage = parseMemBytes(nm.usage.memory);
        return {
          name: nm.metadata.name,
          cpuUsageMilli: cpuUsage,
          memUsageBytes: memUsage,
          cpuCapacityMilli: cap.cpuMilli,
          memCapacityBytes: cap.memBytes,
          cpuPct: pct(cpuUsage, cap.cpuMilli) ?? 0,
          memPct: pct(memUsage, cap.memBytes) ?? 0,
        };
      });
      return { data, error: null };
    } catch (e) {
      return { data: [], error: metricsErr(e) };
    }
  }

  /** Reads HPAs; a deployment without one reports its fixed replica count. */
  async getPodScaling(deployments: DeploymentInfo[]): Promise<ScaleInfo[]> {
    interface HpaInfo {
      target: string;
      min: number;
      max: number;
      current: number;
    }
    const hpas: HpaInfo[] = [];
    try {
      const { autoscaling } = this.clients();
      const res = await autoscaling.listNamespacedHorizontalPodAutoscaler({
        namespace: this.ns(),
      });
      for (const h of res.items) {
        hpas.push({
          target: h.spec?.scaleTargetRef.name ?? "",
          min: h.spec?.minReplicas ?? 1,
          max: h.spec?.maxReplicas ?? 0,
          current: h.status?.currentReplicas || (h.status?.desiredReplicas ?? 0),
        });
      }
    } catch {
      // No HPA access is not an error — every deployment then reports its fixed
      // replica count.
    }

    return deployments.map((d) => {
      const hpa = hpas.find((h) => h.target === d.name);
      if (hpa) {
        return { name: d.name, current: hpa.current, min: hpa.min, max: hpa.max, source: "HPA" };
      }
      return {
        name: d.name,
        current: d.replicas,
        min: null,
        max: null,
        source: "HPA 없음 (고정 replicas)",
      };
    });
  }
}

/**
 * Ready/total out of a node listing the caller already has. Split from
 * countReadyNodes so the kube panel can count from the same response the
 * capacity lookup reads, rather than paying for a second listNode().
 */
export function readyNodeCounts(nodes: V1Node[]): { ready: number; total: number } {
  let ready = 0;
  for (const node of nodes) {
    if (node.status?.conditions?.find((c) => c.type === "Ready")?.status === "True") ready++;
  }
  return { ready, total: nodes.length };
}

export function summarizePodStatus(pods: PodInfo[]): PodStatusBreakdown {
  const b: PodStatusBreakdown = {
    total: pods.length,
    running: 0,
    pending: 0,
    crashLoop: 0,
    oom: 0,
    failed: 0,
    other: 0,
  };
  for (const p of pods) {
    if (p.statusLabel === "CrashLoopBackOff") b.crashLoop++;
    else if (p.statusLabel === "OOMKilled") b.oom++;
    else if (p.statusLabel === "Running") b.running++;
    else if (
      p.statusLabel === "Pending" ||
      p.statusLabel === "ContainerCreating" ||
      p.statusLabel === "PodInitializing"
    ) {
      b.pending++;
    } else if (p.phase === "Failed") b.failed++;
    else b.other++;
  }
  return b;
}
