import "server-only";
import {
  AppsV1Api,
  CoreV1Api,
  KubeConfig,
  PatchStrategy,
  setHeaderOptions,
  type V1Container,
  type V1ContainerStatus,
  type V1Deployment,
  type V1Pod,
} from "@kubernetes/client-node";
import { ENV } from "./config";
import { trackRestarts } from "./db";
import { maskLines } from "./mask";
import type {
  ContainerInfo,
  DeploymentInfo,
  PodInfo,
  WarningEvent,
} from "@/lib/types";

let core: CoreV1Api | null = null;
let apps: AppsV1Api | null = null;

function clients(): { core: CoreV1Api; apps: AppsV1Api } {
  if (!core || !apps) {
    const kc = new KubeConfig();
    if (process.env.KUBERNETES_SERVICE_HOST) {
      kc.loadFromCluster();
    } else {
      kc.loadFromDefault();
    }
    core = kc.makeApiClient(CoreV1Api);
    apps = kc.makeApiClient(AppsV1Api);
  }
  return { core, apps };
}

const HIGHLIGHT_REASONS =
  /(failed|backoff|failedmount|failedscheduling|unhealthy|oom|evicted|killing)/i;

function containerState(cs: V1ContainerStatus): { state: string; reason: string; message: string } {
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

export async function listPods(): Promise<PodInfo[]> {
  const { core: api } = clients();
  const res = await api.listNamespacedPod({ namespace: ENV.targetNamespace });
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
    const podKey = `${pod.metadata?.namespace}/${pod.metadata?.name}`;
    let recentRestartIncrease = 0;
    try {
      recentRestartIncrease = trackRestarts(podKey, totalRestarts).recentIncrease;
    } catch {
      recentRestartIncrease = 0;
    }
    const readyCount = statuses.filter((cs) => cs.ready).length;
    return {
      namespace: pod.metadata?.namespace ?? ENV.targetNamespace,
      name: pod.metadata?.name ?? "",
      phase: pod.status?.phase ?? "Unknown",
      ready: `${readyCount}/${statuses.length}`,
      statusLabel: podStatusLabel(pod),
      containers,
      totalRestarts,
      recentRestartIncrease,
      reason: pod.status?.reason ?? containers.find((c) => c.reason)?.reason ?? "",
      message: pod.status?.message ?? containers.find((c) => c.message)?.message ?? "",
      podIP: pod.status?.podIP ?? "",
      nodeName: pod.spec?.nodeName ?? "",
    };
  });
}

export async function listWarningEvents(): Promise<WarningEvent[]> {
  const { core: api } = clients();
  const res = await api.listNamespacedEvent({
    namespace: ENV.targetNamespace,
    fieldSelector: "type=Warning",
  });
  const events: WarningEvent[] = res.items.map((ev) => {
    const ts =
      ev.lastTimestamp?.toISOString() ??
      ev.eventTime?.toISOString() ??
      ev.firstTimestamp?.toISOString() ??
      "";
    const reason = ev.reason ?? "";
    return {
      timestamp: ts,
      namespace: ev.metadata.namespace ?? ENV.targetNamespace,
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

export async function countReadyNodes(): Promise<{ ready: number; total: number }> {
  const { core: api } = clients();
  const res = await api.listNode();
  let ready = 0;
  for (const node of res.items) {
    const cond = node.status?.conditions?.find((c) => c.type === "Ready");
    if (cond?.status === "True") ready += 1;
  }
  return { ready, total: res.items.length };
}

function toDeploymentInfo(d: V1Deployment): DeploymentInfo {
  return {
    namespace: d.metadata?.namespace ?? ENV.targetNamespace,
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

export async function listDeployments(): Promise<DeploymentInfo[]> {
  const { apps: api } = clients();
  const res = await api.listNamespacedDeployment({ namespace: ENV.targetNamespace });
  return res.items.map(toDeploymentInfo);
}

export async function getDeployment(namespace: string, name: string): Promise<DeploymentInfo> {
  const { apps: api } = clients();
  const d = await api.readNamespacedDeployment({ name, namespace });
  return toDeploymentInfo(d);
}

export async function getPodLogs(params: {
  pod: string;
  container: string;
  previous: boolean;
  tailLines: number;
}): Promise<string[]> {
  const { core: api } = clients();
  const text = await api.readNamespacedPodLog({
    name: params.pod,
    namespace: ENV.targetNamespace,
    container: params.container,
    previous: params.previous,
    tailLines: Math.min(Math.max(params.tailLines, 10), 2000),
    timestamps: true,
  });
  const lines = (text ?? "").split("\n").filter((l) => l.length > 0);
  return maskLines(lines);
}

const NAMESPACE_RE = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const CPU_RE = /^\d+m$|^\d+(\.\d+)?$/;
const MEM_RE = /^\d+(Mi|Gi|M|G)$/;

export interface DeploymentPatchRequest {
  namespace: string;
  name: string;
  replicas?: number;
  containerName?: string;
  cpuLimit?: string;
  memLimit?: string;
}

// Server-side validation (spec §22) — reject before touching the API.
export async function validatePatch(
  req: DeploymentPatchRequest,
): Promise<{ deployment: DeploymentInfo; containerIndex: number }> {
  if (!NAMESPACE_RE.test(req.namespace)) throw new Error(`invalid namespace: ${req.namespace}`);
  if (req.namespace !== ENV.targetNamespace) {
    throw new Error(`namespace must be ${ENV.targetNamespace}`);
  }
  if (!NAMESPACE_RE.test(req.name)) throw new Error(`invalid deployment name: ${req.name}`);

  const deployment = await getDeployment(req.namespace, req.name);

  if (req.replicas !== undefined) {
    if (!Number.isInteger(req.replicas)) throw new Error("replicas must be an integer");
    if (req.replicas < 0 || req.replicas > ENV.maxReplicas) {
      throw new Error(`replicas out of safe range 0..${ENV.maxReplicas}`);
    }
  }

  let containerIndex = -1;
  if (req.cpuLimit !== undefined || req.memLimit !== undefined) {
    if (!req.containerName) throw new Error("containerName required for resource change");
    containerIndex = deployment.containers.findIndex((c) => c.name === req.containerName);
    if (containerIndex < 0) throw new Error(`container not found: ${req.containerName}`);
    if (req.cpuLimit !== undefined && !CPU_RE.test(req.cpuLimit)) {
      throw new Error(`invalid CPU quantity: ${req.cpuLimit} (e.g. 500m, 1)`);
    }
    if (req.memLimit !== undefined && !MEM_RE.test(req.memLimit)) {
      throw new Error(`invalid memory quantity: ${req.memLimit} (e.g. 256Mi, 1Gi)`);
    }
  }
  return { deployment, containerIndex };
}

interface JsonPatchOp {
  op: "add" | "replace";
  path: string;
  value: unknown;
}

export async function patchDeployment(req: DeploymentPatchRequest): Promise<DeploymentInfo> {
  const { apps: api } = clients();
  const { containerIndex } = await validatePatch(req);

  const ops: JsonPatchOp[] = [];
  if (req.replicas !== undefined) {
    ops.push({ op: "replace", path: "/spec/replicas", value: req.replicas });
  }
  if (containerIndex >= 0) {
    const current = await api.readNamespacedDeployment({
      name: req.name,
      namespace: req.namespace,
    });
    const container = current.spec?.template.spec?.containers[containerIndex];
    if (!container) throw new Error("container disappeared during validation");
    const resources = {
      requests: { ...(container.resources?.requests ?? {}) },
      limits: { ...(container.resources?.limits ?? {}) },
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

  const patched = await api.patchNamespacedDeployment(
    { name: req.name, namespace: req.namespace, body: ops },
    setHeaderOptions("Content-Type", PatchStrategy.JsonPatch),
  );
  return toDeploymentInfo(patched);
}
