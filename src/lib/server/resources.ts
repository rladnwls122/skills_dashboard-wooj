import "server-only";
import { AutoscalingV2Api, CoreV1Api, KubeConfig, Metrics } from "@kubernetes/client-node";
import { discoverNodeGroupScaling } from "./aws";
import { ENV } from "./config";
import { errMsg } from "./cloudwatch";
import type {
  ContainerResourceUsage,
  DeploymentInfo,
  NodeResourceUsage,
  PodInfo,
  PodResourceUsage,
  PodStatusBreakdown,
  ScaleInfo,
} from "@/lib/types";

let kubeConfig: KubeConfig | null = null;

function kc(): KubeConfig {
  if (!kubeConfig) {
    kubeConfig = new KubeConfig();
    if (process.env.KUBERNETES_SERVICE_HOST) kubeConfig.loadFromCluster();
    else kubeConfig.loadFromDefault();
  }
  return kubeConfig;
}

// Kubernetes resource.Quantity parsers (metrics.k8s.io reports usage as
// Quantity strings — not necessarily the same suffix family as requests/limits).
export function parseCpuMilli(qty: string): number {
  const m = qty.match(/^(\d+(?:\.\d+)?)([nu]?m?)$/);
  if (!m) return 0;
  const value = Number(m[1]);
  const suffix = m[2];
  if (suffix === "n") return value / 1_000_000;
  if (suffix === "u") return value / 1_000;
  if (suffix === "m") return value;
  return value * 1000;
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
  const m = qty.match(/^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|Pi|Ei|K|M|G|T|P|E)?$/);
  if (!m) return 0;
  const value = Number(m[1]);
  const suffix = m[2];
  return suffix ? value * (MEM_UNITS[suffix] ?? 1) : value;
}

function pct(usage: number, limit: number | null): number | null {
  if (limit === null || limit <= 0) return null;
  return Math.round((usage / limit) * 1000) / 10;
}

export async function getPodResourceUsage(
  pods: PodInfo[],
): Promise<{ data: PodResourceUsage[]; error: string | null }> {
  try {
    const metrics = new Metrics(kc());
    const res = await metrics.getPodMetrics(ENV.targetNamespace);
    const podByName = new Map(pods.map((p) => [p.name, p]));
    const data: PodResourceUsage[] = res.items.map((pm) => {
      const podInfo = podByName.get(pm.metadata.name);
      const containers: ContainerResourceUsage[] = pm.containers.map((cm) => {
        const spec = podInfo?.containers.find((c) => c.name === cm.name);
        const cpuLimitMilli =
          spec?.cpuLimit && spec.cpuLimit !== "-" ? parseCpuMilli(spec.cpuLimit) : null;
        const memLimitBytes =
          spec?.memLimit && spec.memLimit !== "-" ? parseMemBytes(spec.memLimit) : null;
        const cpuUsageMilli = parseCpuMilli(cm.usage.cpu);
        const memUsageBytes = parseMemBytes(cm.usage.memory);
        return {
          container: cm.name,
          cpuUsage: cm.usage.cpu,
          cpuUsageMilli,
          memUsage: cm.usage.memory,
          memUsageBytes,
          cpuLimitMilli,
          memLimitBytes,
          cpuPct: pct(cpuUsageMilli, cpuLimitMilli),
          memPct: pct(memUsageBytes, memLimitBytes),
        };
      });
      const cpuUsageMilli = containers.reduce((a, c) => a + c.cpuUsageMilli, 0);
      const memUsageBytes = containers.reduce((a, c) => a + c.memUsageBytes, 0);
      const cpuLimitTotal = containers.every((c) => c.cpuLimitMilli !== null)
        ? containers.reduce((a, c) => a + (c.cpuLimitMilli ?? 0), 0)
        : null;
      const memLimitTotal = containers.every((c) => c.memLimitBytes !== null)
        ? containers.reduce((a, c) => a + (c.memLimitBytes ?? 0), 0)
        : null;
      return {
        pod: pm.metadata.name,
        containers,
        cpuUsageMilli,
        memUsageBytes,
        cpuPct: pct(cpuUsageMilli, cpuLimitTotal),
        memPct: pct(memUsageBytes, memLimitTotal),
      };
    });
    return { data, error: null };
  } catch (e) {
    return {
      data: [],
      error: `${errMsg(e)} (metrics-server addon 필요)`,
    };
  }
}

export async function getNodeResourceUsage(): Promise<{
  data: NodeResourceUsage[];
  error: string | null;
}> {
  try {
    const metrics = new Metrics(kc());
    const [metricsRes, nodesRes] = await Promise.all([
      metrics.getNodeMetrics(),
      kc().makeApiClient(CoreV1Api).listNode(),
    ]);
    const capacityByName = new Map(
      nodesRes.items.map((n) => [
        n.metadata?.name ?? "",
        {
          cpuMilli: parseCpuMilli(n.status?.allocatable?.["cpu"] ?? "0"),
          memBytes: parseMemBytes(n.status?.allocatable?.["memory"] ?? "0"),
        },
      ]),
    );
    const data: NodeResourceUsage[] = metricsRes.items.map((nm) => {
      const cap = capacityByName.get(nm.metadata.name) ?? { cpuMilli: 0, memBytes: 0 };
      const cpuUsageMilli = parseCpuMilli(nm.usage.cpu);
      const memUsageBytes = parseMemBytes(nm.usage.memory);
      return {
        name: nm.metadata.name,
        cpuUsageMilli,
        memUsageBytes,
        cpuCapacityMilli: cap.cpuMilli,
        memCapacityBytes: cap.memBytes,
        cpuPct: cap.cpuMilli > 0 ? Math.round((cpuUsageMilli / cap.cpuMilli) * 1000) / 10 : 0,
        memPct: cap.memBytes > 0 ? Math.round((memUsageBytes / cap.memBytes) * 1000) / 10 : 0,
      };
    });
    return { data, error: null };
  } catch (e) {
    return { data: [], error: `${errMsg(e)} (metrics-server addon 필요)` };
  }
}

export async function getPodScaling(deployments: DeploymentInfo[]): Promise<ScaleInfo[]> {
  const api = kc().makeApiClient(AutoscalingV2Api);
  let hpas: { target: string; min: number; max: number; current: number }[] = [];
  try {
    const res = await api.listNamespacedHorizontalPodAutoscaler({
      namespace: ENV.targetNamespace,
    });
    hpas = res.items
      .filter((h) => h.spec !== undefined)
      .map((h) => ({
        target: h.spec!.scaleTargetRef.name,
        min: h.spec!.minReplicas ?? 1,
        max: h.spec!.maxReplicas,
        current: h.status?.currentReplicas ?? h.status?.desiredReplicas ?? 0,
      }));
  } catch {
    hpas = [];
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

export async function getNodeScaling(currentNodeCount: number): Promise<ScaleInfo[]> {
  try {
    const groups = await discoverNodeGroupScaling();
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
  } catch (e) {
    return [
      {
        name: "cluster",
        current: currentNodeCount,
        min: null,
        max: null,
        source: `조회 실패: ${errMsg(e)}`,
      },
    ];
  }
}

export function summarizePodStatus(pods: PodInfo[]): PodStatusBreakdown {
  let running = 0;
  let pending = 0;
  let crashLoop = 0;
  let oom = 0;
  let failed = 0;
  let other = 0;
  for (const p of pods) {
    if (p.statusLabel === "CrashLoopBackOff") crashLoop += 1;
    else if (p.statusLabel === "OOMKilled") oom += 1;
    else if (p.statusLabel === "Running") running += 1;
    else if (["Pending", "ContainerCreating", "PodInitializing"].includes(p.statusLabel))
      pending += 1;
    else if (p.phase === "Failed") failed += 1;
    else other += 1;
  }
  return { running, pending, crashLoop, oom, failed, other, total: pods.length };
}
