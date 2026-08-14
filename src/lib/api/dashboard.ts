// The dashboard's data client.
//
// Every function here has the name and the signature of the server action it
// replaces, and returns the same ActionResult — so a screen switches backends by
// changing one import line and nothing else. The work now happens in the Go
// service (backend/), which owns the SQLite file, the settings overrides and the
// AWS/Kubernetes reads.
//
// A transport failure is an ActionResult too. The UI already renders
// `{ ok: false, error }` on every screen; making a dead backend throw instead
// would mean a blank panel with the reason only in the console.

import type {
  ActionResult,
  ApplyHistoryEntry,
  AssembledRule,
  AssembleKind,
  DeployChangeEntry,
  DeploymentInfo,
  DiscoverKind,
  DiscoveryResult,
  GradingPanel,
  IncidentContextResult,
  KubePanel,
  MetricsPanel,
  PodLogsResult,
  ProbeResult,
  RequestLogQueryResult,
  ResourceHistory,
  RuleTestResult,
  SettingsView,
  TestRequest,
  VerificationResult,
  WafPanel,
  WafSampleRow,
  WindowSelection,
} from "@/lib/types";

// Kept here rather than imported from src/lib/server/*: those modules are
// server-only, and these two shapes are part of the request contract, not of
// the AWS client code.
export type StatusClass = "ALL" | "2xx" | "3xx" | "4xx" | "5xx";

export interface DeploymentPatchRequest {
  namespace: string;
  name: string;
  replicas?: number;
  containerName?: string;
  cpuLimit?: string;
  memLimit?: string;
}

// Loopback by default: the service holds AWS credentials and binds 127.0.0.1
// unless told otherwise.
const BASE = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8787").replace(/\/+$/, "");

async function call<T>(path: string, body?: unknown): Promise<ActionResult<T>> {
  try {
    const res = await fetch(`${BASE}/api${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
      cache: "no-store",
    });
    if (!res.ok) {
      return { ok: false, error: `백엔드 응답 오류 ${res.status} (${path})` };
    }
    return (await res.json()) as ActionResult<T>;
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    return { ok: false, error: `백엔드에 연결할 수 없습니다 (${BASE}): ${detail}` };
  }
}

// --- panels ------------------------------------------------------------------

export function getKubePanelAction(): Promise<ActionResult<KubePanel>> {
  return call<KubePanel>("/kube-panel");
}

export function getMetricsPanelAction(sel?: WindowSelection): Promise<ActionResult<MetricsPanel>> {
  return call<MetricsPanel>("/metrics-panel", { window: sel ?? null });
}

export function getWafPanelAction(sel?: WindowSelection): Promise<ActionResult<WafPanel>> {
  return call<WafPanel>("/waf-panel", { window: sel ?? null });
}

export function getGradingPanelAction(sel?: WindowSelection): Promise<ActionResult<GradingPanel>> {
  return call<GradingPanel>("/grading-panel", { window: sel ?? null });
}

export function getResourceHistoryAction(
  sel?: WindowSelection,
): Promise<ActionResult<ResourceHistory>> {
  return call<ResourceHistory>("/resource-history", { window: sel ?? null });
}

export function getWafHistoryAction(): Promise<ActionResult<ApplyHistoryEntry[]>> {
  return call<ApplyHistoryEntry[]>("/waf-history");
}

export function getWafSamplesAction(): Promise<ActionResult<WafSampleRow[]>> {
  return call<WafSampleRow[]>("/waf-samples");
}

// --- logs --------------------------------------------------------------------

export function getPodLogsAction(params: {
  pod: string;
  container: string;
  previous: boolean;
  tailLines: number;
  window?: WindowSelection;
}): Promise<ActionResult<PodLogsResult>> {
  return call<PodLogsResult>("/pod-logs", { ...params, window: params.window ?? null });
}

export function getRequestLogRowsAction(params: {
  statusClass: StatusClass;
  pathContains: string;
  window?: WindowSelection;
}): Promise<ActionResult<RequestLogQueryResult>> {
  return call<RequestLogQueryResult>("/request-log-rows", {
    ...params,
    window: params.window ?? null,
  });
}

// --- settings ----------------------------------------------------------------

export function getSettingsAction(): Promise<ActionResult<SettingsView>> {
  return call<SettingsView>("/settings");
}

export function saveSettingsAction(
  patch: Record<string, string>,
): Promise<ActionResult<SettingsView>> {
  return call<SettingsView>("/settings/save", patch);
}

export function discoverAction(kind: DiscoverKind): Promise<ActionResult<DiscoveryResult>> {
  return call<DiscoveryResult>("/discover", { kind });
}

// --- deployments -------------------------------------------------------------

export function getDeploymentAction(params: {
  namespace: string;
  name: string;
}): Promise<ActionResult<DeploymentInfo>> {
  return call<DeploymentInfo>("/deployment", params);
}

export function previewPatchAction(
  req: DeploymentPatchRequest,
): Promise<ActionResult<{ current: DeploymentInfo }>> {
  return call<{ current: DeploymentInfo }>("/deployment/preview", req);
}

export function patchDeploymentAction(
  req: DeploymentPatchRequest,
): Promise<ActionResult<{ historyId: number; after: DeploymentInfo }>> {
  return call<{ historyId: number; after: DeploymentInfo }>("/deployment/patch", req);
}

export function listDeployHistoryAction(): Promise<ActionResult<DeployChangeEntry[]>> {
  return call<DeployChangeEntry[]>("/deploy-history");
}

export function verifyActionAction(historyId: number): Promise<ActionResult<VerificationResult>> {
  return call<VerificationResult>("/verify", { historyId });
}

// --- incident + sandbox ------------------------------------------------------

export function generateIncidentContextAction(): Promise<ActionResult<IncidentContextResult>> {
  return call<IncidentContextResult>("/incident-context");
}

export function getDefaultTestRequestsAction(): Promise<ActionResult<TestRequest[]>> {
  return call<TestRequest[]>("/test-requests/default");
}

export function getMaliciousExampleRequestsAction(): Promise<ActionResult<TestRequest[]>> {
  return call<TestRequest[]>("/test-requests/malicious");
}

export function assembleRuleAction(
  kind: AssembleKind,
  sel?: WindowSelection,
): Promise<ActionResult<AssembledRule>> {
  return call<AssembledRule>("/assemble-rule", { kind, window: sel ?? null });
}

export function probeUrlAction(
  url: string,
  expectStatus: number | null,
): Promise<ActionResult<ProbeResult>> {
  return call<ProbeResult>("/probe", { url, expectStatus });
}

export function testRuleJsonAction(params: {
  ruleJson: string;
  requests: TestRequest[];
}): Promise<ActionResult<RuleTestResult>> {
  return call<RuleTestResult>("/test-rule", params);
}
