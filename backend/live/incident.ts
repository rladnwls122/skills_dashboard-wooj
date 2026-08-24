// Incident context generation (spec §17, §18): fetch the two panels (cached),
// peek the cross-panel caches, fold in SQLite history, render.

import {
  buildSnapshot,
  toJson,
  toMarkdown,
  toQPrompt,
  type DeployHistoryEntry,
  type IncidentParts,
  type LogsRef,
  type WafHistoryEntry,
} from "../analysis/incident.ts";
import { peek } from "../cache/cache.ts";
import { resolveWindow } from "../service/window.ts";
import type {
  FingerprintEntry,
  IncidentContextResult,
  KubePanel,
  VerificationResult,
} from "../../src/lib/types.ts";
import type { MetricsPanelFull } from "../types/types.ts";
import type { LiveProvider } from "./live.ts";

export async function incidentContext(p: LiveProvider): Promise<IncidentContextResult> {
  const nowMs = p.now();
  const win = resolveWindow(null, nowMs);

  let metrics: MetricsPanelFull | null = null;
  try {
    metrics = await p.metricsPanel(win);
  } catch {
    // A snapshot with no metrics is still worth producing.
  }
  let kubePanel: KubePanel | null = null;
  try {
    kubePanel = await p.kubePanel();
  } catch {
    // ditto
  }

  const parts: IncidentParts = {
    metrics: metrics?.metrics ?? [],
    httpSummary: metrics?.httpSummary ?? null,
    kube: kubePanel,
    anomalies: metrics?.anomalies ?? [],
    correlations: metrics?.correlations ?? [],
    timeline: metrics?.timeline ?? [],
    fingerprints: peek<FingerprintEntry[]>("panel:fingerprints") ?? [],
    logs: peek<LogsRef>("panel:lastlogs") ?? null,
    previousLogs: peek<LogsRef>("panel:lastprevlogs") ?? null,
    wafHistory: [],
    deployHistory: [],
    verifications: peek<VerificationResult[]>("panel:verifications") ?? [],
  };

  // History unavailable — the snapshot proceeds with live data only.
  try {
    parts.wafHistory = p.store.listWafHistoryRows().map(
      (h): WafHistoryEntry => ({
        ts: new Date(h.ts).toISOString(),
        ruleName: h.ruleName,
        action: h.action,
        status: h.status,
        detail: h.detail,
      }),
    );
  } catch {
    // ignored
  }
  try {
    parts.deployHistory = p.store.listDeployHistory().map(
      (d): DeployHistoryEntry => ({
        ts: new Date(d.ts).toISOString(),
        target: `${d.namespace}/${d.name}`,
        change: d.change,
        verdict: d.verdict,
      }),
    );
  } catch {
    // ignored
  }

  const snapshot = buildSnapshot(parts, new Date(nowMs));
  const json = toJson(snapshot);
  // Persisting the snapshot is best-effort.
  try {
    p.store.saveIncidentSnapshot(json, nowMs);
  } catch {
    // ignored
  }

  return {
    markdown: toMarkdown(snapshot),
    json,
    qPrompt: toQPrompt(snapshot),
    generatedAt: snapshot.timestamp,
  };
}
