// Correlation and timeline (spec §15, §16). Wording stays "suspected" — never a
// confirmed root cause. History rows are passed in rather than read here, so
// this stays pure of SQLite.

import type {
  Anomaly,
  AnomalyType,
  DeployChangeEntry,
  Status,
} from "../../src/lib/types.ts";
import type { CorrelationResult, TimelineEntry } from "../types/types.ts";
import type { AnomalyInput } from "./anomaly.ts";

export interface RestartEvent {
  pod: string;
  ts: number;
  delta: number;
}

export interface WafHistoryRow {
  id: number;
  ts: number;
  ruleName: string;
  action: string;
  status: string;
  detail: string;
}

/**
 * The SQLite-backed rows the timeline folds in. Any of the arrays may be empty
 * when the history DB is unavailable — the timeline still renders from live
 * signals.
 */
export interface HistoryInput {
  restartEvents: RestartEvent[];
  deployHistory: DeployChangeEntry[];
  wafHistory: WafHistoryRow[];
}

function findAnomaly(anomalies: Anomaly[], type: AnomalyType): Anomaly | undefined {
  return anomalies.find((a) => a.type === type);
}

export function correlate(anomalies: Anomaly[]): CorrelationResult[] {
  const results: CorrelationResult[] = [];
  const app = findAnomaly(anomalies, "APPLICATION_FAILURE_SUSPECTED");
  const c5 = findAnomaly(anomalies, "5XX_SPIKE");
  const lat = findAnomaly(anomalies, "LATENCY_SPIKE");
  const db = findAnomaly(anomalies, "DATABASE_PRESSURE_SUSPECTED");
  const res = findAnomaly(anomalies, "RESOURCE_EXHAUSTION_SUSPECTED");
  const traffic = findAnomaly(anomalies, "TRAFFIC_ANOMALY_SUSPECTED");
  const wafSpike = findAnomaly(anomalies, "WAF_BLOCK_SPIKE");

  if (app && (c5 || lat)) {
    results.push({
      category: "APPLICATION_FAILURE_SUSPECTED",
      reason:
        "5XX/지연 증가와 Pod 이상(CrashLoopBackOff)·반복 예외 로그가 같은 시간대에 관측 — 애플리케이션 결함이 원인일 가능성",
      evidence: [...app.evidence, ...(c5?.evidence ?? []), ...(lat?.evidence ?? [])],
      confidence: app.confidence,
    });
  }
  if (db) {
    results.push({
      category: "DATABASE_PRESSURE_SUSPECTED",
      reason:
        "Pod는 정상인데 RDS 연결·지연·5XX가 동반 상승 — DB 병목(느린 쿼리, 인덱스 부재, 커넥션 고갈) 가능성",
      evidence: db.evidence,
      confidence: db.confidence,
    });
  }
  if (res) {
    results.push({
      category: "RESOURCE_EXHAUSTION_SUSPECTED",
      reason:
        "재시작 증가 + OOMKilled — Memory Limit이 워크로드 대비 부족할 가능성. Previous Logs에서 OOM 직전 상태 확인 권장",
      evidence: res.evidence,
      confidence: res.confidence,
    });
  }
  if (traffic && (wafSpike || findAnomaly(anomalies, "4XX_SPIKE"))) {
    results.push({
      category: "TRAFFIC_ANOMALY_SUSPECTED",
      reason:
        "특정 IP/경로/UA 집중과 4XX·WAF 차단 증가가 동반 — 자동화/공격성 트래픽 가능성. WAF 규칙 추천 검토",
      evidence: [...traffic.evidence, ...(wafSpike?.evidence ?? [])],
      confidence: traffic.confidence,
    });
  }
  return results;
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/**
 * Merges CloudWatch spikes, K8s events, restarts, and change history into one
 * chronological timeline.
 */
export function buildTimeline(
  input: AnomalyInput,
  anomalies: Anomaly[],
  history: HistoryInput,
  now: Date,
): TimelineEntry[] {
  const entries: TimelineEntry[] = [];

  for (const ev of input.events.slice(0, 30)) {
    if (ev.timestamp === "") continue;
    entries.push({
      ts: ev.timestamp,
      source: "K8s Event",
      severity: ev.highlighted ? "WARNING" : "NORMAL",
      text: `[${ev.kind}/${ev.name}] ${ev.reason}: ${ev.message.slice(0, 120)} (×${ev.count})`,
    });
  }
  for (const r of history.restartEvents) {
    entries.push({
      ts: iso(r.ts),
      source: "Pod Restart",
      severity: "WARNING",
      text: `${r.pod} 재시작 +${r.delta}`,
    });
  }
  for (const d of history.deployHistory.slice(0, 10)) {
    entries.push({
      ts: d.ts,
      source: "Deployment 변경",
      severity: "NORMAL",
      text: `${d.namespace}/${d.name}: ${d.change} (검증: ${d.verdict})`,
    });
  }
  for (const w of history.wafHistory.slice(0, 10)) {
    entries.push({
      ts: iso(w.ts),
      source: "WAF 변경",
      severity: w.status === "FAILED" ? "WARNING" : "NORMAL",
      text: `${w.ruleName} ${w.action} → ${w.status}`,
    });
  }
  for (const a of anomalies) {
    entries.push({
      ts: a.detectedAt,
      source: "Anomaly",
      severity: a.severity,
      text: `[${a.type}] ${a.title}`,
    });
  }

  const nowIso = now.toISOString();
  for (const p of input.pods) {
    if (p.statusLabel !== "Running" && p.statusLabel !== "NotReady") {
      entries.push({
        ts: nowIso,
        source: "Pod 상태",
        severity: "WARNING" as Status,
        text: `${p.name}: ${p.statusLabel} (재시작 ${p.totalRestarts})`,
      });
    }
  }

  // String comparison over ISO timestamps is chronological, and Array#sort is
  // stable, so same-instant entries keep their source order.
  entries.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
  return entries.length > 80 ? entries.slice(entries.length - 80) : entries;
}
