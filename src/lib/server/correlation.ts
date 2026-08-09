import "server-only";
import type { Anomaly, CorrelationResult, PodInfo, TimelineEntry } from "@/lib/types";
import type { AnomalyInput } from "./anomaly";
import { recentRestartEvents, listDeployHistory, listWafHistory } from "./db";

// Combine signals into suspected-cause correlations (spec §16).
// Wording stays "suspected" — never a confirmed root cause.
export function correlate(input: AnomalyInput, anomalies: Anomaly[]): CorrelationResult[] {
  const results: CorrelationResult[] = [];
  const has = (t: Anomaly["type"]): Anomaly | undefined =>
    anomalies.find((a) => a.type === t);

  const app = has("APPLICATION_FAILURE_SUSPECTED");
  const c5 = has("5XX_SPIKE");
  const lat = has("LATENCY_SPIKE");
  const db = has("DATABASE_PRESSURE_SUSPECTED");
  const res = has("RESOURCE_EXHAUSTION_SUSPECTED");
  const traffic = has("TRAFFIC_ANOMALY_SUSPECTED");
  const wafSpike = has("WAF_BLOCK_SPIKE");

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
  if (traffic && (wafSpike || has("4XX_SPIKE"))) {
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

// Merge CloudWatch spikes, K8s events, restarts, and change history into one
// chronological timeline (spec §15).
export function buildTimeline(input: AnomalyInput, anomalies: Anomaly[]): TimelineEntry[] {
  const entries: TimelineEntry[] = [];
  const tenMinAgo = Date.now() - 60 * 60_000;

  for (const ev of input.events.slice(0, 30)) {
    if (!ev.timestamp) continue;
    entries.push({
      ts: ev.timestamp,
      source: "K8s Event",
      severity: ev.highlighted ? "WARNING" : "NORMAL",
      text: `[${ev.kind}/${ev.name}] ${ev.reason}: ${ev.message.slice(0, 120)} (×${ev.count})`,
    });
  }
  try {
    for (const r of recentRestartEvents(tenMinAgo)) {
      entries.push({
        ts: new Date(r.ts).toISOString(),
        source: "Pod Restart",
        severity: "WARNING",
        text: `${r.pod} 재시작 +${r.delta}`,
      });
    }
    for (const d of listDeployHistory().slice(0, 10)) {
      entries.push({
        ts: new Date(d.ts).toISOString(),
        source: "Deployment 변경",
        severity: "NORMAL",
        text: `${d.namespace}/${d.name}: ${d.change} (검증: ${d.verdict})`,
      });
    }
    for (const w of listWafHistory().slice(0, 10)) {
      entries.push({
        ts: new Date(w.ts).toISOString(),
        source: "WAF 변경",
        severity: w.status === "FAILED" ? "WARNING" : "NORMAL",
        text: `${w.rule_name} ${w.action} → ${w.status}`,
      });
    }
  } catch {
    // history DB unavailable — timeline still renders from live signals
  }
  for (const a of anomalies) {
    entries.push({
      ts: a.detectedAt,
      source: "Anomaly",
      severity: a.severity,
      text: `[${a.type}] ${a.title}`,
    });
  }
  for (const p of input.pods) {
    if (p.statusLabel !== "Running" && p.statusLabel !== "NotReady") {
      entries.push({
        ts: new Date().toISOString(),
        source: "Pod 상태",
        severity: "WARNING",
        text: `${p.name}: ${p.statusLabel} (재시작 ${p.totalRestarts})`,
      });
    }
  }
  return entries.sort((a, b) => (a.ts < b.ts ? -1 : 1)).slice(-80);
}
