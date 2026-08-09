import "server-only";
import type {
  Anomaly,
  CorrelationResult,
  FingerprintEntry,
  HttpSummary,
  KubePanel,
  MetricSummary,
  TimelineEntry,
  VerificationResult,
} from "@/lib/types";
import { maskText } from "./mask";
import { listDeployHistory, listWafHistory, saveIncidentSnapshot } from "./db";

export interface IncidentSnapshot {
  timestamp: string;
  metrics: MetricSummary[];
  httpSummary: HttpSummary | null;
  kube: KubePanel | null;
  anomalies: Anomaly[];
  correlations: CorrelationResult[];
  timeline: TimelineEntry[];
  fingerprints: FingerprintEntry[];
  logs: { pod: string; container: string; previous: boolean; lines: string[] } | null;
  previousLogs: { pod: string; container: string; lines: string[] } | null;
  wafHistory: { ts: string; ruleName: string; action: string; status: string; detail: string }[];
  deployHistory: { ts: string; target: string; change: string; verdict: string }[];
  verifications: VerificationResult[];
}

export function buildSnapshot(parts: {
  metrics: MetricSummary[];
  httpSummary: HttpSummary | null;
  kube: KubePanel | null;
  anomalies: Anomaly[];
  correlations: CorrelationResult[];
  timeline: TimelineEntry[];
  fingerprints: FingerprintEntry[];
  logs: IncidentSnapshot["logs"];
  previousLogs: IncidentSnapshot["previousLogs"];
  verifications: VerificationResult[];
}): IncidentSnapshot {
  let wafHistory: IncidentSnapshot["wafHistory"] = [];
  let deployHistory: IncidentSnapshot["deployHistory"] = [];
  try {
    wafHistory = listWafHistory().map((h) => ({
      ts: new Date(h.ts).toISOString(),
      ruleName: h.rule_name,
      action: h.action,
      status: h.status,
      detail: h.detail,
    }));
    deployHistory = listDeployHistory().map((d) => ({
      ts: new Date(d.ts).toISOString(),
      target: `${d.namespace}/${d.name}`,
      change: d.change,
      verdict: d.verdict,
    }));
  } catch {
    // history unavailable — snapshot proceeds with live data only
  }
  const snapshot: IncidentSnapshot = {
    timestamp: new Date().toISOString(),
    ...parts,
    wafHistory,
    deployHistory,
  };
  try {
    saveIncidentSnapshot(JSON.stringify(snapshot));
  } catch {
    // persisting the snapshot is best-effort
  }
  return snapshot;
}

// Markdown incident context for Amazon Q / human operators (spec §18).
export function toMarkdown(s: IncidentSnapshot): string {
  const md: string[] = [];
  md.push(`# Incident Context`);
  md.push(`Generated: ${s.timestamp}`);
  md.push(
    `\n> 본 문서의 모든 원인 표현은 "의심/가능성"이며 확정 진단이 아님. 민감정보는 마스킹됨.`,
  );

  md.push(`\n## 1. CloudWatch Metrics (현재 vs 이전 구간)`);
  md.push(`| Metric | Previous | Current | Δ | %Change | Status |`);
  md.push(`|---|---|---|---|---|---|`);
  for (const m of s.metrics) {
    md.push(
      `| ${m.label} | ${m.previous} | ${m.current} | ${m.delta} | ${m.percentChange ?? "N/A"} | ${m.status} |`,
    );
  }

  if (s.httpSummary) {
    const h = s.httpSummary;
    md.push(`\n## 2. HTTP / WAF 요청 요약 (${h.source})`);
    if (h.statusDist) {
      md.push(
        `상태 분포(분당): 2xx=${h.statusDist.c2xx}, 3xx=${h.statusDist.c3xx}, 4xx=${h.statusDist.c4xx}, 5xx=${h.statusDist.c5xx}`,
      );
    }
    md.push(`\n### Top Paths`);
    for (const p of h.byPath.slice(0, 10)) {
      md.push(`- ${p.path} — ${p.count}건 (차단 ${p.blocked}${p.lowPriority ? ", 헬스체크 제외 대상" : ""})`);
    }
    md.push(`\n### Top IPs`);
    for (const i of h.byIp.slice(0, 5)) md.push(`- ${i.key} — ${i.count}건`);
    md.push(`\n### Top User-Agents`);
    for (const u of h.byUa.slice(0, 5)) md.push(`- ${maskText(u.key)} — ${u.count}건`);
  }

  if (s.kube) {
    md.push(`\n## 3. Kubernetes 상태`);
    md.push(`노드: ${s.kube.nodesReady}/${s.kube.nodesTotal} Ready`);
    md.push(`\n### Pods`);
    md.push(`| Pod | 상태 | Ready | 재시작 | 최근증가 | Node |`);
    md.push(`|---|---|---|---|---|---|`);
    for (const p of s.kube.pods) {
      md.push(
        `| ${p.name} | ${p.statusLabel} | ${p.ready} | ${p.totalRestarts} | +${p.recentRestartIncrease} | ${p.nodeName} |`,
      );
    }
    md.push(`\n### Warning Events (최신순)`);
    for (const e of s.kube.events.slice(0, 15)) {
      md.push(`- ${e.timestamp} [${e.kind}/${e.name}] ${e.reason}: ${maskText(e.message)} (×${e.count})`);
    }
  }

  if (s.fingerprints.length > 0) {
    md.push(`\n## 4. Top Errors / Fingerprints`);
    for (const f of s.fingerprints.slice(0, 10)) {
      md.push(`- ×${f.count} [${f.pods.join(", ")}] ${maskText(f.fingerprint)}`);
    }
  }

  if (s.logs) {
    md.push(`\n## 5. Pod Logs (${s.logs.pod}/${s.logs.container}${s.logs.previous ? ", previous" : ""})`);
    md.push("```");
    md.push(...s.logs.lines.slice(-60));
    md.push("```");
  }
  if (s.previousLogs) {
    md.push(`\n## 6. Previous Logs (${s.previousLogs.pod}/${s.previousLogs.container})`);
    md.push("```");
    md.push(...s.previousLogs.lines.slice(-60));
    md.push("```");
  }

  md.push(`\n## 7. Detected Anomalies`);
  if (s.anomalies.length === 0) md.push(`- 없음`);
  for (const a of s.anomalies) {
    md.push(`- [${a.severity}][${a.type}] ${a.title} (confidence: ${a.confidence})`);
    md.push(`  - ${a.detail}`);
    for (const ev of a.evidence) md.push(`  - 근거: ${maskText(ev)}`);
  }

  md.push(`\n## 8. Correlation (추정 원인 — 확정 아님)`);
  if (s.correlations.length === 0) md.push(`- 상관관계 결과 없음`);
  for (const c of s.correlations) {
    md.push(`- [${c.category}] ${c.reason} (confidence: ${c.confidence})`);
    for (const ev of c.evidence) md.push(`  - ${maskText(ev)}`);
  }

  md.push(`\n## 9. Timeline`);
  for (const t of s.timeline.slice(-40)) {
    md.push(`- ${t.ts} [${t.source}] ${maskText(t.text)}`);
  }

  md.push(`\n## 10. Actions Taken`);
  md.push(`### Deployment 변경`);
  if (s.deployHistory.length === 0) md.push(`- 없음`);
  for (const d of s.deployHistory) md.push(`- ${d.ts} ${d.target}: ${d.change} → 검증 ${d.verdict}`);
  md.push(`### WAF 적용/롤백 이력`);
  if (s.wafHistory.length === 0) md.push(`- 없음`);
  for (const w of s.wafHistory) md.push(`- ${w.ts} ${w.ruleName} ${w.action} → ${w.status} (${w.detail})`);

  md.push(`\n## 11. Post-action Verification`);
  if (s.verifications.length === 0) md.push(`- 검증 결과 없음`);
  for (const v of s.verifications) {
    md.push(`- #${v.actionId} → ${v.verdict} (${v.checkedAt})`);
    for (const d of v.details) md.push(`  - ${d}`);
  }

  return maskText(md.join("\n"));
}

export function toJson(s: IncidentSnapshot): string {
  return maskText(JSON.stringify(s, null, 2));
}
