// Incident context for Amazon Q / human operators (spec §17, §18). History rows
// come in through IncidentParts so this file stays pure of SQLite; persisting
// the snapshot is the caller's business.

import type {
  Anomaly,
  FingerprintEntry,
  HttpSummary,
  KubePanel,
  MetricSummary,
  VerificationResult,
} from "../../src/lib/types.ts";
import type { CorrelationResult, TimelineEntry } from "../types/types.ts";
import {
  contractLines,
  evaluateContract,
  MAX_Q_PROMPT_CHARS,
  packToLimit,
  pathScopeLabel,
  type QSection,
} from "./gateway.ts";
import { maskText } from "./mask.ts";

export interface LogsRef {
  pod: string;
  container: string;
  previous: boolean;
  lines: string[];
}

export interface WafHistoryEntry {
  ts: string;
  ruleName: string;
  action: string;
  status: string;
  detail: string;
}

export interface DeployHistoryEntry {
  ts: string;
  target: string;
  change: string;
  verdict: string;
}

export interface IncidentSnapshot {
  timestamp: string;
  metrics: MetricSummary[];
  httpSummary: HttpSummary | null;
  kube: KubePanel | null;
  anomalies: Anomaly[];
  correlations: CorrelationResult[];
  timeline: TimelineEntry[];
  fingerprints: FingerprintEntry[];
  logs: LogsRef | null;
  previousLogs: LogsRef | null;
  wafHistory: WafHistoryEntry[];
  deployHistory: DeployHistoryEntry[];
  verifications: VerificationResult[];
}

export type IncidentParts = Omit<IncidentSnapshot, "timestamp">;

export function buildSnapshot(parts: IncidentParts, now: Date): IncidentSnapshot {
  const snapshot: IncidentSnapshot = { timestamp: now.toISOString(), ...parts };
  // Drop the source-IP ranking at the single choke point every incident output
  // flows through: volume from one IP is the scenario's own load generator, and
  // this feeds the Amazon Q handoff.
  if (snapshot.httpSummary) {
    snapshot.httpSummary = { ...snapshot.httpSummary, byIp: [] };
  }
  return snapshot;
}

function tail<T>(list: T[], n: number): T[] {
  return list.length > n ? list.slice(list.length - n) : list;
}

const pct = (m: MetricSummary): string => (m.percentChange === null ? "N/A" : String(m.percentChange));

/** Renders the full incident context. */
export function toMarkdown(s: IncidentSnapshot): string {
  const md: string[] = [];
  const push = (...lines: string[]): void => {
    md.push(...lines);
  };

  push("# Incident Context");
  push("Generated: " + s.timestamp);
  push('\n> 본 문서의 모든 원인 표현은 "의심/가능성"이며 확정 진단이 아님. 민감정보는 마스킹됨.');

  // The interpretation key goes first: without it a reader treats the 4XX/403
  // volume this environment produces by design as an outage.
  push("\n## 0. 게이트웨이 기대 동작 (판정 기준)");
  push(...contractLines());

  push("\n## 1. CloudWatch Metrics (현재 vs 이전 구간)");
  push("| Metric | Previous | Current | Δ | %Change | Status |");
  push("|---|---|---|---|---|---|");
  for (const m of s.metrics) {
    push(`| ${m.label} | ${m.previous} | ${m.current} | ${m.delta} | ${pct(m)} | ${m.status} |`);
  }

  const h = s.httpSummary;
  if (h) {
    push(`\n## 2. HTTP / WAF 요청 요약 (${h.source})`);
    if (h.statusDist) {
      const d = h.statusDist;
      push(`상태 분포(분당): 2xx=${d.c2xx}, 3xx=${d.c3xx}, 4xx=${d.c4xx}, 5xx=${d.c5xx}`);
    }
    push("\n### Top Paths");
    for (const p of h.byPath.slice(0, 10)) {
      push(
        `- ${p.path} — ${p.count}건 (차단 ${p.blocked}${p.lowPriority ? ", 헬스체크 제외 대상" : ""})`,
      );
    }
    // Source-IP ranking is deliberately omitted.
    push("\n### Top User-Agents");
    for (const u of h.byUa.slice(0, 5)) {
      push(`- ${maskText(u.key)} — ${u.count}건`);
    }

    const check = evaluateContract(h);
    push("\n### 기대 동작 대비 편차 (§0 기준)");
    if (check.deviations.length === 0) push("- 계약 위반 관측 없음");
    for (const d of check.deviations) push("- [편차] " + d);
    for (const c of check.conforming) push("- [정상] " + c);
  }

  const k = s.kube;
  if (k) {
    push("\n## 3. Kubernetes 상태");
    push(`노드: ${k.nodesReady}/${k.nodesTotal} Ready`);
    push("\n### Pods");
    push("| Pod | 상태 | Ready | 재시작 | 최근증가 | Node |");
    push("|---|---|---|---|---|---|");
    for (const p of k.pods) {
      push(
        `| ${p.name} | ${p.statusLabel} | ${p.ready} | ${p.totalRestarts} | +${p.recentRestartIncrease} | ${p.nodeName} |`,
      );
    }
    push("\n### Warning Events (최신순)");
    for (const e of k.events.slice(0, 15)) {
      push(
        `- ${e.timestamp} [${e.kind}/${e.name}] ${e.reason}: ${maskText(e.message)} (×${e.count})`,
      );
    }
  }

  if (s.fingerprints.length > 0) {
    push("\n## 4. Top Errors / Fingerprints");
    for (const f of s.fingerprints.slice(0, 10)) {
      push(`- ×${f.count} [${f.pods.join(", ")}] ${maskText(f.fingerprint)}`);
    }
  }

  if (s.logs) {
    const l = s.logs;
    push(`\n## 5. Pod Logs (${l.pod}/${l.container}${l.previous ? ", previous" : ""})`);
    push("```");
    push(...tail(l.lines, 60));
    push("```");
  }
  if (s.previousLogs) {
    const l = s.previousLogs;
    push(`\n## 6. Previous Logs (${l.pod}/${l.container})`);
    push("```");
    push(...tail(l.lines, 60));
    push("```");
  }

  push("\n## 7. Detected Anomalies");
  if (s.anomalies.length === 0) push("- 없음");
  for (const a of s.anomalies) {
    push(`- [${a.severity}][${a.type}] ${a.title} (confidence: ${a.confidence})`);
    push("  - " + a.detail);
    for (const ev of a.evidence) push("  - 근거: " + maskText(ev));
  }

  push("\n## 8. Correlation (추정 원인 — 확정 아님)");
  if (s.correlations.length === 0) push("- 상관관계 결과 없음");
  for (const c of s.correlations) {
    push(`- [${c.category}] ${c.reason} (confidence: ${c.confidence})`);
    for (const ev of c.evidence) push("  - " + maskText(ev));
  }

  push("\n## 9. Timeline");
  for (const t of tail(s.timeline, 40)) {
    push(`- ${t.ts} [${t.source}] ${maskText(t.text)}`);
  }

  push("\n## 10. Actions Taken");
  push("### Deployment 변경");
  if (s.deployHistory.length === 0) push("- 없음");
  for (const d of s.deployHistory) {
    push(`- ${d.ts} ${d.target}: ${d.change} → 검증 ${d.verdict}`);
  }
  push("### WAF 적용/롤백 이력");
  if (s.wafHistory.length === 0) push("- 없음");
  for (const w of s.wafHistory) {
    push(`- ${w.ts} ${w.ruleName} ${w.action} → ${w.status} (${w.detail})`);
  }

  push("\n## 11. Post-action Verification");
  if (s.verifications.length === 0) push("- 검증 결과 없음");
  for (const v of s.verifications) {
    push(`- #${v.actionId} → ${v.verdict} (${v.checkedAt})`);
    for (const d of v.details) push("  - " + d);
  }

  return maskText(md.join("\n"));
}

export function toJson(s: IncidentSnapshot): string {
  return maskText(JSON.stringify(s, null, 2));
}

// --- Amazon Q prompt ---------------------------------------------------------
// A different artifact from the full markdown, not a shortened copy of it: the
// prompt has a hard character budget, so the sections are prioritised and the
// overflow is named rather than silently dropped.

const TOP_PATHS = 10;
const TOP_UAS = 8;

function topPathLines(h: HttpSummary): string[] {
  if (h.byPath.length === 0) return [];
  const out = [
    `- Top 경로 ${Math.min(TOP_PATHS, h.byPath.length)}/${h.byPath.length} (요청순, [지정]/[미지정]은 [A] 기준):`,
  ];
  h.byPath.slice(0, TOP_PATHS).forEach((p, i) => {
    out.push(
      `  ${i + 1}. [${pathScopeLabel(p.path)}] ${p.path} — ${p.count}건 (차단 ${p.blocked}${p.lowPriority ? ", 헬스체크 제외 대상" : ""})`,
    );
  });
  return out;
}

function topUaLines(h: HttpSummary): string[] {
  if (h.byUa.length === 0) return [];
  const out = [`- Top User-Agent ${Math.min(TOP_UAS, h.byUa.length)}/${h.byUa.length} (요청순):`];
  h.byUa.slice(0, TOP_UAS).forEach((u, i) => {
    out.push(`  ${i + 1}. ${maskText(u.key)} — ${u.count}건`);
  });
  return out;
}

export function toQPrompt(s: IncidentSnapshot): string {
  const header = [
    "# WAF/게이트웨이 인시던트 분석 요청",
    "수집 시각: " + s.timestamp,
    "",
    "[A] 판정 기준 — 게이트웨이 기대 동작",
    ...contractLines(),
    "",
    "[B] 요청 사항",
    "1. [C]의 이상 징후 중 [A] 계약으로 설명되는 것과 실제 문제를 구분할 것.",
    "2. 실제 문제에 대해 근본 원인 가설을 근거와 함께 제시할 것 (확정 진단 금지).",
    "3. [G]의 규칙 후보를 검토하고, 필요하면 응답 코드(403/404)까지 지정해 보완할 것.",
    "4. 4XX/403/404 증가 자체를 장애로 판정하지 말 것 — [A]에서 정상 동작임.",
    "5. [F]의 Top 경로·Top User-Agent에서 스캐너/정찰 패턴을 식별하고, [미지정] 경로에 몰린 요청은 [A]의 404 정책으로 설명할 것.",
  ];

  const sections: QSection[] = [];

  const anomalyLines: string[] = [];
  if (s.anomalies.length === 0) anomalyLines.push("- 탐지된 이상 징후 없음");
  for (const a of s.anomalies) {
    const evidence = a.evidence.slice(0, 2).map(maskText).join("; ");
    anomalyLines.push(
      `- [${a.severity}/${a.type}] ${maskText(a.title)}: ${maskText(a.detail)} (confidence ${a.confidence}) | 근거 ${evidence}`,
    );
  }
  sections.push({ title: "[C] 이상 징후 (심각도순)", lines: anomalyLines });

  const contract = evaluateContract(s.httpSummary);
  const contractCheckLines: string[] = [];
  if (contract.deviations.length === 0) contractCheckLines.push("- 계약 위반 관측 없음");
  for (const d of contract.deviations) contractCheckLines.push("- [편차] " + maskText(d));
  for (const c of contract.conforming) contractCheckLines.push("- [정상] " + maskText(c));
  sections.push({ title: "[D] 기대 동작 대비 편차 ([A] 기준)", lines: contractCheckLines });

  const metricLines: string[] = [];
  for (const m of s.metrics) {
    if (m.status !== "NORMAL") {
      metricLines.push(
        `- ${m.label}: ${m.previous} → ${m.current} (${pct(m)}%, ${m.status})`,
      );
    }
  }
  if (metricLines.length === 0) metricLines.push("- 임계치 초과 메트릭 없음");
  sections.push({ title: "[E] 근거 — 메트릭 (이전 → 현재)", lines: metricLines });

  const trafficLines: string[] = [];
  if (s.httpSummary) {
    const h = s.httpSummary;
    trafficLines.push(`- 출처: ${h.source} / ${h.totalSampled}건 / ${h.windowLabel}`);
    if (h.statusDist) {
      const d = h.statusDist;
      trafficLines.push(`- 상태 분포(분당): 2xx=${d.c2xx} 3xx=${d.c3xx} 4xx=${d.c4xx} 5xx=${d.c5xx}`);
    }
    trafficLines.push(...topPathLines(h), ...topUaLines(h));
  }
  sections.push({ title: "[F] 근거 — 트래픽", lines: trafficLines });

  const kubeLines: string[] = [];
  if (s.kube) {
    kubeLines.push(`- 노드 ${s.kube.nodesReady}/${s.kube.nodesTotal} Ready`);
    let shown = 0;
    for (const p of s.kube.pods) {
      if (p.statusLabel === "Running" && p.recentRestartIncrease === 0) continue;
      if (shown >= 6) break;
      shown++;
      kubeLines.push(
        `- Pod ${p.name}: ${p.statusLabel}, ready ${p.ready}, 재시작 ${p.totalRestarts} (+${p.recentRestartIncrease})`,
      );
    }
  }
  for (const f of s.fingerprints.slice(0, 5)) {
    kubeLines.push(`- 반복 오류 ×${f.count}: ${maskText(f.fingerprint).slice(0, 120)}`);
  }
  sections.push({ title: "[H] 근거 — 애플리케이션/쿠버네티스", lines: kubeLines });

  const histLines: string[] = [];
  for (const d of tail(s.deployHistory, 5)) {
    histLines.push(`- ${d.ts} ${d.target}: ${maskText(d.change)} → ${d.verdict}`);
  }
  for (const w of tail(s.wafHistory, 5)) {
    histLines.push(`- ${w.ts} ${w.ruleName} ${w.action} → ${w.status}`);
  }
  for (const v of tail(s.verifications, 5)) {
    histLines.push(`- 검증 #${v.actionId} → ${v.verdict} (${v.checkedAt})`);
  }
  sections.push({ title: "[I] 조치 및 검증 이력", lines: histLines });

  const corrLines = s.correlations.map(
    (c) => `- [${c.category}] ${maskText(c.reason)} (confidence ${c.confidence})`,
  );
  sections.push({ title: "[J] 상관관계 (추정, 확정 아님)", lines: corrLines });

  return packToLimit(header, sections, MAX_Q_PROMPT_CHARS);
}
