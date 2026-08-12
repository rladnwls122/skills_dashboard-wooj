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
import {
  MAX_Q_PROMPT_CHARS,
  contractLines,
  evaluateContract,
  packToLimit,
  pathScopeLabel,
  responseGuidance,
  type QSection,
} from "./gateway";

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
    // Drop the source-IP ranking at the single choke point every incident
    // output flows through (markdown, JSON, stored snapshot): volume from one
    // IP is the scenario's own load generator, and this feeds the Amazon Q
    // handoff.
    httpSummary: parts.httpSummary ? { ...parts.httpSummary, byIp: [] } : null,
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

  // The interpretation key goes first: without it a reader treats the 4XX/403
  // volume this environment produces by design as an outage.
  md.push(`\n## 0. 게이트웨이 기대 동작 (판정 기준)`);
  md.push(...contractLines());

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
    // Source-IP ranking is deliberately omitted: request volume from a single
    // IP is the scenario's own load generator, not a finding, and this report
    // is pasted into the Amazon Q handoff.
    md.push(`\n### Top User-Agents`);
    for (const u of h.byUa.slice(0, 5)) md.push(`- ${maskText(u.key)} — ${u.count}건`);

    const check = evaluateContract(h);
    md.push(`\n### 기대 동작 대비 편차 (§0 기준)`);
    if (check.deviations.length === 0) md.push(`- 계약 위반 관측 없음`);
    for (const d of check.deviations) md.push(`- [편차] ${d}`);
    for (const c of check.conforming) md.push(`- [정상] ${c}`);
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

// ---------------------------------------------------------------------------
// Amazon Q prompt
// ---------------------------------------------------------------------------
// A different artifact from the full markdown, not a shortened copy of it. Q's
// prompt box holds 10,000 characters, so everything that does not change the
// analysis is left out — raw pod log tails, the full timeline, and the rule
// JSON bodies (which alone run past the budget). What stays is grouped into
// labelled categories so each block can be read, or dropped, on its own.
// Top paths and top user-agents are the two lists an analyst opens first, so
// they are labelled and ranked rather than left as loose bullets. Each path
// carries its [A] side: a status code means nothing until you know whether the
// path is one the gateway serves. Counts are stated as shown/total so a reader
// can tell a short tail from a truncated list.
const TOP_PATHS = 10;
const TOP_UAS = 8;

function topPathLines(h: HttpSummary): string[] {
  if (h.byPath.length === 0) return [];
  return [
    `- Top 경로 ${Math.min(TOP_PATHS, h.byPath.length)}/${h.byPath.length} (요청순, [지정]/[미지정]은 [A] 기준):`,
    ...h.byPath
      .slice(0, TOP_PATHS)
      .map(
        (p, i) =>
          `  ${i + 1}. [${pathScopeLabel(p.path)}] ${p.path} — ${p.count}건 (차단 ${p.blocked}${p.lowPriority ? ", 헬스체크 제외 대상" : ""})`,
      ),
  ];
}

function topUaLines(h: HttpSummary): string[] {
  if (h.byUa.length === 0) return [];
  return [
    `- Top User-Agent ${Math.min(TOP_UAS, h.byUa.length)}/${h.byUa.length} (요청순):`,
    ...h.byUa.slice(0, TOP_UAS).map((u, i) => `  ${i + 1}. ${maskText(u.key)} — ${u.count}건`),
  ];
}

export function toQPrompt(s: IncidentSnapshot): string {
  const m = (t: string): string => maskText(t);
  const header = [
    `# WAF/게이트웨이 인시던트 분석 요청`,
    `수집 시각: ${s.timestamp}`,
    ``,
    `[A] 판정 기준 — 게이트웨이 기대 동작`,
    ...contractLines(),
    ``,
    `[B] 요청 사항`,
    `1. [C]의 이상 징후 중 [A] 계약으로 설명되는 것과 실제 문제를 구분할 것.`,
    `2. 실제 문제에 대해 근본 원인 가설을 근거와 함께 제시할 것 (확정 진단 금지).`,
    `3. [G]의 규칙 후보를 검토하고, 필요하면 응답 코드(403/404)까지 지정해 보완할 것.`,
    `4. 4XX/403/404 증가 자체를 장애로 판정하지 말 것 — [A]에서 정상 동작임.`,
    `5. [F]의 Top 경로·Top User-Agent에서 스캐너/정찰 패턴을 식별하고, [미지정] 경로에 몰린 요청은 [A]의 404 정책으로 설명할 것.`,
  ];

  const sections: QSection[] = [];

  const contract = s.httpSummary ? evaluateContract(s.httpSummary) : { conforming: [], deviations: [] };
  sections.push({
    title: `[C] 이상 징후 (심각도순)`,
    lines:
      s.anomalies.length === 0
        ? [`- 탐지된 이상 징후 없음`]
        : s.anomalies.map(
            (a) =>
              `- [${a.severity}/${a.type}] ${m(a.title)}: ${m(a.detail)} (confidence ${a.confidence}) | 근거 ${a.evidence
                .slice(0, 2)
                .map((e) => m(e))
                .join("; ")}`,
          ),
  });

  sections.push({
    title: `[D] 기대 동작 대비 편차 ([A] 기준)`,
    lines: [
      ...(contract.deviations.length === 0
        ? [`- 계약 위반 관측 없음`]
        : contract.deviations.map((d) => `- [편차] ${m(d)}`)),
      ...contract.conforming.map((c) => `- [정상] ${m(c)}`),
    ],
  });

  sections.push({
    title: `[E] 근거 — 메트릭 (이전 → 현재)`,
    lines: s.metrics
      .filter((x) => x.status !== "NORMAL")
      .map((x) => `- ${x.label}: ${x.previous} → ${x.current} (${x.percentChange ?? "N/A"}%, ${x.status})`)
      .concat(
        s.metrics.every((x) => x.status === "NORMAL") ? [`- 임계치 초과 메트릭 없음`] : [],
      ),
  });

  const h = s.httpSummary;
  sections.push({
    title: `[F] 근거 — 트래픽`,
    lines: h
      ? [
          // Not "샘플 N건": with a WAF log group this is a full count, and the
          // source string already says which of the two it is.
          `- 출처: ${h.source} / ${h.totalSampled}건 / ${h.windowLabel}`,
          ...(h.statusDist
            ? [
                `- 상태 분포(분당): 2xx=${h.statusDist.c2xx} 3xx=${h.statusDist.c3xx} 4xx=${h.statusDist.c4xx} 5xx=${h.statusDist.c5xx}`,
              ]
            : []),
          ...topPathLines(h),
          ...topUaLines(h),
        ]
      : [],
  });

  sections.push({
    title: `[H] 근거 — 애플리케이션/쿠버네티스`,
    lines: [
      ...(s.kube
        ? [
            `- 노드 ${s.kube.nodesReady}/${s.kube.nodesTotal} Ready`,
            ...s.kube.pods
              .filter((p) => p.statusLabel !== "Running" || p.recentRestartIncrease > 0)
              .slice(0, 6)
              .map(
                (p) =>
                  `- Pod ${p.name}: ${p.statusLabel}, ready ${p.ready}, 재시작 ${p.totalRestarts} (+${p.recentRestartIncrease})`,
              ),
          ]
        : []),
      ...s.fingerprints.slice(0, 5).map((f) => `- 반복 오류 ×${f.count}: ${m(f.fingerprint).slice(0, 120)}`),
    ],
  });

  sections.push({
    title: `[I] 조치 및 검증 이력`,
    lines: [
      ...s.deployHistory.slice(-5).map((d) => `- ${d.ts} ${d.target}: ${m(d.change)} → ${d.verdict}`),
      ...s.wafHistory.slice(-5).map((w) => `- ${w.ts} ${w.ruleName} ${w.action} → ${w.status}`),
      ...s.verifications.slice(-5).map((v) => `- 검증 #${v.actionId} → ${v.verdict} (${v.checkedAt})`),
    ],
  });

  sections.push({
    title: `[J] 상관관계 (추정, 확정 아님)`,
    lines: s.correlations.map((c) => `- [${c.category}] ${m(c.reason)} (confidence ${c.confidence})`),
  });

  return packToLimit(header, sections, MAX_Q_PROMPT_CHARS);
}
