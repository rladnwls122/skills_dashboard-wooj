// Anomaly detection. A single signal is never enough for CRITICAL (spec §8):
// severity escalates only when corroborating signals exist.

import { isBenignPath, isPathSuspicious } from "../config/paths.ts";
import {
  CATEGORY_RECON,
  CATEGORY_SCANNER,
  CATEGORY_UNKNOWN,
  classifyUa,
  queryHasBase64Blob,
  type ThreatHit,
} from "../rules/threatsig.ts";
import type {
  Anomaly,
  AnomalyType,
  Confidence,
  FingerprintEntry,
  HttpSummary,
  KeyCount,
  MetricSummary,
  PodInfo,
  Status,
  WarningEvent,
} from "../../src/lib/types.ts";

export interface AnomalyInput {
  metrics: MetricSummary[];
  httpSummary: HttpSummary | null;
  pods: PodInfo[];
  events: WarningEvent[];
  fingerprints: FingerprintEntry[];
}

function metricOf(input: AnomalyInput, key: string): MetricSummary | undefined {
  return input.metrics.find((m) => m.key === key);
}

function escalate(base: Status, corroborating: number): Status {
  if (base === "NORMAL") return "NORMAL";
  if (corroborating >= 1 && base === "CRITICAL") return "CRITICAL";
  return "WARNING";
}

function fmtPct(p: number | null): string {
  if (p === null) return "이전 구간 0 → 신규 발생";
  return `${p >= 0 ? "+" : ""}${p}%`;
}

const MOZILLA_RE = /mozilla/i;

export function detectAnomalies(input: AnomalyInput, now: Date): Anomaly[] {
  const anomalies: Anomaly[] = [];
  const nowIso = now.toISOString();
  const trt = metricOf(input, "targetResponseTime");
  const c4 = metricOf(input, "http4xx");
  const c5 = metricOf(input, "http5xx");
  const wafB = metricOf(input, "wafBlocked");
  const rds = metricOf(input, "rdsClientConnections");

  const badPods: PodInfo[] = [];
  const oomPods: PodInfo[] = [];
  const crashPods: PodInfo[] = [];
  for (const p of input.pods) {
    if (p.statusLabel !== "Running" || p.recentRestartIncrease > 0 || p.phase === "Failed") {
      badPods.push(p);
    }
    const oom = p.statusLabel === "OOMKilled" || p.containers.some((c) => c.reason === "OOMKilled");
    if (oom) oomPods.push(p);
    if (p.statusLabel === "CrashLoopBackOff") crashPods.push(p);
  }
  const repeatedErrors = input.fingerprints.filter((f) => f.count >= 5);

  const abnormal = (m: MetricSummary | undefined): m is MetricSummary =>
    m !== undefined && m.status !== "NORMAL";

  // Counted with `abnormal`, not with "not NORMAL": a metric CloudWatch never
  // returned is absent, not spiking. Treating absence as corroboration let two
  // missing metrics carry a lone 4XX alarm to CRITICAL, which is exactly the
  // "one signal is never enough" guard this count exists to enforce — a red
  // alarm assembled out of nothing is worse than no alarm.
  const spikeSignals = [
    abnormal(trt),
    abnormal(c4),
    abnormal(c5),
    abnormal(wafB),
    badPods.length > 0,
    repeatedErrors.length > 0,
  ].filter(Boolean).length;

  const push = (
    type: AnomalyType,
    base: Status,
    title: string,
    detail: string,
    evidence: string[],
    confidence: Confidence,
  ): void => {
    anomalies.push({
      id: `${type}-${anomalies.length}`,
      type,
      severity: escalate(base, spikeSignals - 1),
      title,
      detail,
      evidence,
      confidence,
      detectedAt: nowIso,
    });
  };

  if (abnormal(c4)) {
    push(
      "4XX_SPIKE",
      c4.status,
      "4XX 응답 급증",
      `4XX가 ${c4.previous} → ${c4.current} (${fmtPct(c4.percentChange)}) 변화. 정상 404/인증 실패 가능성도 있으므로 경로 분포 확인 필요.`,
      [`Target 4XX: ${c4.previous} → ${c4.current}/min`],
      c4.status === "CRITICAL" ? "HIGH" : "MEDIUM",
    );
  }
  if (abnormal(c5)) {
    push(
      "5XX_SPIKE",
      c5.status,
      "5XX 응답 급증",
      `5XX가 ${c5.previous} → ${c5.current} (${fmtPct(c5.percentChange)}) 변화 — 애플리케이션 또는 백엔드 장애 의심.`,
      [`Target 5XX: ${c5.previous} → ${c5.current}/min`],
      c5.status === "CRITICAL" ? "HIGH" : "MEDIUM",
    );
  }
  if (abnormal(trt)) {
    push(
      "LATENCY_SPIKE",
      trt.status,
      "응답 지연 급증",
      `TargetResponseTime ${trt.previous}s → ${trt.current}s (${fmtPct(trt.percentChange)}).`,
      [`TargetResponseTime: ${trt.previous}s → ${trt.current}s`],
      "MEDIUM",
    );
  }
  if (abnormal(wafB)) {
    push(
      "WAF_BLOCK_SPIKE",
      wafB.status,
      "WAF 차단 급증",
      `BlockedRequests ${wafB.previous} → ${wafB.current}/min — 공격 시도 증가 또는 오탐 증가 가능성 모두 검토 필요.`,
      [`WAF BlockedRequests: ${wafB.previous} → ${wafB.current}/min`],
      "MEDIUM",
    );
  }

  const h = input.httpSummary;
  if (h) {
    const total = h.totalSampled < 1 ? 1 : h.totalSampled;

    // Request volume is never an anomaly in this environment — only traffic
    // aimed outside the served surface (probing, scanning) counts.
    const offSurface = h.byPath.filter((p) => !p.lowPriority && !isBenignPath(p.path));
    const offSurfaceCount = offSurface.reduce((acc, p) => acc + p.count, 0);

    const concentrated: string[] = [];
    const top = offSurface[0];
    if (top && isPathSuspicious(top.path, top.count, total)) {
      concentrated.push(`경로 ${top.path}: 샘플 ${top.count}/${total}건 (서비스 경로 외)`);
    }
    const topUa = h.byUa[0];
    if (
      topUa &&
      offSurfaceCount >= 20 &&
      topUa.count / total >= 0.4 &&
      !MOZILLA_RE.test(topUa.key)
    ) {
      concentrated.push(`UA "${topUa.key}": ${topUa.count}/${total}건`);
    }
    if (concentrated.length > 0) {
      const strong = concentrated.length >= 2;
      push(
        "TRAFFIC_ANOMALY_SUSPECTED",
        strong ? "CRITICAL" : "WARNING",
        "비정상 트래픽 집중 의심",
        "서비스 경로(/v1/*) 외 요청이 집중 — 스캔 또는 탐색 시도 가능성. WAF 탭에서 규칙 추천 확인.",
        concentrated,
        strong ? "HIGH" : "MEDIUM",
      );
    }

    // Malicious-client signatures in the sampled UA/query mix. UNKNOWN is
    // excluded on purpose — a positive signature is required to alarm.
    const flaggedUa: { hit: ThreatHit; key: string; count: number }[] = [];
    for (const u of h.byUa) {
      const hit = classifyUa(u.key);
      if (hit && hit.category !== CATEGORY_UNKNOWN) {
        flaggedUa.push({ hit, key: u.key, count: u.count });
      }
    }
    const b64Query: KeyCount[] = h.queryPatterns.filter((q) => queryHasBase64Blob(q.key));

    if (flaggedUa.length > 0 || b64Query.length > 0) {
      const evidence: string[] = [];
      for (const f of flaggedUa.slice(0, 5)) {
        evidence.push(`악성 클라이언트 UA "${f.key}" (${f.hit.category}/${f.hit.label}): ${f.count}건`);
      }
      for (const q of b64Query.slice(0, 3)) {
        evidence.push(`base64 난독화 쿼리 의심: "${q.key.slice(0, 60)}"`);
      }
      // Only a named offensive tool is CRITICAL on its own.
      const hasScanner = flaggedUa.some(
        (f) => f.hit.category === CATEGORY_SCANNER || f.hit.category === CATEGORY_RECON,
      );
      const base: Status = hasScanner ? "CRITICAL" : "WARNING";
      push(
        "MALICIOUS_CLIENT_SUSPECTED",
        base,
        "악성 클라이언트 시그니처 탐지",
        "샘플 트래픽에서 스캐너·정찰 툴 또는 위조/난독 시그니처가 관측됨",
        evidence,
        "HIGH",
      );
      // A named scanner/recon tool is an unambiguous signature on its own — its
      // severity must not be downgraded by escalate() just because no other
      // metric is spiking.
      anomalies[anomalies.length - 1]!.severity = base;
    }
  }

  if (crashPods.length > 0 || (abnormal(c5) && repeatedErrors.length > 0)) {
    const base: Status = crashPods.length > 0 && abnormal(c5) ? "CRITICAL" : "WARNING";
    const conf: Confidence = crashPods.length > 0 ? "HIGH" : "MEDIUM";
    const evidence: string[] = [];
    for (const p of crashPods) {
      evidence.push(`Pod ${p.name}: CrashLoopBackOff (재시작 ${p.totalRestarts})`);
    }
    for (const f of repeatedErrors.slice(0, 3)) {
      evidence.push(`반복 오류 ×${f.count}: ${f.fingerprint.slice(0, 80)}`);
    }
    push(
      "APPLICATION_FAILURE_SUSPECTED",
      base,
      "애플리케이션 장애 의심",
      "CrashLoopBackOff 또는 반복 예외 로그와 5XX가 동반 — 애플리케이션 결함 가능성 (확정 아님, 로그 확인 필요).",
      evidence,
      conf,
    );
  }

  if (abnormal(rds) && abnormal(trt) && badPods.length === 0) {
    push(
      "DATABASE_PRESSURE_SUSPECTED",
      abnormal(c5) ? "CRITICAL" : "WARNING",
      "데이터베이스 부하 의심",
      "RDS 연결 증가 + 지연 증가 + Pod 정상 조합 — DB 측 병목 가능성 (쿼리/인덱스/커넥션 풀 점검 필요).",
      [
        `RDS Proxy Client Conn: ${rds.previous} → ${rds.current}`,
        `TargetResponseTime: ${trt.previous}s → ${trt.current}s`,
        "이상 Pod 없음",
      ],
      "MEDIUM",
    );
  }

  if (oomPods.length > 0) {
    const base: Status = oomPods.some((p) => p.recentRestartIncrease > 0) ? "CRITICAL" : "WARNING";
    const evidence = oomPods.map(
      (p) =>
        `Pod ${p.name}: OOMKilled, limit=${p.containers[0]?.memLimit ?? "-"}, 최근 재시작 +${p.recentRestartIncrease}`,
    );
    push(
      "RESOURCE_EXHAUSTION_SUSPECTED",
      base,
      "리소스 고갈 의심 (OOM)",
      "OOMKilled 발생 — Memory Limit 부족 가능성. Action 탭에서 리소스 상향 검토.",
      evidence,
      "HIGH",
    );
  }

  const highlightedEvents = input.events.filter((e) => e.highlighted).length;
  if (anomalies.length === 0 && (badPods.length > 0 || highlightedEvents >= 3)) {
    const evidence = badPods.slice(0, 3).map((p) => `Pod ${p.name}: ${p.statusLabel}`);
    evidence.push(`Warning 이벤트(강조) ${highlightedEvents}건`);
    push(
      "UNKNOWN_ANOMALY",
      "WARNING",
      "미분류 이상 징후",
      "메트릭 스파이크는 없으나 Pod 이상 또는 Warning 이벤트 다수 — 원인 미상, 추가 확인 필요.",
      evidence,
      "LOW",
    );
  }

  return anomalies;
}
