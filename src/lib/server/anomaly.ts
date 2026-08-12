import "server-only";
import { isBenignPath, isPathSuspicious } from "./config";
import { classifyUa, queryHasBase64Blob } from "./threatsig";
import type {
  Anomaly,
  AnomalyType,
  FingerprintEntry,
  HttpSummary,
  MetricSummary,
  PodInfo,
  Status,
  WarningEvent,
} from "@/lib/types";

export interface AnomalyInput {
  metrics: MetricSummary[];
  httpSummary: HttpSummary | null;
  pods: PodInfo[];
  events: WarningEvent[];
  fingerprints: FingerprintEntry[];
}

function metric(input: AnomalyInput, key: string): MetricSummary | undefined {
  return input.metrics.find((m) => m.key === key);
}

// A single signal is never enough for CRITICAL (spec §8): severity escalates
// only when corroborating signals exist.
function escalate(base: Status, corroborating: number): Status {
  if (base === "NORMAL") return "NORMAL";
  if (corroborating >= 1 && base === "CRITICAL") return "CRITICAL";
  return "WARNING";
}

export function detectAnomalies(input: AnomalyInput): Anomaly[] {
  const anomalies: Anomaly[] = [];
  const now = new Date().toISOString();
  const trt = metric(input, "targetResponseTime");
  const c4 = metric(input, "http4xx");
  const c5 = metric(input, "http5xx");
  const wafB = metric(input, "wafBlocked");
  const rds = metric(input, "rdsClientConnections");

  const badPods = input.pods.filter(
    (p) =>
      p.statusLabel !== "Running" || p.recentRestartIncrease > 0 || p.phase === "Failed",
  );
  const oomPods = input.pods.filter(
    (p) =>
      p.statusLabel === "OOMKilled" ||
      p.containers.some((c) => c.reason === "OOMKilled"),
  );
  const crashPods = input.pods.filter((p) => p.statusLabel === "CrashLoopBackOff");
  const repeatedErrors = input.fingerprints.filter((f) => f.count >= 5);

  const spikeSignals = [
    trt?.status !== "NORMAL",
    c4?.status !== "NORMAL",
    c5?.status !== "NORMAL",
    wafB?.status !== "NORMAL",
    badPods.length > 0,
    repeatedErrors.length > 0,
  ].filter(Boolean).length;

  const push = (
    type: AnomalyType,
    base: Status,
    title: string,
    detail: string,
    evidence: string[],
    confidence: Anomaly["confidence"],
  ): void => {
    anomalies.push({
      id: `${type}-${anomalies.length}`,
      type,
      severity: escalate(base, spikeSignals - 1),
      title,
      detail,
      evidence,
      confidence,
      detectedAt: now,
    });
  };

  if (c4 && c4.status !== "NORMAL") {
    push(
      "4XX_SPIKE",
      c4.status,
      "4XX 응답 급증",
      `4XX가 ${c4.previous} → ${c4.current} (${fmtPct(c4.percentChange)}) 변화. 정상 404/인증 실패 가능성도 있으므로 경로 분포 확인 필요.`,
      [`Target 4XX: ${c4.previous} → ${c4.current}/min`],
      c4.status === "CRITICAL" ? "HIGH" : "MEDIUM",
    );
  }
  if (c5 && c5.status !== "NORMAL") {
    push(
      "5XX_SPIKE",
      c5.status,
      "5XX 응답 급증",
      `5XX가 ${c5.previous} → ${c5.current} (${fmtPct(c5.percentChange)}) 변화 — 애플리케이션 또는 백엔드 장애 의심.`,
      [`Target 5XX: ${c5.previous} → ${c5.current}/min`],
      c5.status === "CRITICAL" ? "HIGH" : "MEDIUM",
    );
  }
  if (trt && trt.status !== "NORMAL") {
    push(
      "LATENCY_SPIKE",
      trt.status,
      "응답 지연 급증",
      `TargetResponseTime ${trt.previous}s → ${trt.current}s (${fmtPct(trt.percentChange)}).`,
      [`TargetResponseTime: ${trt.previous}s → ${trt.current}s`],
      "MEDIUM",
    );
  }
  if (wafB && wafB.status !== "NORMAL") {
    push(
      "WAF_BLOCK_SPIKE",
      wafB.status,
      "WAF 차단 급증",
      `BlockedRequests ${wafB.previous} → ${wafB.current}/min — 공격 시도 증가 또는 오탐 증가 가능성 모두 검토 필요.`,
      [`WAF BlockedRequests: ${wafB.previous} → ${wafB.current}/min`],
      "MEDIUM",
    );
  }

  if (input.httpSummary) {
    const total = Math.max(input.httpSummary.totalSampled, 1);
    // Request volume is never an anomaly in this environment — the scenario's
    // own load generator hammers the served API surface from a single IP.
    // Only traffic aimed outside that surface (probing, scanning) counts, so
    // the source-IP signal is gone and the path signal skips APP_TRAFFIC_PATHS.
    const offSurface = input.httpSummary.byPath.filter((p) => !p.lowPriority && !isBenignPath(p.path));
    const offSurfaceCount = offSurface.reduce((a, p) => a + p.count, 0);
    const concentrated: string[] = [];
    const topOff = offSurface[0];
    if (topOff && isPathSuspicious(topOff.path, topOff.count, total)) {
      concentrated.push(`경로 ${topOff.path}: 샘플 ${topOff.count}/${total}건 (서비스 경로 외)`);
    }
    const topUa = input.httpSummary.byUa[0];
    if (
      topUa &&
      offSurfaceCount >= 20 &&
      topUa.count / total >= 0.4 &&
      !/mozilla/i.test(topUa.key)
    ) {
      concentrated.push(`UA "${topUa.key}": ${topUa.count}/${total}건`);
    }
    if (concentrated.length > 0) {
      push(
        "TRAFFIC_ANOMALY_SUSPECTED",
        concentrated.length >= 2 ? "CRITICAL" : "WARNING",
        "비정상 트래픽 집중 의심",
        "서비스 경로(/v1/*) 외 요청이 집중 — 스캔 또는 탐색 시도 가능성. WAF 탭에서 규칙 추천 확인.",
        concentrated,
        concentrated.length >= 2 ? "HIGH" : "MEDIUM",
      );
    }

    // Malicious-client signatures in the sampled UA/query mix. Independent of
    // request volume — a single scanner fingerprint is a finding — and blind to
    // source IP by policy. The Go client is bypassed inside classifyUa (REQ-01).
    // UNKNOWN is excluded here on purpose. classifyUa reports it for any client
    // that is not on the expected list, which is what the rule assembler wants
    // — a rule should cover them — but it is not evidence of an attack, and an
    // anomaly raised for every stray client would bury the scanner hit that
    // actually matters. A positive signature is required to alarm.
    const flaggedUa = input.httpSummary.byUa
      .map((u) => ({ hit: classifyUa(u.key), key: u.key, count: u.count }))
      .filter(
        (x): x is { hit: NonNullable<ReturnType<typeof classifyUa>>; key: string; count: number } =>
          x.hit !== null && x.hit.category !== "UNKNOWN",
      );
    const b64Query = input.httpSummary.queryPatterns.filter((q) => queryHasBase64Blob(q.key));
    if (flaggedUa.length > 0 || b64Query.length > 0) {
      const evidence: string[] = [];
      for (const f of flaggedUa.slice(0, 5)) {
        evidence.push(`악성 클라이언트 UA "${f.key}" (${f.hit.category}/${f.hit.label}): ${f.count}건`);
      }
      for (const q of b64Query.slice(0, 3)) {
        evidence.push(`base64 난독화 쿼리 의심: "${q.key.slice(0, 60)}"`);
      }
      // Only a named offensive tool is CRITICAL on its own. AUTOMATION (curl,
      // python-requests) is worth a rule but is not by itself an attack, and
      // treating it as one would make every scripted client a red light.
      const hasScanner = flaggedUa.some(
        (f) => f.hit.category === "SCANNER" || f.hit.category === "RECON",
      );
      push(
        "MALICIOUS_CLIENT_SUSPECTED",
        hasScanner ? "CRITICAL" : "WARNING",
        "악성 클라이언트 시그니처 탐지",
        "샘플 트래픽에서 스캐너·정찰 툴 또는 위조/난독 시그니처가 관측됨",
        evidence,
        "HIGH",
      );
      // A named scanner/recon tool is an unambiguous, near-zero-false-positive
      // signature on its own — unlike the other detectors above, its severity
      // must not be downgraded by escalate() just because no other metric is
      // spiking (a lone scanner UA is common with volume-based signals quiet).
      // Overwrite the severity `push` just set instead of touching escalate,
      // which every other detector in this file still relies on unchanged.
      // Non-null: `push` synchronously appended one element immediately above.
      const justPushed = anomalies[anomalies.length - 1]!;
      justPushed.severity = hasScanner ? "CRITICAL" : "WARNING";
    }
  }

  if (crashPods.length > 0 || (c5 && c5.status !== "NORMAL" && repeatedErrors.length > 0)) {
    push(
      "APPLICATION_FAILURE_SUSPECTED",
      crashPods.length > 0 && c5 && c5.status !== "NORMAL" ? "CRITICAL" : "WARNING",
      "애플리케이션 장애 의심",
      "CrashLoopBackOff 또는 반복 예외 로그와 5XX가 동반 — 애플리케이션 결함 가능성 (확정 아님, 로그 확인 필요).",
      [
        ...crashPods.map((p) => `Pod ${p.name}: CrashLoopBackOff (재시작 ${p.totalRestarts})`),
        ...repeatedErrors.slice(0, 3).map((f) => `반복 오류 ×${f.count}: ${f.fingerprint.slice(0, 80)}`),
      ],
      crashPods.length > 0 ? "HIGH" : "MEDIUM",
    );
  }

  const healthyPods = badPods.length === 0;
  if (
    rds &&
    rds.status !== "NORMAL" &&
    trt &&
    trt.status !== "NORMAL" &&
    healthyPods
  ) {
    push(
      "DATABASE_PRESSURE_SUSPECTED",
      c5 && c5.status !== "NORMAL" ? "CRITICAL" : "WARNING",
      "데이터베이스 부하 의심",
      "RDS 연결 증가 + 지연 증가 + Pod 정상 조합 — DB 측 병목 가능성 (쿼리/인덱스/커넥션 풀 점검 필요).",
      [
        `RDS Proxy Client Conn: ${rds.previous} → ${rds.current}`,
        `TargetResponseTime: ${trt.previous}s → ${trt.current}s`,
        `이상 Pod 없음`,
      ],
      "MEDIUM",
    );
  }

  if (oomPods.length > 0) {
    push(
      "RESOURCE_EXHAUSTION_SUSPECTED",
      oomPods.some((p) => p.recentRestartIncrease > 0) ? "CRITICAL" : "WARNING",
      "리소스 고갈 의심 (OOM)",
      "OOMKilled 발생 — Memory Limit 부족 가능성. Action 탭에서 리소스 상향 검토.",
      oomPods.map(
        (p) =>
          `Pod ${p.name}: OOMKilled, limit=${p.containers[0]?.memLimit ?? "-"}, 최근 재시작 +${p.recentRestartIncrease}`,
      ),
      "HIGH",
    );
  }

  const highlightedEvents = input.events.filter((e) => e.highlighted).length;
  if (anomalies.length === 0 && (badPods.length > 0 || highlightedEvents >= 3)) {
    push(
      "UNKNOWN_ANOMALY",
      "WARNING",
      "미분류 이상 징후",
      "메트릭 스파이크는 없으나 Pod 이상 또는 Warning 이벤트 다수 — 원인 미상, 추가 확인 필요.",
      [
        ...badPods.slice(0, 3).map((p) => `Pod ${p.name}: ${p.statusLabel}`),
        `Warning 이벤트(강조) ${highlightedEvents}건`,
      ],
      "LOW",
    );
  }

  return anomalies;
}

function fmtPct(p: number | null): string {
  if (p === null) return "이전 구간 0 → 신규 발생";
  return `${p >= 0 ? "+" : ""}${p}%`;
}
