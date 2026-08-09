"use client";

import { useState } from "react";
import {
  applyRuleAction,
  rollbackWafAction,
  simulateRuleAction,
} from "@/app/actions/dashboard";
import type { MetricsPanel, SimulationResult, WafPanel } from "@/lib/types";
import { Card, ErrorNote, SectionLoading, fmtTs, type PollState } from "./shared";

const RISK_COLOR = {
  LOW: "text-emerald-400",
  MEDIUM: "text-amber-400",
  HIGH: "text-red-400",
} as const;

function StatList({
  title,
  rows,
}: {
  title: string;
  rows: { key: string; count: number; warn?: boolean }[];
}) {
  return (
    <div>
      <div className="mb-1 text-[11px] text-neutral-500">{title}</div>
      <div className="max-h-40 space-y-0.5 overflow-y-auto text-[11px]">
        {rows.map((r, i) => (
          <div
            key={i}
            className={`flex justify-between gap-2 rounded px-1.5 py-0.5 ${r.warn ? "bg-red-950/30 text-red-300" : "bg-neutral-950 text-neutral-300"}`}
          >
            <span className="truncate">{r.key || "(empty)"}</span>
            <span className="tabular-nums text-neutral-500">{r.count}</span>
          </div>
        ))}
        {rows.length === 0 && <div className="text-neutral-600">데이터 없음</div>}
      </div>
    </div>
  );
}

export function WafTab({
  waf,
  metrics,
}: {
  waf: PollState<WafPanel>;
  metrics: PollState<MetricsPanel>;
}) {
  const [simResults, setSimResults] = useState<Record<string, SimulationResult>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [confirmApply, setConfirmApply] = useState<{ id: string; mode: "COUNT" | "BLOCK" } | null>(
    null,
  );

  const wafBlockedMetric = metrics.data?.metrics.find((m) => m.key === "wafBlocked");
  const wafAllowedMetric = metrics.data?.metrics.find((m) => m.key === "wafAllowed");

  const runSimulate = async (id: string): Promise<void> => {
    setBusy(id);
    setMessage(null);
    const res = await simulateRuleAction(id);
    if (res.ok) setSimResults((prev) => ({ ...prev, [id]: res.data }));
    else setMessage(`시뮬레이션 실패: ${res.error}`);
    setBusy(null);
  };

  const runApply = async (id: string, mode: "COUNT" | "BLOCK"): Promise<void> => {
    setBusy(id);
    setMessage(null);
    setConfirmApply(null);
    const res = await applyRuleAction({ recommendationId: id, mode });
    if (res.ok) {
      setMessage(
        `적용 성공: ${res.data.ruleName} (priority ${res.data.priority}, ${mode}) — 이력 #${res.data.historyId}. CloudWatch에서 매칭량 검증 후 다음 단계 판단.`,
      );
      waf.refresh();
    } else {
      setMessage(`적용 실패: ${res.error}`);
    }
    setBusy(null);
  };

  const runRollback = async (historyId: number): Promise<void> => {
    setBusy(`rb-${historyId}`);
    setMessage(null);
    const res = await rollbackWafAction(historyId);
    setMessage(res.ok ? `롤백 완료 (이력 #${historyId})` : `롤백 실패: ${res.error}`);
    if (res.ok) waf.refresh();
    setBusy(null);
  };

  return (
    <div className="space-y-3">
      {message && (
        <div className="rounded border border-sky-900 bg-sky-950/40 px-3 py-2 text-xs text-sky-200">
          {message}
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card title="WAF 이상 요약" right={<ErrorNote error={waf.error} />}>
          <div className="space-y-1 text-xs text-neutral-400">
            <div>
              BlockedRequests:{" "}
              {wafBlockedMetric
                ? `${wafBlockedMetric.previous} → ${wafBlockedMetric.current}/min (${wafBlockedMetric.status})`
                : "수집 중"}
            </div>
            <div>
              AllowedRequests:{" "}
              {wafAllowedMetric
                ? `${wafAllowedMetric.previous} → ${wafAllowedMetric.current}/min (${wafAllowedMetric.status})`
                : "수집 중"}
            </div>
            {waf.data?.acl ? (
              <>
                <div>
                  WebACL: <span className="text-neutral-200">{waf.data.acl.name}</span> ({waf.data.acl.scope}) — 규칙 {waf.data.acl.ruleCount}개, WCU {waf.data.acl.capacityUsed}
                </div>
                <div className="mt-1 space-y-0.5">
                  {waf.data.acl.rules.map((r) => (
                    <div key={r.name} className="flex justify-between rounded bg-neutral-950 px-2 py-0.5">
                      <span>{r.name}</span>
                      <span className="tabular-nums text-neutral-500">
                        p{r.priority} · {r.action}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="text-red-400">{waf.data?.aclError ?? "WebACL 조회 중…"}</div>
            )}
          </div>
        </Card>

        <Card title="적용 이력 / 롤백">
          <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
            {(waf.data?.history ?? []).map((h) => (
              <div key={h.id} className="flex items-center justify-between rounded bg-neutral-950 px-2 py-1">
                <div>
                  <span className="text-neutral-500">{fmtTs(h.ts)}</span>{" "}
                  <span className="text-neutral-200">{h.ruleName}</span>{" "}
                  <span className="text-neutral-400">{h.action}</span>{" "}
                  <span className={h.status === "SUCCESS" ? "text-emerald-400" : "text-red-400"}>
                    {h.status}
                  </span>
                  <div className="text-neutral-600">{h.detail}</div>
                </div>
                {h.canRollback && (
                  <button
                    type="button"
                    disabled={busy === `rb-${h.id}`}
                    onClick={() => void runRollback(h.id)}
                    className="rounded bg-red-900/60 px-2 py-1 text-red-200 hover:bg-red-900 disabled:opacity-50"
                  >
                    롤백
                  </button>
                )}
              </div>
            ))}
            {(waf.data?.history.length ?? 0) === 0 && (
              <div className="text-neutral-500">적용 이력 없음</div>
            )}
          </div>
        </Card>
      </div>

      <Card title="WAF 로그 통계 (경로/쿼리/헤더/메소드/차단)">
        {metrics.data?.httpSummary ? (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
            <StatList
              title={`Path (총 ${metrics.data.httpSummary.totalSampled}건, 차단 ${metrics.data.httpSummary.byPath.reduce((a, p) => a + p.blocked, 0)}건)`}
              rows={metrics.data.httpSummary.byPath.map((p) => ({
                key: `${p.path || "/"}${p.blocked > 0 ? ` (차단 ${p.blocked})` : ""}`,
                count: p.count,
                warn: p.blocked > 0,
              }))}
            />
            <StatList
              title="Method"
              rows={metrics.data.httpSummary.byMethod.map((m) => ({ key: m.key, count: m.count }))}
            />
            <StatList
              title="QueryString 패턴"
              rows={metrics.data.httpSummary.queryPatterns.map((q) => ({ key: q.key, count: q.count }))}
            />
            <StatList
              title="Header 패턴"
              rows={metrics.data.httpSummary.headerPatterns.map((h) => ({ key: h.key, count: h.count }))}
            />
          </div>
        ) : (
          <div className="text-xs text-neutral-500">{metrics.data?.httpSummaryError ?? "수집 중…"}</div>
        )}
      </Card>

      <Card title={`추천 규칙 (${waf.data?.recommendations.length ?? 0})`}>
        {waf.loading ? (
          <SectionLoading />
        ) : (
          <div className="space-y-3">
            {waf.data?.recommendationError && <ErrorNote error={waf.data.recommendationError} />}
            {(waf.data?.recommendations ?? []).map((r) => {
              const sim = simResults[r.id];
              return (
                <div key={r.id} className="rounded border border-neutral-800 bg-neutral-950 p-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-neutral-800 px-1.5 py-0.5 font-mono text-[10px] text-sky-300">
                      {r.kind}
                    </span>
                    <span className="font-semibold text-neutral-200">{r.targetPattern}</span>
                    <span className="text-neutral-500">신뢰도 {r.confidence}</span>
                    <span className={RISK_COLOR[r.falsePositiveRisk]}>
                      오탐위험 {r.falsePositiveRisk}
                    </span>
                    {r.hasScopeDown && <span className="text-neutral-500">scope-down 포함</span>}
                  </div>
                  <p className="mt-1 text-neutral-400">{r.reason}</p>
                  <div className="mt-1 grid grid-cols-2 gap-x-4 text-neutral-500 md:grid-cols-4">
                    {r.threshold !== null && <div>임계치: {r.threshold}건</div>}
                    {r.evaluationWindowSec !== null && <div>평가 윈도우: {r.evaluationWindowSec}s</div>}
                    <div>기본 액션: {r.action}</div>
                    <div>예상 영향: {r.expectedImpact.slice(0, 40)}…</div>
                  </div>
                  <ul className="mt-1 list-inside list-disc text-neutral-600">
                    {r.evidence.map((ev, i) => (
                      <li key={i}>{ev}</li>
                    ))}
                  </ul>

                  {sim && (
                    <div className="mt-2 rounded border border-sky-900/50 bg-sky-950/20 p-2">
                      <div className="font-semibold text-sky-300">
                        시뮬레이션 결과 — 위험도{" "}
                        <span className={RISK_COLOR[sim.riskLevel]}>{sim.riskLevel}</span>
                      </div>
                      <div className="mt-1 grid grid-cols-2 gap-x-4 text-neutral-400 md:grid-cols-3">
                        <div>샘플 매칭: {sim.matchedSampled}/{sim.totalSampled} ({sim.matchRatePct}%)</div>
                        <div>추정 전체 요청: {sim.estimatedTotalRequests}</div>
                        <div>추정 매칭: {sim.estimatedMatched}</div>
                        <div>추정 오탐: {sim.estimatedFalsePositives}</div>
                        <div>추정 정상 차단(BLOCK 시): {sim.estimatedLegitBlocked}</div>
                      </div>
                      <ul className="mt-1 list-inside list-disc text-neutral-600">
                        {sim.notes.map((n, i) => (
                          <li key={i}>{n}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="mt-2 flex gap-2">
                    <button
                      type="button"
                      disabled={busy === r.id}
                      onClick={() => void runSimulate(r.id)}
                      className="rounded bg-sky-900/60 px-3 py-1 text-sky-200 hover:bg-sky-900 disabled:opacity-50"
                    >
                      시뮬레이션
                    </button>
                    <button
                      type="button"
                      disabled={busy === r.id || !sim}
                      title={sim ? "" : "시뮬레이션 먼저 실행"}
                      onClick={() => setConfirmApply({ id: r.id, mode: "COUNT" })}
                      className="rounded bg-amber-900/60 px-3 py-1 text-amber-200 hover:bg-amber-900 disabled:opacity-50"
                    >
                      COUNT 적용 (승인 필요)
                    </button>
                    <button
                      type="button"
                      disabled={busy === r.id}
                      onClick={() => setConfirmApply({ id: r.id, mode: "BLOCK" })}
                      className="rounded bg-red-900/60 px-3 py-1 text-red-200 hover:bg-red-900 disabled:opacity-50"
                    >
                      BLOCK 승격
                    </button>
                  </div>

                  {confirmApply?.id === r.id && (
                    <div className="mt-2 rounded border border-red-900 bg-red-950/40 p-2">
                      <p className="text-red-200">
                        {confirmApply.mode === "COUNT"
                          ? `"${r.name}" 규칙을 COUNT 모드로 실제 WebACL에 추가합니다. 차단은 발생하지 않으며 매칭량만 계측됩니다. 적용 전 WebACL 스냅샷이 저장되어 롤백 가능합니다.`
                          : `"${r.name}" 규칙을 BLOCK으로 전환합니다. 동일 규칙의 COUNT 검증 이력이 서버에서 확인되어야 하며, 매칭 요청이 실제로 차단됩니다.`}
                      </p>
                      <div className="mt-2 flex gap-2">
                        <button
                          type="button"
                          onClick={() => void runApply(r.id, confirmApply.mode)}
                          className="rounded bg-red-700 px-3 py-1 font-semibold text-white hover:bg-red-600"
                        >
                          승인 및 적용
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmApply(null)}
                          className="rounded bg-neutral-800 px-3 py-1 text-neutral-300"
                        >
                          취소
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
            {(waf.data?.recommendations.length ?? 0) === 0 && !waf.data?.recommendationError && (
              <div className="text-xs text-neutral-500">
                현재 추천 조건 미충족 — 트래픽 집중/스파이크가 관측되면 자동 생성됩니다
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
