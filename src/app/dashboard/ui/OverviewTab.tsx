"use client";

import { useState } from "react";
import type { KubePanel, MetricsPanel, WafPanel, WarningEvent } from "@/lib/types";
import {
  Card,
  ErrorNote,
  SectionLoading,
  Sparkline,
  Stat,
  StatusBadge,
  Truncate,
  WarningEventDetailModal,
  fmtDelta,
  fmtTs,
  type PollState,
} from "./shared";

export function OverviewTab({
  kube,
  metrics,
  waf,
  onJumpToLogs,
}: {
  kube: PollState<KubePanel>;
  metrics: PollState<MetricsPanel>;
  waf: PollState<WafPanel>;
  onJumpToLogs: (pod: string, container: string) => void;
}) {
  const pods = kube.data?.pods ?? [];
  const badPods = pods.filter((p) => p.statusLabel !== "Running");
  const restartPods = pods.filter((p) => p.recentRestartIncrease > 0);
  // Healthy-pod count comes from the server's own classification, so this card
  // and the 성능 tab's breakdown can never disagree.
  const breakdown = kube.data?.statusBreakdown;
  const [eventDetail, setEventDetail] = useState<WarningEvent | null>(null);

  return (
    <div className="space-y-3">
      <Card
        title="Infrastructure Health"
        basis={
          metrics.data
            ? `조회 구간 ${metrics.data.window.label} · 각 값의 출처는 타일 아래에 따로 적혀 있음`
            : undefined
        }
        right={
          <ErrorNote
            error={metrics.error ?? (metrics.data?.metricErrors.join(" / ") || null)}
          />
        }
      >
        {metrics.loading ? (
          <SectionLoading />
        ) : (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
            {(metrics.data?.metrics ?? []).map((m) => (
              // The basis is per tile, not per card: "요청 수" over a Sum and
              // over an Average are different populations, and one shared
              // caption gives no way to tell which is which.
              <Stat
                key={m.key}
                label={m.label}
                value={String(m.current)}
                unit={m.unit}
                status={m.status}
                basis={m.basis}
                // Each tile carries its own series, so ⤢ on the tile opens that
                // one metric on a real axis instead of enlarging all six.
                points={m.points}
                detail={
                  <div className="grid grid-cols-3 gap-2 text-[11px]">
                    {(
                      [
                        ["직전 값", String(m.previous)],
                        ["변화", fmtDelta(m.delta, m.percentChange)],
                        ["버킷 수", `${m.points.length}개`],
                      ] as const
                    ).map(([k, v]) => (
                      <div key={k} className="rounded border border-neutral-800 bg-neutral-950 p-2">
                        <div className="text-[10px] text-neutral-500">{k}</div>
                        <div className="font-mono tabular-nums text-neutral-200">{v}</div>
                      </div>
                    ))}
                  </div>
                }
                sub={
                  <div className="flex items-center justify-between gap-1">
                    <span
                      className={`font-mono text-[10px] tabular-nums ${
                        m.delta > 0
                          ? "text-amber-400"
                          : m.delta < 0
                            ? "text-emerald-400"
                            : "text-neutral-500"
                      }`}
                    >
                      {fmtDelta(m.delta, m.percentChange)}
                    </span>
                    <Sparkline points={m.points} status={m.status} />
                  </div>
                }
              />
            ))}
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card title={`Pod Health (${pods.length})`} right={<ErrorNote error={kube.error} />}>
          {kube.loading ? (
            <SectionLoading />
          ) : (
            <div className="space-y-1 text-xs">
              <div className="flex justify-between text-neutral-400">
                <span>노드</span>
                <span className="tabular-nums">
                  {kube.data?.nodesReady}/{kube.data?.nodesTotal} Ready
                </span>
              </div>
              <div className="flex justify-between text-neutral-400">
                <span>정상 Pod</span>
                <span className="tabular-nums text-emerald-400">
                  {breakdown?.running ?? 0}/{breakdown?.total ?? 0}
                </span>
              </div>
              {badPods.map((p) => (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => onJumpToLogs(p.name, p.containers[0]?.name ?? "")}
                  className="flex w-full justify-between rounded bg-red-950/40 px-2 py-1 text-left text-red-300 hover:bg-red-950/70"
                >
                  <Truncate text={p.name} />
                  <span>{p.statusLabel}</span>
                </button>
              ))}
              {restartPods.map((p) => (
                <div key={`r-${p.name}`} className="flex justify-between rounded bg-amber-950/40 px-2 py-1 text-amber-300">
                  <Truncate text={p.name} />
                  <span>재시작 +{p.recentRestartIncrease}</span>
                </div>
              ))}
              {badPods.length === 0 && restartPods.length === 0 && (
                <div className="text-neutral-500">이상 Pod 없음</div>
              )}
            </div>
          )}
        </Card>

        <Card title={`Warning Events (${kube.data?.events.length ?? 0})`}>
          {kube.loading ? (
            <SectionLoading />
          ) : (
            <div className="max-h-48 space-y-1 overflow-y-auto text-[11px]">
              {(kube.data?.events ?? []).slice(0, 8).map((e, i) => (
                <button
                  key={`${e.name}-${i}`}
                  type="button"
                  onClick={() => setEventDetail(e)}
                  className={`block w-full cursor-pointer rounded px-2 py-1 text-left ${e.highlighted ? "bg-amber-950/40 text-amber-300 hover:bg-amber-950/70" : "bg-neutral-950 text-neutral-400 hover:bg-neutral-800/60"}`}
                >
                  <span className="font-semibold">{e.reason}</span> [{e.kind}/{e.name}]{" "}
                  <span className="text-neutral-500">×{e.count}</span>
                </button>
              ))}
              {(kube.data?.events.length ?? 0) === 0 && (
                <div className="text-neutral-500">Warning 이벤트 없음</div>
              )}
            </div>
          )}
        </Card>

        <Card title={`Anomalies (${metrics.data?.anomalies.length ?? 0})`}>
          {metrics.loading ? (
            <SectionLoading />
          ) : (
            <div className="max-h-48 space-y-1 overflow-y-auto text-[11px]">
              {(metrics.data?.anomalies ?? []).map((a) => (
                <div key={a.id} className="rounded bg-neutral-950 px-2 py-1">
                  <div className="flex items-center gap-2">
                    <StatusBadge status={a.severity} />
                    <span className="font-semibold text-neutral-200">{a.title}</span>
                  </div>
                  <div className="mt-0.5 text-neutral-500">{a.type}</div>
                </div>
              ))}
              {(metrics.data?.anomalies.length ?? 0) === 0 && (
                <div className="text-emerald-500">감지된 이상 없음</div>
              )}
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card title="이상 상세 (근거 포함)" right={<ErrorNote error={metrics.error} />}>
          <div className="max-h-56 space-y-2 overflow-y-auto text-[11px]">
            {(metrics.data?.anomalies ?? []).map((a) => (
              <div key={a.id} className="rounded border border-neutral-800 bg-neutral-950 p-2">
                <div className="flex items-center gap-2">
                  <StatusBadge status={a.severity} />
                  <span className="font-semibold text-neutral-200">{a.title}</span>
                  <span className="text-neutral-600">신뢰도 {a.confidence}</span>
                </div>
                <p className="mt-1 text-neutral-400">{a.detail}</p>
                <ul className="mt-1 list-inside list-disc text-neutral-500">
                  {a.evidence.map((ev, i) => (
                    <li key={i}>{ev}</li>
                  ))}
                </ul>
              </div>
            ))}
            {(metrics.data?.anomalies.length ?? 0) === 0 && (
              <div className="text-neutral-500">감지된 이상 없음</div>
            )}
          </div>
        </Card>

        <Card title="Correlation (추정 원인 — 확정 아님)">
          <div className="max-h-56 space-y-2 overflow-y-auto text-[11px]">
            {(metrics.data?.correlations ?? []).map((c, i) => (
              <div key={i} className="rounded border border-sky-900/50 bg-sky-950/20 p-2">
                <div className="font-semibold text-sky-300">
                  {c.category} <span className="text-neutral-500">({c.confidence})</span>
                </div>
                <p className="mt-1 text-neutral-400">{c.reason}</p>
                <ul className="mt-1 list-inside list-disc text-neutral-500">
                  {c.evidence.slice(0, 5).map((ev, j) => (
                    <li key={j}>{ev}</li>
                  ))}
                </ul>
              </div>
            ))}
            {(metrics.data?.correlations.length ?? 0) === 0 && (
              <div className="text-neutral-500">상관관계 결과 없음</div>
            )}
          </div>
        </Card>
      </div>

      <Card title="Incident Timeline">
        <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
          {(metrics.data?.timeline ?? []).slice(-30).map((t, i) => (
            <div key={i} className="flex gap-2">
              <span className="whitespace-nowrap tabular-nums text-neutral-600">{fmtTs(t.ts)}</span>
              <span
                className={
                  t.severity === "CRITICAL"
                    ? "text-red-400"
                    : t.severity === "WARNING"
                      ? "text-amber-400"
                      : "text-neutral-400"
                }
              >
                [{t.source}] {t.text}
              </span>
            </div>
          ))}
          {(metrics.data?.timeline.length ?? 0) === 0 && (
            <div className="text-neutral-500">타임라인 이벤트 없음</div>
          )}
        </div>
      </Card>

      {eventDetail && (
        <WarningEventDetailModal
          event={eventDetail}
          onClose={() => setEventDetail(null)}
          onJumpToLogs={(pod) => onJumpToLogs(pod, "")}
        />
      )}
    </div>
  );
}
