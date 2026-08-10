"use client";

import { useState } from "react";
import type { KubePanel, MetricsPanel, WafPanel, WarningEvent } from "@/lib/types";
import {
  Card,
  ErrorNote,
  SectionLoading,
  Sparkline,
  StatusBadge,
  Truncate,
  WarningEventDetailModal,
  fmtDelta,
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
  const [eventDetail, setEventDetail] = useState<WarningEvent | null>(null);

  return (
    <div className="space-y-3">
      <Card
        title="Infrastructure Health"
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
              <div
                key={m.key}
                className="rounded border border-neutral-800 bg-neutral-950 p-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-neutral-500">{m.label}</span>
                  <StatusBadge status={m.status} />
                </div>
                <div className="mt-1 font-mono text-xl font-bold tabular-nums text-neutral-100">
                  {m.current}
                  <span className="ml-1 font-sans text-[10px] font-normal text-neutral-500">
                    {m.unit}
                  </span>
                </div>
                <div
                  className={`font-mono text-[10px] tabular-nums ${
                    m.delta > 0 ? "text-amber-400" : m.delta < 0 ? "text-emerald-400" : "text-neutral-500"
                  }`}
                >
                  {fmtDelta(m.delta, m.percentChange)}
                </div>
                <Sparkline points={m.points} status={m.status} />
              </div>
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
                  {pods.length - badPods.length}/{pods.length}
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
              {waf.data && waf.data.recommendations.length > 0 && (
                <div className="rounded bg-sky-950/40 px-2 py-1 text-sky-300">
                  WAF 규칙 추천 {waf.data.recommendations.length}건 — WAF 탭 확인
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

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
