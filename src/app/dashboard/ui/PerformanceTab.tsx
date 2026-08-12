"use client";

import { useState } from "react";
import type { KubePanel, MetricsPanel, WarningEvent } from "@/lib/types";
import { ActionTab } from "./ActionTab";
import {
  Card,
  ErrorNote,
  SectionLoading,
  StatusBadge,
  Truncate,
  WarningEventDetailModal,
  fmtTs,
  type PollState,
} from "./shared";

function UsageBar({ label, pct }: { label: string; pct: number | null }) {
  const color =
    pct === null ? "bg-neutral-700" : pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div>
      <div className="flex justify-between text-neutral-500">
        <span>{label}</span>
        <span className="tabular-nums">{pct === null ? "limit 없음" : `${pct}%`}</span>
      </div>
      <div className="h-1.5 rounded bg-neutral-800">
        <div className={`h-1.5 rounded ${color}`} style={{ width: `${Math.min(pct ?? 0, 100)}%` }} />
      </div>
    </div>
  );
}

// Everything about how the workload is performing and how to change it: pod and
// node health, resource usage, response-time/status metrics, and the deployment
// controls that act on them.
export function PerformanceTab({
  kube,
  metrics,
  onJumpToLogs,
}: {
  kube: PollState<KubePanel>;
  metrics: PollState<MetricsPanel>;
  // The log terminal lives on its own tab now, so every "로그" affordance has
  // to move the user there as well as select the pod.
  onJumpToLogs: (pod: string, container: string) => void;
}) {
  const pods = kube.data?.pods ?? [];
  const [eventDetail, setEventDetail] = useState<WarningEvent | null>(null);
  const statusDist = metrics.data?.httpSummary?.statusDist ?? null;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card title="Pod 상태 분포">
          {kube.data ? (
            <div className="grid grid-cols-3 gap-2 text-[11px]">
              {(
                [
                  ["Running", kube.data.statusBreakdown.running, "text-emerald-400"],
                  ["Pending", kube.data.statusBreakdown.pending, "text-sky-400"],
                  ["CrashLoop", kube.data.statusBreakdown.crashLoop, "text-red-400"],
                  ["OOM", kube.data.statusBreakdown.oom, "text-red-400"],
                  ["Failed", kube.data.statusBreakdown.failed, "text-amber-400"],
                  ["기타", kube.data.statusBreakdown.other, "text-neutral-400"],
                ] as const
              ).map(([label, v, color]) => (
                <div key={label} className="rounded bg-neutral-950 p-2 text-center">
                  <div className={`text-lg font-bold tabular-nums ${color}`}>{v}</div>
                  <div className="text-neutral-500">{label}</div>
                </div>
              ))}
            </div>
          ) : (
            <SectionLoading />
          )}
        </Card>

        <Card
          title="Pod 개수 (최소/현재/최대)"
          right={<ErrorNote error={kube.data?.scalingError ?? null} />}
        >
          <div className="max-h-40 space-y-1 overflow-y-auto text-[11px]">
            {(kube.data?.podScaling ?? []).map((s) => (
              <div
                key={s.name}
                className="flex items-center justify-between rounded bg-neutral-950 px-2 py-1"
              >
                <Truncate text={s.name} className="text-neutral-300" />
                <span className="tabular-nums text-neutral-400">
                  {s.min ?? "-"} / <span className="font-bold text-neutral-200">{s.current}</span> /{" "}
                  {s.max ?? "-"}
                </span>
              </div>
            ))}
            <div className="text-neutral-600">{kube.data?.podScaling[0]?.source}</div>
          </div>
        </Card>

        <Card title="Node 개수 (최소/현재/최대)">
          <div className="max-h-40 space-y-1 overflow-y-auto text-[11px]">
            {(kube.data?.nodeScaling ?? []).map((s) => (
              <div
                key={s.name}
                className="flex items-center justify-between rounded bg-neutral-950 px-2 py-1"
              >
                <Truncate text={s.name} className="text-neutral-300" />
                <span className="tabular-nums text-neutral-400">
                  {s.min ?? "-"} / <span className="font-bold text-neutral-200">{s.current}</span> /{" "}
                  {s.max ?? "-"}
                </span>
              </div>
            ))}
            <div className="text-neutral-600">
              {kube.data?.nodeScaling[0]?.source} · 전체 노드 {kube.data?.nodesTotal ?? 0}개
            </div>
          </div>
        </Card>
      </div>

      <Card title={`Pod Health (${pods.length})`} right={<ErrorNote error={kube.error} />}>
        {kube.loading ? (
          <SectionLoading />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="text-neutral-500">
                <tr>
                  {[
                    "Pod",
                    "상태",
                    "Ready",
                    "재시작",
                    "CPU req/lim",
                    "Mem req/lim",
                    "Pod IP",
                    "Node",
                    "로그",
                  ].map((h) => (
                    <th key={h} className="px-2 py-1 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pods.map((p) => {
                  const c0 = p.containers[0];
                  const bad = p.statusLabel !== "Running";
                  return (
                    <tr
                      key={p.name}
                      className={`border-t border-neutral-800 ${bad ? "bg-red-950/20" : ""} ${p.recentRestartIncrease > 0 ? "bg-amber-950/20" : ""}`}
                    >
                      <td className="px-2 py-1 text-neutral-200">{p.name}</td>
                      <td
                        className={`px-2 py-1 ${bad ? "font-semibold text-red-400" : "text-emerald-400"}`}
                      >
                        {p.statusLabel}
                        {p.reason && <span className="ml-1 text-neutral-500">({p.reason})</span>}
                      </td>
                      <td className="px-2 py-1 tabular-nums">{p.ready}</td>
                      <td className="px-2 py-1 tabular-nums">
                        {p.totalRestarts}
                        {p.recentRestartIncrease > 0 && (
                          <span className="ml-1 font-bold text-amber-400">
                            +{p.recentRestartIncrease}
                          </span>
                        )}
                      </td>
                      <td className="px-2 py-1 tabular-nums text-neutral-400">
                        {c0 ? `${c0.cpuRequest}/${c0.cpuLimit}` : "-"}
                      </td>
                      <td className="px-2 py-1 tabular-nums text-neutral-400">
                        {c0 ? `${c0.memRequest}/${c0.memLimit}` : "-"}
                      </td>
                      <td className="px-2 py-1 text-neutral-500">{p.podIP}</td>
                      <td className="px-2 py-1 text-neutral-500">{p.nodeName}</td>
                      <td className="px-2 py-1">
                        <button
                          type="button"
                          onClick={() => onJumpToLogs(p.name, c0?.name ?? "")}
                          className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
                        >
                          보기
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card
          title="Pod 리소스 사용률 (CPU/Memory)"
          right={<ErrorNote error={kube.data?.podResourceError ?? null} />}
        >
          <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
            {(kube.data?.podResources ?? []).map((p) => (
              <div key={p.pod} className="rounded bg-neutral-950 px-2 py-1">
                <div className="flex justify-between text-neutral-300">
                  <Truncate text={p.pod} />
                  <span className="tabular-nums text-neutral-500">
                    {(p.cpuUsageMilli / 1000).toFixed(2)} core ·{" "}
                    {(p.memUsageBytes / 1024 / 1024).toFixed(0)}Mi
                  </span>
                </div>
                <div className="mt-1 grid grid-cols-2 gap-2">
                  <UsageBar label="CPU" pct={p.cpuPct} />
                  <UsageBar label="Mem" pct={p.memPct} />
                </div>
              </div>
            ))}
            {(kube.data?.podResources.length ?? 0) === 0 && !kube.data?.podResourceError && (
              <div className="text-neutral-500">수집 중…</div>
            )}
          </div>
        </Card>

        <Card
          title="Node 리소스 사용률 (CPU/Memory)"
          right={<ErrorNote error={kube.data?.nodeResourceError ?? null} />}
        >
          <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
            {(kube.data?.nodeResources ?? []).map((n) => (
              <div key={n.name} className="rounded bg-neutral-950 px-2 py-1">
                <div className="flex justify-between text-neutral-300">
                  <Truncate text={n.name} />
                  <span className="tabular-nums text-neutral-500">
                    {(n.cpuUsageMilli / 1000).toFixed(2)}/{(n.cpuCapacityMilli / 1000).toFixed(1)}{" "}
                    core · {(n.memUsageBytes / 1024 / 1024 / 1024).toFixed(2)}/
                    {(n.memCapacityBytes / 1024 / 1024 / 1024).toFixed(2)}Gi
                  </span>
                </div>
                <div className="mt-1 grid grid-cols-2 gap-2">
                  <UsageBar label="CPU" pct={n.cpuPct} />
                  <UsageBar label="Mem" pct={n.memPct} />
                </div>
              </div>
            ))}
            {(kube.data?.nodeResources.length ?? 0) === 0 && !kube.data?.nodeResourceError && (
              <div className="text-neutral-500">수집 중…</div>
            )}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card
          title="Target Group별 지표"
          right={<ErrorNote error={metrics.data?.targetGroupError ?? null} />}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="text-neutral-500">
                <tr>
                  {["Target Group", "경로", "TargetResponseTime", "4XX", "5XX"].map((h) => (
                    <th key={h} className="px-2 py-1 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(metrics.data?.targetGroupMetrics ?? []).map((tg) => (
                  <tr key={tg.name} className="border-t border-neutral-800">
                    <td className="px-2 py-1 text-neutral-200">{tg.name}</td>
                    <td className="px-2 py-1 text-neutral-400">{tg.pathPattern}</td>
                    <td className="px-2 py-1 tabular-nums">
                      {tg.responseTime.current}s <StatusBadge status={tg.responseTime.status} />
                    </td>
                    <td className="px-2 py-1 tabular-nums">
                      {tg.c4xx.current}/min <StatusBadge status={tg.c4xx.status} />
                    </td>
                    <td className="px-2 py-1 tabular-nums">
                      {tg.c5xx.current}/min <StatusBadge status={tg.c5xx.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(metrics.data?.targetGroupMetrics.length ?? 0) === 0 &&
              !metrics.data?.targetGroupError && (
                <div className="p-2 text-[11px] text-neutral-500">수집 중…</div>
              )}
          </div>
        </Card>

        <Card title="Status Code 분포 (분당)">
          {statusDist ? (
            <div className="space-y-2 text-[11px]">
              {(
                [
                  ["2xx", statusDist.c2xx, "bg-emerald-600"],
                  ["3xx", statusDist.c3xx, "bg-sky-600"],
                  ["4xx", statusDist.c4xx, "bg-amber-600"],
                  ["5xx", statusDist.c5xx, "bg-red-600"],
                ] as const
              ).map(([label, v, color]) => {
                const pct = statusDist.total > 0 ? Math.round((v / statusDist.total) * 100) : 0;
                return (
                  <div key={label}>
                    <div className="flex justify-between text-neutral-400">
                      <span>{label}</span>
                      <span className="tabular-nums">
                        {v} ({pct}%)
                      </span>
                    </div>
                    <div className="h-1.5 rounded bg-neutral-800">
                      <div className={`h-1.5 rounded ${color}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
              <div className="text-neutral-600">
                코드별(400/403/429/500/502/503/504…) 세분화는 ALB 메트릭 미제공 — WAF/ALB 로그 활성화
                시 확장 가능
              </div>
            </div>
          ) : (
            <div className="text-[11px] text-neutral-500">ALB 메트릭 수집 중…</div>
          )}
        </Card>
      </div>

      <Card title={`Warning Event Board (${kube.data?.events.length ?? 0})`}>
        <div className="max-h-64 overflow-y-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="text-neutral-500">
              <tr>
                {["시각", "대상", "사유", "메시지", "횟수", ""].map((h, i) => (
                  <th key={i} className="px-2 py-1 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(kube.data?.events ?? []).map((e, i) => (
                <tr
                  key={i}
                  onClick={() => setEventDetail(e)}
                  className={`cursor-pointer border-t border-neutral-800 hover:bg-neutral-800/40 ${e.highlighted ? "bg-amber-950/20" : ""}`}
                >
                  <td className="px-2 py-1 whitespace-nowrap text-neutral-500">
                    {fmtTs(e.timestamp)}
                  </td>
                  <td className="px-2 py-1 text-neutral-300">
                    {e.kind}/{e.name}
                  </td>
                  <td className={`px-2 py-1 ${e.highlighted ? "font-semibold text-amber-400" : ""}`}>
                    {e.reason}
                  </td>
                  <td className="px-2 py-1 text-neutral-400">
                    <Truncate text={e.message} className="max-w-64" />
                  </td>
                  <td className="px-2 py-1 tabular-nums">{e.count}</td>
                  <td className="px-2 py-1">
                    {e.isPod && (
                      <button
                        type="button"
                        onClick={(ev) => {
                          ev.stopPropagation();
                          onJumpToLogs(e.name, "");
                        }}
                        className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
                      >
                        로그
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <ActionTab kube={kube} />

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
