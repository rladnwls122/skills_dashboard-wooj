"use client";

import { useState } from "react";
import { getResourceHistoryAction } from "@/app/actions/dashboard";
import type {
  KubePanel,
  MetricsPanel,
  NamedSeries,
  ResourceHistory,
  WarningEvent,
  WindowSelection,
} from "@/lib/types";
import { ActionTab } from "./ActionTab";
import { GradingCard } from "./GradingCard";
import {
  Card,
  ErrorNote,
  SectionLoading,
  StatusBadge,
  Truncate,
  WarningEventDetailModal,
  fmtTs,
  usePoll,
  type PollState,
} from "./shared";
import { TimeChart } from "./TimeChart";

// Target groups keep their colour across both charts, so the line that is slow
// in the latency chart is the same colour as the one throwing errors below it.
const TG_COLORS = ["#54b8ff", "#3ddc97", "#c792ea", "#7fdbca"] as const;
const ERR_COLORS = ["#ff5c5c", "#ffb454", "#f78c6c", "#e57373"] as const;

const STATUS_SERIES = [
  { key: "http2xx", label: "2XX", color: "#3ddc97" },
  { key: "http3xx", label: "3XX", color: "#54b8ff" },
  { key: "http4xx", label: "4XX", color: "#ffb454" },
  { key: "http5xx", label: "5XX", color: "#ff5c5c" },
] as const;

// Distinct enough that eight pods stay tellable apart in a legend.
const USAGE_COLORS = [
  "#54b8ff", "#3ddc97", "#ffb454", "#c792ea", "#7fdbca", "#f78c6c", "#89ddff", "#e57373",
];

interface UsageNow {
  name: string;
  cpuPct: number | null;
  memPct: number | null;
  detail: string;
}

// Usage as two charts plus the current reading.
//
// The bars this replaces could say 95% and not say for how long — which is the
// difference between a burst and a pod that needs a bigger limit. The current
// number stays, because "what is it right now" is still the first question,
// but it sits under the line that explains it.
//
// Colours are assigned per name across both charts, so the pod that is hot on
// CPU is the same colour in the memory chart underneath.
function UsageCharts({
  cpu,
  mem,
  now,
  loading,
}: {
  cpu: NamedSeries[];
  mem: NamedSeries[];
  now: UsageNow[];
  loading: boolean;
}) {
  const color = (name: string): string => {
    const names = [...new Set([...cpu, ...mem].map((s) => s.label))].sort();
    const i = names.indexOf(name);
    return USAGE_COLORS[(i < 0 ? 0 : i) % USAGE_COLORS.length]!;
  };
  const paint = (list: NamedSeries[]) =>
    list.map((s) => ({ label: s.label, points: s.points, color: color(s.label), unit: "%" }));

  if (loading && now.length === 0) return <SectionLoading />;

  return (
    <div className="space-y-2">
      {cpu.length === 0 && mem.length === 0 ? (
        <div className="rounded border border-neutral-800 bg-neutral-950 px-2 py-3 text-center text-[11px] text-neutral-500">
          이 구간에 기록된 사용률이 없습니다 — 대시보드가 켜져 있는 동안에만 기록됩니다.
        </div>
      ) : (
        <>
          <div>
            <div className="mb-1 font-mono text-[10px] text-neutral-500">CPU 사용률 (%)</div>
            <TimeChart height={150} syncKey="perf" series={paint(cpu)} />
          </div>
          <div>
            <div className="mb-1 font-mono text-[10px] text-neutral-500">Memory 사용률 (%)</div>
            <TimeChart height={150} syncKey="perf" series={paint(mem)} />
          </div>
        </>
      )}

      <div className="max-h-32 space-y-0.5 overflow-y-auto text-[11px]">
        <div className="text-neutral-500">현재값</div>
        {now.map((r) => (
          <div key={r.name} className="flex items-center justify-between gap-2 rounded bg-neutral-950 px-2 py-0.5">
            <span className="flex min-w-0 items-center gap-1.5">
              <span
                aria-hidden
                className="h-0.5 w-3 shrink-0 rounded"
                style={{ background: color(r.name) }}
              />
              <Truncate text={r.name} className="text-neutral-300" />
            </span>
            <span className="shrink-0 tabular-nums text-neutral-500">
              {r.detail} · CPU{" "}
              <span className={pctClass(r.cpuPct)}>
                {r.cpuPct === null ? "limit 없음" : `${r.cpuPct}%`}
              </span>{" "}
              · Mem{" "}
              <span className={pctClass(r.memPct)}>
                {r.memPct === null ? "limit 없음" : `${r.memPct}%`}
              </span>
            </span>
          </div>
        ))}
        {now.length === 0 && <div className="text-neutral-600">수집 중…</div>}
      </div>
    </div>
  );
}

function pctClass(pct: number | null): string {
  if (pct === null) return "text-neutral-600";
  if (pct >= 90) return "text-red-400";
  if (pct >= 70) return "text-amber-400";
  return "text-emerald-400";
}

// Everything about how the workload is performing and how to change it: pod and
// node health, resource usage, response-time/status metrics, and the deployment
// controls that act on them.
export function PerformanceTab({
  kube,
  metrics,
  onJumpToLogs,
  window: win,
}: {
  kube: PollState<KubePanel>;
  metrics: PollState<MetricsPanel>;
  window: WindowSelection;
  // The log terminal lives on its own tab now, so every "로그" affordance has
  // to move the user there as well as select the pod.
  onJumpToLogs: (pod: string, container: string) => void;
}) {
  const pods = kube.data?.pods ?? [];
  const [eventDetail, setEventDetail] = useState<WarningEvent | null>(null);
  // Read-only: the samples are written by the kube poll, so this only reads
  // SQLite. It follows the shared window like every other panel.
  const history: PollState<ResourceHistory> = usePoll(
    () => getResourceHistoryAction(win),
    15_000,
    true,
    [win.windowMin, win.intervalMin],
  );
  const statusDist = metrics.data?.httpSummary?.statusDist ?? null;

  // The charts read the series already on the panel — nothing is re-fetched or
  // re-aggregated here, so a line and the number beside it cannot disagree.
  const tgs = metrics.data?.targetGroupMetrics ?? [];
  const tgSeries = {
    trt: tgs
      .filter((tg) => tg.responseTime.points.length > 0)
      .map((tg, i) => ({
        label: tg.name,
        points: tg.responseTime.points,
        color: TG_COLORS[i % TG_COLORS.length],
      })),
    // 4XX and 5XX share the axis because they share a unit, and the pair is
    // read together: 5XX rising while 4XX holds is a different fault from both
    // rising at once.
    errors: tgs.flatMap((tg, i) => [
      { label: `${tg.name} 4XX`, points: tg.c4xx.points, color: TG_COLORS[i % TG_COLORS.length] },
      { label: `${tg.name} 5XX`, points: tg.c5xx.points, color: ERR_COLORS[i % ERR_COLORS.length] },
    ]).filter((s) => s.points.length > 0),
  };

  const statusSeries = STATUS_SERIES.map(({ key, label, color }) => {
    const m = metrics.data?.metrics.find((x) => x.key === key);
    return { label, points: m?.points ?? [], color };
  }).filter((s) => s.points.length > 0);

  return (
    <div className="space-y-3">
      <GradingCard window={win} />

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
          basis="metrics.k8s.io 는 이력을 남기지 않아, 이 대시보드가 켜져 있는 동안 3초마다 기록한 값 · limit 이 없는 컨테이너는 비율을 낼 수 없어 선이 없음"
          right={<ErrorNote error={kube.data?.podResourceError ?? history.error} />}
        >
          <UsageCharts
            cpu={history.data?.podCpu ?? []}
            mem={history.data?.podMem ?? []}
            now={(kube.data?.podResources ?? []).map((p) => ({
              name: p.pod,
              cpuPct: p.cpuPct,
              memPct: p.memPct,
              detail: `${(p.cpuUsageMilli / 1000).toFixed(2)} core · ${(p.memUsageBytes / 1024 / 1024).toFixed(0)}Mi`,
            }))}
            loading={kube.loading}
          />
        </Card>

        <Card
          title="Node 리소스 사용률 (CPU/Memory)"
          basis="metrics.k8s.io 는 이력을 남기지 않아, 이 대시보드가 켜져 있는 동안 3초마다 기록한 값 · 선이 끊긴 구간은 사용량 0 이 아니라 대시보드가 꺼져 있던 구간"
          right={<ErrorNote error={kube.data?.nodeResourceError ?? history.error} />}
        >
          <UsageCharts
            cpu={history.data?.nodeCpu ?? []}
            mem={history.data?.nodeMem ?? []}
            now={(kube.data?.nodeResources ?? []).map((n) => ({
              name: n.name,
              cpuPct: n.cpuPct,
              memPct: n.memPct,
              detail: `${(n.cpuUsageMilli / 1000).toFixed(2)}/${(n.cpuCapacityMilli / 1000).toFixed(1)} core · ${(n.memUsageBytes / 1024 ** 3).toFixed(2)}/${(n.memCapacityBytes / 1024 ** 3).toFixed(2)}Gi`,
            }))}
            loading={kube.loading}
          />
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card
          title="Target Group별 지표"
          basis={metrics.data ? `조회 구간 ${metrics.data.window.label}` : undefined}
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

          {/* The table says which Target Group is slow now; this says since
              when, and whether the others moved with it. Split by unit —
              seconds and req/min on one axis would flatten whichever is
              smaller into the baseline. */}
          {tgSeries.trt.length > 0 && (
            <div className="mt-3 space-y-3">
              <div>
                <div className="mb-1 font-mono text-[10px] text-neutral-500">
                  TargetResponseTime (s) — Target Group별
                </div>
                <TimeChart height={160} syncKey="perf" series={tgSeries.trt} />
              </div>
              <div>
                <div className="mb-1 font-mono text-[10px] text-neutral-500">
                  4XX · 5XX (req/min) — Target Group별
                </div>
                <TimeChart height={160} syncKey="perf" series={tgSeries.errors} />
              </div>
            </div>
          )}
        </Card>

        <Card
          title="Status Code 분포"
          basis={
            metrics.data
              ? `ALB 메트릭 · ${metrics.data.metrics[0]?.basis ?? ""} · 조회 구간 ${metrics.data.window.label}`
              : undefined
          }
        >
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

          {/* The bars are the mix at one instant. A 5XX share that has been
              flat all hour and one that appeared four minutes ago are the same
              bar and different incidents. */}
          {statusSeries.length > 0 && (
            <div className="mt-3">
              <div className="mb-1 font-mono text-[10px] text-neutral-500">
                상태코드 추이 (req/min)
              </div>
              <TimeChart height={160} syncKey="perf" series={statusSeries} />
            </div>
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
