"use client";

import { useMemo, useState } from "react";
import { getPodLogsAction } from "@/app/actions/dashboard";
import type { KubePanel, MetricsPanel, PodLogsResult, WarningEvent } from "@/lib/types";
import type { PodSelection } from "./DashboardClient";
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

const RED = /(error|fatal|exception|\b50\d\b|\b5xx\b)/i;
const ORANGE = /(warn|warning|timeout|\b429\b|\b4\d{2}\b|\b4xx\b)/i;
const YELLOW = /(retry|backoff|connection refused|oom)/i;

const LINE_TS_RE = /^\d{4}-\d{2}-\d{2}T(\d{2}:\d{2}:\d{2})(?:\.\d+)?Z?\s([\s\S]*)$/;

function splitLineTs(line: string): { ts: string | null; rest: string } {
  const m = line.match(LINE_TS_RE);
  if (!m) return { ts: null, rest: line };
  return { ts: m[1] ?? null, rest: m[2] ?? "" };
}

function isProblemLine(line: string): boolean {
  return RED.test(line) || ORANGE.test(line) || YELLOW.test(line);
}

function lineColor(line: string): string {
  if (RED.test(line)) return "text-red-400";
  if (ORANGE.test(line)) return "text-orange-400";
  if (YELLOW.test(line)) return "text-yellow-300";
  return "text-neutral-300";
}

function fmtScanBytes(n: number): string {
  if (n >= 1024 * 1024 * 1024) return `${(n / 1024 / 1024 / 1024).toFixed(2)}GB`;
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)}MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${n}B`;
}

function UsageBar({ label, pct }: { label: string; pct: number | null }) {
  const color = pct === null ? "bg-neutral-700" : pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-amber-500" : "bg-emerald-500";
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

export function InvestigationTab({
  kube,
  metrics,
  selection,
  onSelect,
}: {
  kube: PollState<KubePanel>;
  metrics: PollState<MetricsPanel>;
  selection: PodSelection | null;
  onSelect: (s: PodSelection | null) => void;
}) {
  const pods = kube.data?.pods ?? [];
  const [previous, setPrevious] = useState(false);
  const [tailLines, setTailLines] = useState(200);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [search, setSearch] = useState("");
  const [hideTs, setHideTs] = useState(false);
  const [onlyProblems, setOnlyProblems] = useState(false);
  const [eventDetail, setEventDetail] = useState<WarningEvent | null>(null);

  const selectedPod = pods.find((p) => p.name === selection?.pod);
  const container =
    selection?.container && selectedPod?.containers.some((c) => c.name === selection.container)
      ? selection.container
      : (selectedPod?.containers[0]?.name ?? "");

  const logs: PollState<PodLogsResult> = usePoll(
    async () => {
      if (!selection?.pod || !container) {
        return { ok: false as const, error: "Pod를 선택하세요" };
      }
      return getPodLogsAction({ pod: selection.pod, container, previous, tailLines });
    },
    autoRefresh ? 30_000 : 3_600_000,
    Boolean(selection?.pod),
  );

  const filteredLines = useMemo(() => {
    let lines = logs.data?.lines ?? [];
    if (onlyProblems) lines = lines.filter(isProblemLine);
    if (search) {
      const q = search.toLowerCase();
      lines = lines.filter((l) => l.toLowerCase().includes(q));
    }
    return lines;
  }, [logs.data, search, onlyProblems]);

  const httpSummary = metrics.data?.httpSummary ?? null;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card title="Detected Anomalies" right={<ErrorNote error={metrics.error} />}>
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

        <Card title="Pod 개수 (최소/현재/최대)" right={<ErrorNote error={kube.data?.scalingError ?? null} />}>
          <div className="max-h-40 space-y-1 overflow-y-auto text-[11px]">
            {(kube.data?.podScaling ?? []).map((s) => (
              <div key={s.name} className="flex items-center justify-between rounded bg-neutral-950 px-2 py-1">
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
              <div key={s.name} className="flex items-center justify-between rounded bg-neutral-950 px-2 py-1">
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
                  {["Pod", "상태", "Ready", "재시작", "CPU req/lim", "Mem req/lim", "Pod IP", "Node", "로그"].map(
                    (h) => (
                      <th key={h} className="px-2 py-1 font-medium">
                        {h}
                      </th>
                    ),
                  )}
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
                      <td className={`px-2 py-1 ${bad ? "font-semibold text-red-400" : "text-emerald-400"}`}>
                        {p.statusLabel}
                        {p.reason && <span className="ml-1 text-neutral-500">({p.reason})</span>}
                      </td>
                      <td className="px-2 py-1 tabular-nums">{p.ready}</td>
                      <td className="px-2 py-1 tabular-nums">
                        {p.totalRestarts}
                        {p.recentRestartIncrease > 0 && (
                          <span className="ml-1 font-bold text-amber-400">+{p.recentRestartIncrease}</span>
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
                          onClick={() => onSelect({ pod: p.name, container: c0?.name ?? "" })}
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
        <Card title="Pod 리소스 사용률 (CPU/Memory)" right={<ErrorNote error={kube.data?.podResourceError ?? null} />}>
          <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
            {(kube.data?.podResources ?? []).map((p) => (
              <div key={p.pod} className="rounded bg-neutral-950 px-2 py-1">
                <div className="flex justify-between text-neutral-300">
                  <Truncate text={p.pod} />
                  <span className="tabular-nums text-neutral-500">
                    {(p.cpuUsageMilli / 1000).toFixed(2)} core · {(p.memUsageBytes / 1024 / 1024).toFixed(0)}Mi
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

        <Card title="Node 리소스 사용률 (CPU/Memory)" right={<ErrorNote error={kube.data?.nodeResourceError ?? null} />}>
          <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
            {(kube.data?.nodeResources ?? []).map((n) => (
              <div key={n.name} className="rounded bg-neutral-950 px-2 py-1">
                <div className="flex justify-between text-neutral-300">
                  <Truncate text={n.name} />
                  <span className="tabular-nums text-neutral-500">
                    {(n.cpuUsageMilli / 1000).toFixed(2)}/{(n.cpuCapacityMilli / 1000).toFixed(1)} core ·{" "}
                    {(n.memUsageBytes / 1024 / 1024 / 1024).toFixed(2)}/
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

      <Card title="Target Group별 지표" right={<ErrorNote error={metrics.data?.targetGroupError ?? null} />}>
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
          {(metrics.data?.targetGroupMetrics.length ?? 0) === 0 && !metrics.data?.targetGroupError && (
            <div className="p-2 text-[11px] text-neutral-500">수집 중…</div>
          )}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
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
                    <td className="px-2 py-1 whitespace-nowrap text-neutral-500">{fmtTs(e.timestamp)}</td>
                    <td className="px-2 py-1 text-neutral-300">
                      {e.kind}/{e.name}
                    </td>
                    <td className={`px-2 py-1 ${e.highlighted ? "font-semibold text-amber-400" : ""}`}>
                      {e.reason}
                    </td>
                    <td className="max-w-64 px-2 py-1 text-neutral-400">
                      <Truncate text={e.message} />
                    </td>
                    <td className="px-2 py-1 tabular-nums">{e.count}</td>
                    <td className="px-2 py-1">
                      {e.isPod && (
                        <button
                          type="button"
                          onClick={(ev) => {
                            ev.stopPropagation();
                            onSelect({ pod: e.name, container: "" });
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

        <Card title="Top Errors / Fingerprints (선택 Pod 기준)">
          <div className="max-h-64 space-y-1 overflow-y-auto text-[11px]">
            {(logs.data?.fingerprints ?? []).map((f, i) => (
              <div key={i} className="rounded border border-neutral-800 bg-neutral-950 p-2">
                <div className="flex justify-between">
                  <span className="font-bold text-red-400">×{f.count}</span>
                  <span className="text-neutral-600">
                    {fmtTs(f.firstSeen)} ~ {fmtTs(f.lastSeen)} · {f.pods.join(", ")}
                  </span>
                </div>
                <code className="mt-1 block break-all text-neutral-300">{f.fingerprint}</code>
              </div>
            ))}
            {(logs.data?.fingerprints.length ?? 0) === 0 && (
              <div className="text-neutral-500">Pod 로그를 조회하면 반복 오류가 집계됩니다</div>
            )}
          </div>
        </Card>
      </div>

      <Card
        title="Log Terminal"
        right={
          <div className="flex items-center gap-2 text-[11px]">
            <select
              value={selection?.pod ?? ""}
              onChange={(e) => {
                const p = pods.find((x) => x.name === e.target.value);
                onSelect(e.target.value ? { pod: e.target.value, container: p?.containers[0]?.name ?? "" } : null);
              }}
              className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1"
            >
              <option value="">Pod 선택</option>
              {pods.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                </option>
              ))}
            </select>
            <select
              value={container}
              onChange={(e) => selection && onSelect({ pod: selection.pod, container: e.target.value })}
              className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1"
            >
              {(selectedPod?.containers ?? []).map((c) => (
                <option key={c.name} value={c.name}>
                  {c.name}
                </option>
              ))}
            </select>
            <select
              value={tailLines}
              onChange={(e) => setTailLines(Number(e.target.value))}
              className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1"
            >
              {[100, 200, 500, 1000].map((n) => (
                <option key={n} value={n}>
                  tail {n}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1 text-neutral-400">
              <input type="checkbox" checked={previous} onChange={(e) => setPrevious(e.target.checked)} />
              Previous
            </label>
            <label className="flex items-center gap-1 text-neutral-400">
              <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
              자동갱신(30s)
            </label>
            <label className="flex items-center gap-1 text-neutral-400">
              <input type="checkbox" checked={onlyProblems} onChange={(e) => setOnlyProblems(e.target.checked)} />
              문제만
            </label>
            <label className="flex items-center gap-1 text-neutral-400">
              <input type="checkbox" checked={hideTs} onChange={(e) => setHideTs(e.target.checked)} />
              시간 숨김
            </label>
            <button
              type="button"
              onClick={logs.refresh}
              className="rounded bg-neutral-800 px-2 py-1 text-neutral-300 hover:bg-neutral-700"
            >
              조회
            </button>
          </div>
        }
      >
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="로그 검색 (즉시 필터)"
          className="mb-2 w-full rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs"
        />
        {logs.data && (
          <div className="mb-1 font-mono text-[10px] text-neutral-600">
            소스{" "}
            {logs.data.source === "insights"
              ? `CloudWatch Logs Insights · 조회창 ${logs.data.windowLabel} · 스캔 ${fmtScanBytes(logs.data.scannedBytes ?? 0)}`
              : "Kubernetes API (Insights 폴백/이전 컨테이너)"}
          </div>
        )}
        <div className="h-80 overflow-y-auto rounded bg-black p-2 font-mono text-[11px] leading-4">
          {logs.error && <div className="text-red-400">{logs.error}</div>}
          {!logs.error && filteredLines.length === 0 && (
            <div className="text-neutral-600">
              {selection?.pod
                ? search
                  ? "검색 결과 없음"
                  : previous
                    ? "이전 컨테이너 로그 없음 (재시작 이력 없는 Pod일 수 있음)"
                    : "로그 없음 — 조회 버튼을 누르세요"
                : "Pod를 선택하세요"}
            </div>
          )}
          {filteredLines.map((line, i) => {
            const { ts, rest } = splitLineTs(line);
            return (
              <div key={i} className="flex gap-2">
                {!hideTs && (
                  <span className="shrink-0 tabular-nums text-neutral-600 select-none">
                    {ts ?? "        "}
                  </span>
                )}
                <span className={`whitespace-pre-wrap break-all ${lineColor(line)}`}>{rest}</span>
              </div>
            );
          })}
        </div>
      </Card>

      <Card title="요청 로그 분석 (선택 Pod — Latency / Non-2xx / Error·Warn)">
        {logs.data?.requestLog ? (
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <div>
              <div className="mb-1 text-[11px] text-neutral-500">
                평균 latency {logs.data.requestLog.avgLatencyMs ?? "-"}ms · 최대{" "}
                {logs.data.requestLog.maxLatencyMs ?? "-"}ms · 요청{" "}
                {logs.data.requestLog.totalRequests ?? logs.data.requestLog.entries.length}건
                {logs.data.requestLog.basis && (
                  <span className="text-neutral-600"> · 기준: {logs.data.requestLog.basis}</span>
                )}
              </div>
              <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
                {logs.data.requestLog.byPath.map((p) => (
                  <div key={p.path} className="flex justify-between rounded bg-neutral-950 px-2 py-1">
                    <Truncate text={p.path} className="text-neutral-300" />
                    <span className="tabular-nums text-neutral-500">
                      {p.count}건 · avg {p.avgLatencyMs}ms · max {p.maxLatencyMs}ms
                      {p.nonOkCount > 0 && <span className="text-amber-400"> · non-2xx {p.nonOkCount}</span>}
                    </span>
                  </div>
                ))}
                {logs.data.requestLog.byPath.length === 0 && (
                  <div className="text-neutral-500">파싱된 요청 없음</div>
                )}
              </div>
            </div>
            <div>
              <div className="mb-1 text-[11px] text-neutral-500">
                200/201 이외 응답 (
                {logs.data.requestLog.nonOkTotal ?? logs.data.requestLog.nonOkEntries.length}건)
              </div>
              <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
                {logs.data.requestLog.nonOkEntries.map((e, i) => (
                  <div key={i} className="flex justify-between rounded bg-amber-950/30 px-2 py-1 text-amber-300">
                    <span>
                      {e.method} {e.path}
                    </span>
                    <span className="tabular-nums">
                      {e.status} · {e.latencyMs}ms
                    </span>
                  </div>
                ))}
                {logs.data.requestLog.nonOkEntries.length === 0 && (
                  <div className="text-neutral-500">없음</div>
                )}
              </div>
            </div>
            <div>
              <div className="mb-1 text-[11px] text-neutral-500">
                Error/Warn 로그 (
                {logs.data.requestLog.errorWarnTotal ?? logs.data.requestLog.errorWarnLines.length}
                건)
              </div>
              <div className="max-h-56 space-y-1 overflow-y-auto font-mono text-[11px]">
                {logs.data.requestLog.errorWarnLines.map((l, i) => (
                  <div key={i} className={`break-all ${lineColor(l)}`}>
                    {l}
                  </div>
                ))}
                {logs.data.requestLog.errorWarnLines.length === 0 && (
                  <div className="text-neutral-500">없음</div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-[11px] text-neutral-500">Pod 로그를 조회하면 분석 결과가 표시됩니다</div>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card title="HTTP Path 분석">
          {httpSummary ? (
            <div className="max-h-56 space-y-1 overflow-y-auto text-[11px]">
              <div className="mb-1 text-neutral-600">{httpSummary.source}</div>
              {httpSummary.byPath.map((p) => {
                const suspicious =
                  !p.lowPriority &&
                  p.count >= 30 &&
                  p.count / Math.max(httpSummary.totalSampled, 1) >= 0.5;
                return (
                  <div key={p.path} className="flex justify-between gap-2">
                    <span className={`truncate ${p.lowPriority ? "text-neutral-600" : "text-neutral-300"}`}>
                      {suspicious && (
                        <span className="mr-1 rounded-[3px] bg-red-900 px-1 font-mono text-[9px] font-bold text-red-200">
                          의심
                        </span>
                      )}
                      {p.path || "/"}
                      {p.lowPriority && " (헬스체크)"}
                    </span>
                    <span className="tabular-nums text-neutral-400">
                      {p.count}건{p.blocked > 0 && <span className="text-red-400"> 차단{p.blocked}</span>}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-[11px] text-neutral-500">
              {metrics.data?.httpSummaryError ?? "수집 중…"}
            </div>
          )}
        </Card>

        <Card title="Status Code 분포 (분당)">
          {httpSummary?.statusDist ? (
            <div className="space-y-2 text-[11px]">
              {(
                [
                  ["2xx", httpSummary.statusDist.c2xx, "bg-emerald-600"],
                  ["3xx", httpSummary.statusDist.c3xx, "bg-sky-600"],
                  ["4xx", httpSummary.statusDist.c4xx, "bg-amber-600"],
                  ["5xx", httpSummary.statusDist.c5xx, "bg-red-600"],
                ] as const
              ).map(([label, v, color]) => {
                const total =
                  httpSummary.statusDist!.c2xx +
                  httpSummary.statusDist!.c3xx +
                  httpSummary.statusDist!.c4xx +
                  httpSummary.statusDist!.c5xx;
                const pct = total > 0 ? Math.round((v / total) * 100) : 0;
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
                코드별(400/403/429/500/502/503/504…) 세분화는 ALB 메트릭 미제공 — WAF/ALB 로그 활성화 시 확장 가능
              </div>
            </div>
          ) : (
            <div className="text-[11px] text-neutral-500">ALB 메트릭 수집 중…</div>
          )}
        </Card>

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
      </div>

      {eventDetail && (
        <WarningEventDetailModal
          event={eventDetail}
          onClose={() => setEventDetail(null)}
          onJumpToLogs={(pod) => onSelect({ pod, container: "" })}
        />
      )}
    </div>
  );
}
