"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { getPodLogsAction } from "@/app/actions/dashboard";
import type { KubePanel, MetricsPanel, PodLogsResult, WindowSelection } from "@/lib/types";
import type { PodSelection } from "./DashboardClient";
import { RequestLogPanel } from "./RequestLogPanel";
import { TimeChart } from "./TimeChart";
import {
  Card,
  ErrorNote,
  SectionLoading,
  Truncate,
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

// What is arriving right now, in one tab: which paths and query strings the WAF
// saw, which User-Agents (the only list that leads to a rule), the app's own
// request lines, and the pod terminal underneath them.
//
// The path list is watch-only. Undefined paths are answered by the ALB with a
// 404 already, so a 의심 path is a cue to check that it really ended in 404 —
// not a cue to write a WAF rule (see 04).
export function TrafficTab({
  kube,
  metrics,
  selection,
  onSelect,
  onMakeUaRule,
  window: win,
}: {
  kube: PollState<KubePanel>;
  metrics: PollState<MetricsPanel>;
  selection: PodSelection | null;
  onSelect: (s: PodSelection | null) => void;
  // The one path from here into 규칙 생성: a scanner User-Agent.
  onMakeUaRule: () => void;
  // The page's shared window — the log queries cover exactly the span the
  // metric charts do, so a spike and the lines around it line up.
  window: WindowSelection;
}) {
  const summary = metrics.data?.httpSummary ?? null;
  const wafSeries = (["wafBlocked", "wafAllowed"] as const)
    .map((key, i) => {
      const m = metrics.data?.metrics.find((x) => x.key === key);
      return {
        label: key === "wafBlocked" ? "Blocked" : "Allowed",
        points: m?.points ?? [],
        color: i === 0 ? "#ff5c5c" : "#3ddc97",
      };
    })
    .filter((s) => s.points.length > 0);
  const pods = kube.data?.pods ?? [];
  const [previous, setPrevious] = useState(false);
  const [tailLines, setTailLines] = useState(200);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [search, setSearch] = useState("");
  const [hideTs, setHideTs] = useState(false);
  const [onlyProblems, setOnlyProblems] = useState(false);

  // Arriving here from another tab's "로그" button should land on the terminal,
  // not at the top of the page.
  const logTerminalRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!selection?.pod) return;
    logTerminalRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [selection?.pod]);

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
      return getPodLogsAction({
        pod: selection.pod,
        container,
        previous,
        tailLines,
        window: win,
      });
    },
    autoRefresh ? 30_000 : 3_600_000,
    Boolean(selection?.pod),
    [selection?.pod, container, previous, tailLines, win.windowMin, win.intervalMin],
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

  const totalLines = logs.data?.lines.length ?? 0;
  const filtered = onlyProblems || search.length > 0;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card title="경로별 요청·차단" right={<ErrorNote error={metrics.data?.httpSummaryError ?? null} />}>
          <div className="max-h-56 space-y-0.5 overflow-y-auto text-[11px]">
            {(summary?.byPath ?? []).map((p) => (
              <div
                key={p.path}
                className={`flex justify-between gap-2 rounded px-1.5 py-0.5 ${p.blocked > 0 ? "bg-red-950/30" : "bg-neutral-950"}`}
              >
                <span className={`truncate ${p.lowPriority ? "text-neutral-600" : "text-neutral-300"}`}>
                  {p.suspicious && (
                    <span className="mr-1 rounded-[3px] bg-red-900 px-1 font-mono text-[9px] font-bold text-red-200">
                      의심
                    </span>
                  )}
                  {p.path || "/"}
                </span>
                <span className="tabular-nums text-neutral-500">
                  {p.count}
                  {p.blocked > 0 && <span className="text-red-400"> · 차단 {p.blocked}</span>}
                </span>
              </div>
            ))}
            {(summary?.byPath.length ?? 0) === 0 && <div className="text-neutral-600">데이터 없음</div>}
          </div>
        </Card>

        {/* The only list here that leads anywhere: a scanner UA is the one thing
            04 still blocks by hand. */}
        <Card
          title="User-Agent"
          right={
            <button
              type="button"
              onClick={onMakeUaRule}
              className="rounded bg-neutral-800 px-2 py-0.5 text-[11px] text-neutral-200 hover:bg-neutral-700"
            >
              규칙 만들기
            </button>
          }
        >
          <div className="max-h-56 space-y-0.5 overflow-y-auto text-[11px]">
            {(summary?.byUa ?? []).map((u, i) => (
              <div
                key={i}
                className="flex justify-between gap-2 rounded bg-neutral-950 px-1.5 py-0.5 text-neutral-300"
              >
                <span className="truncate">{u.key || "(empty)"}</span>
                <span className="tabular-nums text-neutral-500">{u.count}</span>
              </div>
            ))}
            {(summary?.byUa.length ?? 0) === 0 && <div className="text-neutral-600">데이터 없음</div>}
          </div>
        </Card>

        <Card title="QueryString 패턴">
          <div className="max-h-56 space-y-0.5 overflow-y-auto text-[11px]">
            {(summary?.queryPatterns ?? []).map((q, i) => (
              <div
                key={i}
                className="flex justify-between gap-2 rounded bg-neutral-950 px-1.5 py-0.5 text-neutral-300"
              >
                <span className="truncate">{q.key || "(empty)"}</span>
                <span className="tabular-nums text-neutral-500">{q.count}</span>
              </div>
            ))}
            {(summary?.queryPatterns.length ?? 0) === 0 && (
              <div className="text-neutral-600">데이터 없음</div>
            )}
          </div>
        </Card>
      </div>

      <RequestLogPanel window={win} />

      {wafSeries.length > 0 && (
        <Card title="WAF Blocked / Allowed 추이">
          <TimeChart height={160} syncKey="traffic" series={wafSeries} />
        </Card>
      )}

      <div ref={logTerminalRef} className="scroll-mt-4">
        <Card
          title="Log Terminal"
          right={
            <div className="flex items-center gap-2 text-[11px]">
              <select
                value={selection?.pod ?? ""}
                onChange={(e) => {
                  const p = pods.find((x) => x.name === e.target.value);
                  onSelect(
                    e.target.value
                      ? { pod: e.target.value, container: p?.containers[0]?.name ?? "" }
                      : null,
                  );
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
                onChange={(e) =>
                  selection && onSelect({ pod: selection.pod, container: e.target.value })
                }
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
                <input
                  type="checkbox"
                  checked={previous}
                  onChange={(e) => setPrevious(e.target.checked)}
                />
                Previous
              </label>
              <label className="flex items-center gap-1 text-neutral-400">
                <input
                  type="checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                />
                자동갱신(30s)
              </label>
              <label className="flex items-center gap-1 text-neutral-400">
                <input
                  type="checkbox"
                  checked={onlyProblems}
                  onChange={(e) => setOnlyProblems(e.target.checked)}
                />
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
              {/* The terminal filters in the browser, so say which number is
                  which rather than letting the visible count read as the total. */}
              {filtered
                ? ` · 표시 ${filteredLines.length}줄 / 조회 ${totalLines}줄 (브라우저 필터)`
                : ` · ${totalLines}줄`}
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
      </div>

      <Card title="Top Errors / Fingerprints (선택 Pod 기준)">
        {kube.loading && !logs.data ? (
          <SectionLoading />
        ) : (
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
        )}
      </Card>

    </div>
  );
}
