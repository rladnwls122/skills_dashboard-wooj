"use client";

import { useEffect, useState } from "react";
import { getRequestLogRowsAction } from "@/lib/api/dashboard";
import type { RequestLogQueryResult, RequestLogRow, WindowSelection } from "@/lib/types";
import {
  Card,
  Counts,
  DetailModal,
  ErrorNote,
  LastUpdated,
  SectionLoading,
  Truncate,
  fmtBytes,
  fmtTs,
  usePoll,
  type PollState,
} from "./shared";

// How often the tail re-queries with auto-refresh on. Matches the pod-log
// terminal and POLLING.logAutoRefreshMs — Logs Insights bills per byte scanned,
// so this is the floor, not a target.
const AUTO_REFRESH_MS = 30_000;
const MANUAL_MS = 3_600_000;

const CLASSES = ["ALL", "2xx", "3xx", "4xx", "5xx"] as const;
type StatusClass = (typeof CLASSES)[number];

const LABEL: Record<StatusClass, string> = {
  ALL: "전체",
  "2xx": "2xx",
  "3xx": "3xx",
  "4xx": "4xx",
  "5xx": "5xx",
};

function statusColor(status: number): string {
  if (status >= 500) return "text-red-400";
  if (status >= 400) return "text-amber-400";
  if (status >= 300) return "text-neutral-300";
  return "text-emerald-400";
}

export function RequestLogPanel({ window: win }: { window: WindowSelection }) {
  const [statusClass, setStatusClass] = useState<StatusClass>("ALL");
  const [pathInput, setPathInput] = useState("");
  const [pathQuery, setPathQuery] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  // The row whose full line is open. Headers are why: the table shows the
  // User-Agent because that is the one that decides a rule, and the line
  // behind it holds whatever else the app logged.
  const [detail, setDetail] = useState<RequestLogRow | null>(null);

  // Debounce the free-text path so typing does not fire one Insights query
  // per keystroke.
  useEffect(() => {
    const id = setTimeout(() => setPathQuery(pathInput), 400);
    return () => clearTimeout(id);
  }, [pathInput]);

  // This used to fetch on mount and on a filter change only, with the window
  // captured in a closure that never updated — so the tail simply aged on
  // screen, and "the log is two minutes behind" was however long you had been
  // looking at it. usePoll re-queries on its own timer and re-runs whenever a
  // listed input changes, which is also what makes a span change take effect.
  const poll: PollState<RequestLogQueryResult> = usePoll(
    () =>
      getRequestLogRowsAction({
        statusClass,
        pathContains: pathQuery,
        window: win,
      }),
    autoRefresh ? AUTO_REFRESH_MS : MANUAL_MS,
    true,
    [statusClass, pathQuery, win.windowMin, win.intervalMin],
  );
  const { data, error, loading, refresh } = poll;

  const rows = data?.rows ?? [];

  return (
    <Card
      title={`앱 요청 로그 (${rows.length})`}
      right={
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <ErrorNote error={error} />
          {CLASSES.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => setStatusClass(c)}
              className={`rounded px-2 py-0.5 font-mono text-[10px] ${
                statusClass === c
                  ? "bg-neutral-200 text-neutral-900"
                  : "bg-neutral-800 text-neutral-400 hover:bg-neutral-700"
              }`}
            >
              {LABEL[c]}
            </button>
          ))}
          <input
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            placeholder="경로 검색"
            className="w-32 rounded border border-neutral-700 bg-neutral-900 px-2 py-0.5"
          />
          <label className="flex items-center gap-1 text-neutral-400">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            자동갱신(30s)
          </label>
          <button
            type="button"
            onClick={refresh}
            className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
          >
            조회
          </button>
        </div>
      }
    >
      {data && (
        <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1">
          {/* Three numbers, stated separately: how many matched in the window,
              how many came back under the row cap, how many are drawn. */}
          <Counts
            total={data.totalMatched}
            fetched={rows.length}
            shown={rows.length}
            cap={data.truncated ? rows.length : undefined}
          />
          <span className="font-mono text-[10px] text-neutral-600">
            창 {data.windowLabel} · Logs Insights 스캔 {fmtBytes(data.scannedBytes)} · 헬스체크 제외
          </span>
          {/* Two clocks, because they answer different questions. The fetch time
              says whether the panel is stale; the newest row says whether the
              traffic is. A parse-heavy Insights scan does not return the last
              ~2 minutes of a busy log group, so a gap of a couple of minutes is
              the source's indexing delay — a gap of ten is traffic that
              stopped, and reading one as the other costs the whole diagnosis. */}
          {rows[0] && (
            <span className="font-mono text-[10px] text-neutral-600">
              최신 로그 {fmtTs(rows[0].ts)}
            </span>
          )}
          <LastUpdated at={poll.lastUpdated} label="조회" />
          {(data.uaJoined > 0 || data.uaJoinNote) && (
            <span className="font-mono text-[10px] text-neutral-600">
              {data.uaJoined > 0 && `UA 결합 ${data.uaJoined}건 (requestid 기준)`}
              {data.uaJoinNote && ` · ${data.uaJoinNote}`}
            </span>
          )}
        </div>
      )}
      {loading && rows.length === 0 ? (
        <SectionLoading />
      ) : (
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-left font-mono text-[10px]">
            <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
              <tr>
                {/* No User-Agent column: the app does not log one, so it was a
                    column of dashes for every row. The joined value still opens
                    with the row, and the WAF log panel below has it natively. */}
                {["시각", "메소드", "경로", "상태", "지연(ms)"].map((h) => (
                  <th key={h} className="px-2 py-1 font-medium whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr
                  key={i}
                  onClick={() => setDetail(r)}
                  title="클릭하면 로그 원문(전체 헤더)"
                  className="cursor-pointer border-t border-neutral-800 text-neutral-300 hover:bg-neutral-800/60"
                >
                  <td className="px-2 py-0.5 whitespace-nowrap text-neutral-500">{fmtTs(r.ts)}</td>
                  <td className="px-2 py-0.5">{r.method}</td>
                  <td className="px-2 py-0.5">
                    <Truncate text={r.path} className="max-w-64" />
                  </td>
                  <td className={`px-2 py-0.5 font-bold tabular-nums ${statusColor(r.status)}`}>
                    {r.status}
                  </td>
                  <td className="px-2 py-0.5 tabular-nums text-neutral-500">{r.latencyMs}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && !error && (
            <div className="p-3 text-center text-[11px] text-neutral-500">
              {loading ? (
                "조회 중…"
              ) : (
                <>
                  <div>조건에 맞는 요청 없음 (구간 전체를 검색한 결과)</div>
                  {/* The usual reason a path that is obviously in the WAF panel
                      finds nothing here: WAF cut it before the app saw it. */}
                  {pathQuery && (
                    <div className="mt-1 text-neutral-600">
                      WAF 가 차단한 요청은 앱에 도달하지 않아 앱 로그에 없습니다 — 차단된 경로는 위
                      글로벌 요청·차단 패널에서 보세요.
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}

      {detail && (
        <DetailModal title="요청 로그 원문" onClose={() => setDetail(null)}>
          <dl className="space-y-1 font-mono text-[10px]">
            {(
              [
                ["시각", fmtTs(detail.ts)],
                ["요청", `${detail.method} ${detail.path}`],
                ["상태", `${detail.status} · ${detail.latencyMs}ms`],
                ["requestid", detail.requestId || "(앱이 기록하지 않음 — POST·PUT)"],
                [
                  "User-Agent",
                  detail.userAgent
                    ? `${detail.userAgent}${detail.uaSource === "waf" ? " (WAF 로그에서 requestid 로 결합)" : ""}`
                    : "(앱 로그에 없고 WAF 로그에서도 결합되지 않음)",
                ],
              ] as [string, string][]
            ).map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <dt className="w-20 shrink-0 text-neutral-500">{k}</dt>
                <dd className="min-w-0 break-all text-neutral-200">{v}</dd>
              </div>
            ))}
          </dl>
          <div className="mt-2 text-[10px] text-neutral-500">
            로그 원문 — 앱이 남긴 헤더는 여기 그대로 있습니다 (민감값은 마스킹됨).
          </div>
          <pre className="mt-1 rounded bg-black p-2 font-mono text-[10px] leading-4 break-all whitespace-pre-wrap text-neutral-300">
            {detail.raw || "(원문 없음)"}
          </pre>
        </DetailModal>
      )}
    </Card>
  );
}
