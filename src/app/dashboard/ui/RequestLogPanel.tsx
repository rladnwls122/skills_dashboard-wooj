"use client";

import { useCallback, useEffect, useState } from "react";
import { getRequestLogRowsAction } from "@/app/actions/dashboard";
import type { RequestLogQueryResult, WindowSelection } from "@/lib/types";
import { Card, Counts, ErrorNote, SectionLoading, Truncate, fmtBytes, fmtTs } from "./shared";

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
  const [data, setData] = useState<RequestLogQueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Debounce the free-text path so typing does not fire one Insights query
  // per keystroke.
  useEffect(() => {
    const id = setTimeout(() => setPathQuery(pathInput), 400);
    return () => clearTimeout(id);
  }, [pathInput]);

  const run = useCallback(async (cls: StatusClass, path: string): Promise<void> => {
    setLoading(true);
    const res = await getRequestLogRowsAction({ statusClass: cls, pathContains: path, window: win });
    if (res.ok) {
      setData(res.data);
      setError(null);
    } else {
      setError(res.error);
    }
    setLoading(false);
  }, []);

  // Fires on mount and whenever a filter settles. Never on a timer.
  useEffect(() => {
    void run(statusClass, pathQuery);
  }, [run, statusClass, pathQuery]);

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
          <button
            type="button"
            onClick={() => void run(statusClass, pathQuery)}
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
            창 {data.windowLabel} · Logs Insights 스캔 {fmtBytes(data.scannedBytes)}
          </span>
        </div>
      )}
      {loading && rows.length === 0 ? (
        <SectionLoading />
      ) : (
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-left font-mono text-[10px]">
            <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
              <tr>
                {["시각", "메소드", "경로", "상태", "지연(ms)"].map((h) => (
                  <th key={h} className="px-2 py-1 font-medium whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-t border-neutral-800 text-neutral-300">
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
              {loading ? "조회 중…" : "조건에 맞는 요청 없음"}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
