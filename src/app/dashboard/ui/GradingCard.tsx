"use client";

import { getGradingPanelAction } from "@/app/actions/dashboard";
import type { GradingPanel, WindowSelection } from "@/lib/types";
import { Card, ErrorNote, SectionLoading, usePoll, type PollState } from "./shared";

function fmtBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(2)}GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)}MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(0)}KB`;
  return `${n}B`;
}

// Observed traffic lined up against the grader's metric keys. No score is
// computed here — the grade comes from the grader's own run; this only shows
// which measurement moves which key, over the page's shared window. On demand
// only: it is an Insights query, and nobody asked for it on every page load.
export function GradingCard({ window: win }: { window: WindowSelection }) {
  const grading: PollState<GradingPanel> = usePoll(
    () => getGradingPanelAction(win),
    3_600_000,
    false,
    [win.windowMin, win.intervalMin],
  );
  const data = grading.data;

  return (
    <Card
      title="채점 지표 정렬 (관측값)"
      basis={
        data
          ? `${data.source} · 구간 ${data.window.label} · 스캔 ${fmtBytes(data.scannedBytes)}`
          : "조회를 눌러야 실행됨 — Logs Insights 는 스캔 바이트당 과금"
      }
      right={
        <div className="flex items-center gap-2 text-[11px]">
          <ErrorNote error={grading.error} />
          <button
            type="button"
            onClick={grading.refresh}
            disabled={grading.loading}
            className="rounded bg-sky-900 px-2 py-0.5 font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
          >
            {grading.loading ? "집계 중…" : data ? "다시 조회" : "조회"}
          </button>
        </div>
      }
    >
      {grading.loading && !data ? (
        <SectionLoading />
      ) : !data ? (
        <div className="py-6 text-center text-[11px] text-neutral-600">
          버튼을 눌러 현재 구간의 관측값을 채점 키에 맞춰 집계
        </div>
      ) : (
        <div className="space-y-2">
          <table className="w-full text-left text-[11px]">
            <thead className="text-neutral-500">
              <tr>
                {["채점 키", "비율", "충족/전체"].map((h) => (
                  <th key={h} className="px-2 py-1 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.lines.map((l) => {
                const none = l.total === 0;
                return (
                  <tr key={l.label} className="border-t border-neutral-800">
                    <td className="px-2 py-1 font-mono text-neutral-200">{l.label}</td>
                    <td
                      className={`px-2 py-1 tabular-nums ${
                        none ? "text-neutral-600" : l.pct >= 90 ? "text-emerald-400" : l.pct >= 50 ? "text-amber-400" : "text-red-400"
                      }`}
                    >
                      {none ? "—" : `${l.pct}%`}
                    </td>
                    <td className="px-2 py-1 tabular-nums text-neutral-500">
                      {none
                        ? "요청 없음"
                        : `${l.okCount.toLocaleString()} / ${l.total.toLocaleString()}`}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <ul className="space-y-0.5 text-[11px] text-neutral-500">
            {data.notes.map((n, i) => (
              <li key={i}>· {n}</li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}
