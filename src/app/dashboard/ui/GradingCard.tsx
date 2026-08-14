"use client";

import { getGradingPanelAction } from "@/lib/api/dashboard";
import type { GradingPanel, WindowSelection } from "@/lib/types";
import { Card, ErrorNote, SectionLoading, Stat, fmtBytes, usePoll, type PollState } from "./shared";

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
          {/* What this panel cost, as a number rather than a footnote: Logs
              Insights bills per byte scanned, so it is a first-class figure on
              a screen whose refresh button spends money. */}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat
              label="Insights 스캔량"
              value={fmtBytes(data.scannedBytes)}
              copy={String(data.scannedBytes)}
              basis={`이 조회 1건 · ${data.source}`}
            />
            <Stat
              label="집계 구간"
              value={data.window.label}
              basis={`${data.window.buckets}개 버킷 · ${data.window.intervalMin}분 간격`}
            />
            <Stat
              label="관측 요청"
              value={data.lines.reduce((a, l) => a + l.total, 0).toLocaleString("ko-KR")}
              unit="건"
              basis="아래 채점 키 분모의 합 · 같은 요청이 두 키에 들어가지는 않음"
            />
            <Stat
              label="채점 키"
              value={String(data.lines.length)}
              unit="개"
              basis="채점기 키 순서대로 정렬 · 점수는 매기지 않음"
            />
          </div>

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
