"use client";

import { getNodeCostAction } from "@/app/actions/dashboard";
import type { NodeCountProjection } from "@/app/actions/dashboard";
import { Card, ErrorNote, SectionLoading, usePoll, type PollState } from "./shared";

// Node count over the scoring window — the cost grader's input.
//
// Two numbers carry the decision and everything else is context. `최종 평균` is
// where the window average lands if the current count is held to the end, which
// is what a scaling choice actually changes; `1대 증감` is what one instance
// moves it by right now, which shrinks as the window runs out. The running
// average is the intermediate value of the first, so it sits underneath in
// small type rather than competing for the eye.
//
// Deliberately colourless. The scoring formula is sealed, so any green here
// would be this screen inventing a verdict it cannot support. The one red is
// the off-spec list, and that is a comparison against the task's allowed set —
// a fact, not an estimate.
//
// 30s, on its own timer: node counts move in minutes, and describe-instances is
// not billed per byte the way the grading query is, so this does not have to
// share the slow tier next door.
export function NodeCostPanel() {
  const cost: PollState<NodeCountProjection> = usePoll(() => getNodeCostAction(), 30_000);
  const d = cost.data;

  const dae = (n: number | null, digits = 1): string =>
    n === null ? "—" : `${n.toFixed(digits)} 대`;

  return (
    <Card
      title="채점 창 노드 대수"
      right={
        <div className="flex items-center gap-2 text-[11px]">
          <ErrorNote error={cost.error} />
          {d?.window && d.remainingMin !== null && d.elapsedMin !== null && (
            <span className="font-mono text-[10px] text-neutral-600">
              {d.elapsedMin}분 경과 · {d.remainingMin}분 남음
            </span>
          )}
        </div>
      }
    >
      {cost.loading && !d ? (
        <SectionLoading />
      ) : !d ? (
        <div className="py-6 text-center text-[11px] text-neutral-600">읽는 중…</div>
      ) : (
        <div className="space-y-2">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <div className="rounded bg-neutral-950 p-2">
              <div className="text-[11px] text-neutral-500">최종 평균</div>
              <div className="text-lg font-bold tabular-nums text-neutral-100">
                {dae(d.finalAvg)}
              </div>
              <div className="text-[10px] text-neutral-600">
                {d.finalAvg === null ? "경기 시작 시각 미설정" : "지금 대수를 끝까지 유지했을 때"}
              </div>
            </div>
            <div className="rounded bg-neutral-950 p-2">
              <div className="text-[11px] text-neutral-500">1대 증감</div>
              <div className="text-lg font-bold tabular-nums text-neutral-100">
                {d.marginalPerInstance === null ? "—" : `±${d.marginalPerInstance.toFixed(2)} 대`}
              </div>
              <div className="text-[10px] text-neutral-600">지금 한 대를 늘리거나 줄이면</div>
            </div>
            <div className="rounded bg-neutral-950 p-2">
              <div className="text-[11px] text-neutral-500">현재 / 누적 평균</div>
              <div className="text-lg font-bold tabular-nums text-neutral-100">
                {d.current === null ? "—" : `${d.current} 대`}
              </div>
              <div className="text-[10px] text-neutral-600">누적 {dae(d.cumulativeAvg)}</div>
            </div>
          </div>

          {/* Absent when the list is empty: a line reading "규격 외 0대" is space
              spent saying nothing, and this panel is at the top of the screen. */}
          {d.offSpec.length > 0 && (
            <div className="rounded border border-red-900 bg-red-950/30 p-2 text-[11px]">
              <div className="font-semibold text-red-300">⚠ 규격 외 {d.offSpec.length}대</div>
              <ul className="mt-1 space-y-0.5 font-mono text-[10px] text-red-200">
                {d.offSpec.map((i) => (
                  <li key={i.id}>
                    {i.id} {i.name ? `(${i.name}) ` : ""}— {i.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {d.notes.length > 0 && (
            <ul className="space-y-0.5 text-[11px] text-neutral-500">
              {d.notes.map((n, i) => (
                <li key={i}>· {n}</li>
              ))}
            </ul>
          )}

          <div className="border-t border-neutral-800 pt-1 text-[10px] text-neutral-600">
            채점식은 비공개입니다. 이 패널은 채점기 입력값(대수)만 세고 점수를 만들지 않습니다.
          </div>
        </div>
      )}
    </Card>
  );
}
