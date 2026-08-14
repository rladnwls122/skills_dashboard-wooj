"use client";

import { useEffect, useState } from "react";
import { getWafLogRowsAction } from "@/app/actions/dashboard";
import type { WafLogQueryResult, WafLogRow, WindowSelection } from "@/lib/types";
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

const ACTIONS = ["ALL", "BLOCK", "ALLOW", "COUNT"] as const;
type ActionFilter = (typeof ACTIONS)[number];

const LABEL: Record<ActionFilter, string> = {
  ALL: "전체",
  BLOCK: "Block",
  ALLOW: "Allow",
  COUNT: "Count",
};

const AUTO_REFRESH_MS = 30_000;
const MANUAL_MS = 3_600_000;

function actionColor(action: string): string {
  if (action === "BLOCK") return "text-red-400";
  if (action === "COUNT") return "text-amber-400";
  if (action === "ALLOW") return "text-emerald-400";
  return "text-neutral-300";
}

// The request as the WAF saw it, one row per request.
//
// This is the panel that answers a disputed block. The app's request log stops
// at the origin, so a request WAF cut never appears in it — "왜 403 이 나갔나"
// has no answer there, and the aggregate panels only say how many. Here the
// terminating rule is on the row: a managed rule group reports the group name,
// so the sub-rule is shown beside it, because that is the name an override or a
// scope-down has to reference.
export function WafLogPanel({ window: win }: { window: WindowSelection }) {
  const [action, setAction] = useState<ActionFilter>("ALL");
  const [pathInput, setPathInput] = useState("");
  const [pathQuery, setPathQuery] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [detail, setDetail] = useState<WafLogRow | null>(null);

  useEffect(() => {
    const id = setTimeout(() => setPathQuery(pathInput), 400);
    return () => clearTimeout(id);
  }, [pathInput]);

  const poll: PollState<WafLogQueryResult> = usePoll(
    () => getWafLogRowsAction({ action, pathContains: pathQuery, window: win }),
    autoRefresh ? AUTO_REFRESH_MS : MANUAL_MS,
    true,
    [action, pathQuery, win.windowMin, win.intervalMin],
  );
  const { data, error, loading, refresh } = poll;
  const rows = data?.rows ?? [];

  return (
    <Card
      title={`WAF 로그 (${rows.length})`}
      right={
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <ErrorNote error={error} />
          {ACTIONS.map((a) => (
            <button
              key={a}
              type="button"
              onClick={() => setAction(a)}
              className={`rounded px-2 py-0.5 font-mono text-[10px] ${
                action === a
                  ? "bg-neutral-200 text-neutral-900"
                  : "bg-neutral-800 text-neutral-400 hover:bg-neutral-700"
              }`}
            >
              {LABEL[a]}
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
          <Counts
            total={data.totalMatched}
            fetched={rows.length}
            shown={rows.length}
            cap={data.truncated ? rows.length : undefined}
          />
          <span className="font-mono text-[10px] text-neutral-600">
            창 {data.windowLabel} · {data.logGroup} · 스캔 {fmtBytes(data.scannedBytes)}
          </span>
          {rows[0] && (
            <span className="font-mono text-[10px] text-neutral-600">
              최신 로그 {fmtTs(rows[0].ts)}
            </span>
          )}
          <LastUpdated at={poll.lastUpdated} label="조회" />
        </div>
      )}
      {loading && rows.length === 0 ? (
        <SectionLoading />
      ) : (
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-left font-mono text-[10px]">
            <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
              <tr>
                {["시각", "액션", "코드", "메소드", "경로", "규칙", "IP", "User-Agent"].map((h) => (
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
                  title="클릭하면 요청 전체(쿼리스트링·requestid)"
                  className="cursor-pointer border-t border-neutral-800 text-neutral-300 hover:bg-neutral-800/60"
                >
                  <td className="px-2 py-0.5 whitespace-nowrap text-neutral-500">{fmtTs(r.ts)}</td>
                  <td className={`px-2 py-0.5 font-bold ${actionColor(r.action)}`}>{r.action}</td>
                  <td className="px-2 py-0.5 tabular-nums text-neutral-400">
                    {r.responseCode ?? "—"}
                  </td>
                  <td className="px-2 py-0.5">{r.method}</td>
                  <td className="px-2 py-0.5">
                    <Truncate text={r.uri} className="max-w-56" />
                  </td>
                  {/* Group name and sub-rule together: "known-bad-inputs" alone
                      names a group of dozens of rules and cannot be acted on. */}
                  <td className="px-2 py-0.5 text-neutral-400">
                    <Truncate text={r.subRule ? `${r.rule} / ${r.subRule}` : r.rule} className="max-w-56" />
                  </td>
                  <td className="px-2 py-0.5 text-neutral-500">
                    {r.ip}
                    {r.country ? ` (${r.country})` : ""}
                  </td>
                  <td className="px-2 py-0.5 text-neutral-400">
                    {r.userAgent ? (
                      <Truncate text={r.userAgent} className="max-w-64" />
                    ) : (
                      <span className="text-neutral-700">—</span>
                    )}
                  </td>
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

      {detail && (
        <DetailModal title="WAF 로그 원문" onClose={() => setDetail(null)}>
          <dl className="space-y-1 font-mono text-[10px]">
            {(
              [
                ["시각", fmtTs(detail.ts)],
                ["액션", `${detail.action}${detail.responseCode ? ` · ${detail.responseCode}` : ""}`],
                ["종료 규칙", detail.rule],
                ["하위 규칙", detail.subRule || "(단일 규칙)"],
                ["요청", `${detail.method} ${detail.uri}`],
                ["쿼리스트링", detail.args || "(없음)"],
                ["requestid", detail.requestId || "(없음)"],
                ["클라이언트", `${detail.ip}${detail.country ? ` (${detail.country})` : ""}`],
                ["User-Agent", detail.userAgent || "(없음)"],
              ] as [string, string][]
            ).map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <dt className="w-24 shrink-0 text-neutral-500">{k}</dt>
                <dd className="min-w-0 break-all text-neutral-200">{v}</dd>
              </div>
            ))}
          </dl>
          <div className="mt-2 text-[10px] text-neutral-500">
            종료 규칙이 관리형 그룹이면 하위 규칙 이름이 조치 대상입니다 — 그 이름으로
            RuleActionOverride 를 걸거나 그룹에 경로 스코프다운을 답니다.
          </div>
        </DetailModal>
      )}
    </Card>
  );
}
