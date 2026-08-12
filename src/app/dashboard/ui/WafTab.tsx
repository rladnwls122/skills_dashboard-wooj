"use client";

import { useState } from "react";
import { getWafSamplesAction } from "@/app/actions/dashboard";
import type { MetricsPanel, WafPanel, WafSampleRow } from "@/lib/types";
import {
  Card,
  ErrorNote,
  SectionLoading,
  SourceNote,
  Truncate,
  fmtTs,
  usePoll,
  type PollState,
} from "./shared";

// Column widths for the sampled-request table. They add up to 100% so the
// fixed layout never needs a horizontal scrollbar; the three unbounded fields
// (path / query / User-Agent) get the slack.
const SAMPLE_COLUMNS = [
  { label: "시각", width: "9%" },
  { label: "IP", width: "10%" },
  { label: "국가", width: "4%" },
  { label: "메소드", width: "6%" },
  { label: "경로", width: "13%" },
  { label: "쿼리", width: "17%" },
  { label: "User-Agent", width: "19%" },
  {
    label: "상태",
    width: "6%",
    hint: "WAF가 직접 응답한 요청만 기록됨 (Block+커스텀 응답, CAPTCHA). 일반 ALLOW 요청은 비어 있음 — 실제 앱 상태 코드는 아래 앱 요청 로그 참고",
  },
  { label: "판정", width: "7%" },
  { label: "룰", width: "9%" },
] as const;

function StatList({
  title,
  rows,
}: {
  title: string;
  rows: { key: string; count: number; warn?: boolean }[];
}) {
  return (
    <div>
      <div className="mb-1 text-[11px] text-neutral-500">{title}</div>
      <div className="max-h-40 space-y-0.5 overflow-y-auto text-[11px]">
        {rows.map((r, i) => (
          <div
            key={i}
            className={`flex justify-between gap-2 rounded px-1.5 py-0.5 ${r.warn ? "bg-red-950/30 text-red-300" : "bg-neutral-950 text-neutral-300"}`}
          >
            <span className="truncate">{r.key || "(empty)"}</span>
            <span className="tabular-nums text-neutral-500">{r.count}</span>
          </div>
        ))}
        {rows.length === 0 && <div className="text-neutral-600">데이터 없음</div>}
      </div>
    </div>
  );
}

export function WafTab({
  waf,
  metrics,
}: {
  waf: PollState<WafPanel>;
  metrics: PollState<MetricsPanel>;
}) {
  const [sampleFilter, setSampleFilter] = useState<"ALL" | "BLOCK" | "ALLOW" | "COUNT">("ALL");
  const [sampleSearch, setSampleSearch] = useState("");

  const samples = usePoll(getWafSamplesAction, 30_000);

  const filteredSamples = (samples.data ?? []).filter((s) => {
    if (sampleFilter !== "ALL" && s.action !== sampleFilter) return false;
    if (sampleSearch) {
      const q = sampleSearch.toLowerCase();
      const hay = `${s.ip} ${s.path} ${s.query} ${s.userAgent} ${s.method} ${s.responseCode ?? ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const wafBlockedMetric = metrics.data?.metrics.find((m) => m.key === "wafBlocked");
  const wafAllowedMetric = metrics.data?.metrics.find((m) => m.key === "wafAllowed");

  return (
    <div className="space-y-3">
      <Card
        title={`샘플 요청 원본 (${filteredSamples.length}/${samples.data?.length ?? 0})`}
        basis="WAF GetSampledRequests 최신 300건 · 앞의 수는 화면 필터 적용 결과"
        right={
          <div className="flex items-center gap-2 text-[11px]">
            <ErrorNote error={samples.error} />
            {(["ALL", "BLOCK", "ALLOW", "COUNT"] as const).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setSampleFilter(f)}
                className={`rounded px-2 py-0.5 font-mono text-[10px] ${
                  sampleFilter === f
                    ? "bg-neutral-200 text-neutral-900"
                    : "bg-neutral-800 text-neutral-400 hover:bg-neutral-700"
                }`}
              >
                {f}
              </button>
            ))}
            <input
              value={sampleSearch}
              onChange={(e) => setSampleSearch(e.target.value)}
              placeholder="IP/경로/UA/코드 검색"
              className="w-36 rounded border border-neutral-700 bg-neutral-900 px-2 py-0.5"
            />
            <button
              type="button"
              onClick={samples.refresh}
              className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
            >
              새로고침
            </button>
          </div>
        }
      >
        <div className="max-h-80 overflow-auto">
          {/* Fixed layout: query strings and User-Agents are unbounded, and an
              auto-layout table lets them widen their column until the later
              ones overlap. Fixed columns + Truncate keeps every row readable. */}
          <table className="w-full table-fixed text-left font-mono text-[10px]">
            <colgroup>
              {SAMPLE_COLUMNS.map((c) => (
                <col key={c.label} style={{ width: c.width }} />
              ))}
            </colgroup>
            <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
              <tr>
                {SAMPLE_COLUMNS.map((h) => (
                  <th
                    key={h.label}
                    title={"hint" in h ? h.hint : undefined}
                    className={`px-2 py-1 font-medium whitespace-nowrap ${"hint" in h ? "cursor-help underline decoration-dotted" : ""}`}
                  >
                    {h.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredSamples.map((s, i) => (
                <tr
                  key={i}
                  className={`border-t border-neutral-800 ${s.action === "BLOCK" ? "bg-red-950/25 text-red-300" : "text-neutral-300"}`}
                >
                  <td className="px-2 py-0.5 text-neutral-500">
                    <Truncate text={fmtTs(s.ts)} />
                  </td>
                  <td className="px-2 py-0.5">
                    <Truncate text={s.ip} />
                  </td>
                  <td className="px-2 py-0.5">{s.country}</td>
                  <td className="px-2 py-0.5">{s.method}</td>
                  <td className="px-2 py-0.5">
                    <Truncate text={s.path} />
                  </td>
                  <td className="px-2 py-0.5 text-neutral-500">
                    <Truncate text={s.query} />
                  </td>
                  <td className="px-2 py-0.5 text-neutral-500">
                    <Truncate text={s.userAgent} />
                  </td>
                  <td className="px-2 py-0.5 tabular-nums whitespace-nowrap">
                    {s.responseCode === null ? (
                      <span className="text-neutral-600">—</span>
                    ) : (
                      <span className={s.responseCode >= 500 ? "text-red-400" : s.responseCode >= 400 ? "text-amber-400" : "text-neutral-300"}>
                        {s.responseCode}
                      </span>
                    )}
                  </td>
                  <td
                    className={`px-2 py-0.5 font-bold ${s.action === "BLOCK" ? "text-red-400" : s.action === "COUNT" ? "text-amber-400" : "text-emerald-400"}`}
                  >
                    {s.action}
                  </td>
                  <td className="px-2 py-0.5 text-neutral-500">
                    <Truncate text={s.rule} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filteredSamples.length === 0 && !samples.error && (
            <div className="p-3 text-center text-[11px] text-neutral-500">
              {samples.loading ? "수집 중…" : "조건에 맞는 샘플 없음"}
            </div>
          )}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card title="WAF 이상 요약" right={<ErrorNote error={waf.error} />}>
          <div className="space-y-1 text-xs text-neutral-400">
            <div>
              BlockedRequests:{" "}
              {wafBlockedMetric
                ? `${wafBlockedMetric.previous} → ${wafBlockedMetric.current}/min (${wafBlockedMetric.status})`
                : "수집 중"}
            </div>
            <div>
              AllowedRequests:{" "}
              {wafAllowedMetric
                ? `${wafAllowedMetric.previous} → ${wafAllowedMetric.current}/min (${wafAllowedMetric.status})`
                : "수집 중"}
            </div>
            {waf.data?.acl ? (
              <>
                <div>
                  WebACL: <span className="text-neutral-200">{waf.data.acl.name}</span> ({waf.data.acl.scope}) — 규칙 {waf.data.acl.ruleCount}개, WCU {waf.data.acl.capacityUsed}
                </div>
                <div className="mt-1 space-y-0.5">
                  {waf.data.acl.rules.map((r) => (
                    <div key={r.name} className="flex justify-between rounded bg-neutral-950 px-2 py-0.5">
                      <span>{r.name}</span>
                      <span className="tabular-nums text-neutral-500">
                        p{r.priority} · {r.action}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="text-red-400">{waf.data?.aclError ?? "WebACL 조회 중…"}</div>
            )}
          </div>
        </Card>

      </div>

      <Card
        title="WAF 로그 통계 (경로/쿼리/헤더/메소드/차단)"
        basis={
          metrics.data?.httpSummary
            ? `${metrics.data.httpSummary.source} · 경로는 요청순 상위 20개, IP·UA·쿼리·헤더는 상위 10개 (차단 건수는 잘리지 않은 전체 기준)`
            : undefined
        }
      >
        {/* Two panels on this page count blocked requests and will not agree.
            The conflict is stated where the numbers are, not in a footnote. */}
        <SourceNote>
          이 표는 <span className="text-neutral-200">WAF 로그·샘플 기준</span>입니다. 요약 탭의{" "}
          <span className="text-neutral-200">WAF BlockedRequests</span> 는 CloudWatch 메트릭
          기준이라, 전달 지연과 집계 단위 차이로 같은 구간에서도 값이 다르게 보일 수 있습니다.
          {metrics.data?.httpSummary?.notes.map((n) => (
            <span key={n} className="mt-0.5 block text-neutral-500">
              · {n}
            </span>
          ))}
        </SourceNote>

        {metrics.data?.httpSummary ? (
          <div className="mt-2 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
            {/* The path list carries two server-decided marks the other stat
                lists have no use for: 의심 (off-surface and concentrated) and
                헬스체크 (excluded from anomaly scoring). */}
            <div>
              <div className="mb-1 text-[11px] text-neutral-500">
                Path (총 {metrics.data.httpSummary.totalSampled}건, 차단{" "}
                {metrics.data.httpSummary.blockedTotal}건)
              </div>
              <div className="max-h-40 space-y-0.5 overflow-y-auto text-[11px]">
                {metrics.data.httpSummary.byPath.map((p) => (
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
                      {p.lowPriority && " (헬스체크)"}
                    </span>
                    <span className="tabular-nums text-neutral-500">
                      {p.count}
                      {p.blocked > 0 && <span className="text-red-400"> · 차단 {p.blocked}</span>}
                    </span>
                  </div>
                ))}
                {metrics.data.httpSummary.byPath.length === 0 && (
                  <div className="text-neutral-600">데이터 없음</div>
                )}
              </div>
            </div>
            <StatList
              title="IP (점유율 30%↑ 강조)"
              rows={metrics.data.httpSummary.byIp.map((ip) => ({
                key: ip.key,
                count: ip.count,
                warn: ip.concentrated,
              }))}
            />
            <StatList
              title="Method"
              rows={metrics.data.httpSummary.byMethod.map((m) => ({ key: m.key, count: m.count }))}
            />
            <StatList
              title="QueryString 패턴"
              rows={metrics.data.httpSummary.queryPatterns.map((q) => ({ key: q.key, count: q.count }))}
            />
            <div>
              <div className="mb-1 text-[11px] text-neutral-500">Header 패턴</div>
              {metrics.data.httpSummary.headerPatterns.length === 0 &&
              metrics.data.httpSummary.notes.length > 0 ? (
                <div className="rounded bg-neutral-950 px-1.5 py-1 text-[11px] text-neutral-500">
                  {metrics.data.httpSummary.notes[0]}
                </div>
              ) : (
                <div className="max-h-40 space-y-0.5 overflow-y-auto text-[11px]">
                  {metrics.data.httpSummary.headerPatterns.map((h, i) => (
                    <div
                      key={i}
                      className="flex justify-between gap-2 rounded bg-neutral-950 px-1.5 py-0.5 text-neutral-300"
                    >
                      <span className="truncate">{h.key || "(empty)"}</span>
                      <span className="tabular-nums text-neutral-500">{h.count}</span>
                    </div>
                  ))}
                  {metrics.data.httpSummary.headerPatterns.length === 0 && (
                    <div className="text-neutral-600">데이터 없음</div>
                  )}
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="text-xs text-neutral-500">{metrics.data?.httpSummaryError ?? "수집 중…"}</div>
        )}
      </Card>

    </div>
  );
}
