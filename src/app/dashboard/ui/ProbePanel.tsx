"use client";

import { useEffect, useRef, useState } from "react";
import { probeUrlAction } from "@/lib/api/dashboard";
import type { ProbeResult } from "@/lib/types";
import { Card, CopyValue, ErrorNote, fmtNum } from "./shared";

// 트래픽 점검.
//
// Every other screen here reads CloudWatch, which lags by minutes and, when a
// panel comes back empty, cannot say whether nothing happened or nothing was
// published yet. This one asks the service directly, and only when told to —
// nothing on this screen fires a request the operator did not.
//
// The history is in memory on purpose. Persisting it would make this a
// monitoring system with a retention policy, an on-disk format and a question
// about what happens while the dashboard is closed. It is a button.

const REPEAT_CHOICES = [
  { label: "수동", seconds: 0 },
  { label: "5초", seconds: 5 },
  { label: "10초", seconds: 10 },
  { label: "30초", seconds: 30 },
] as const;

// Kept short: this is a recent trend, not a record.
const HISTORY = 30;

function clock(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString("ko-KR", { hour12: false });
}

function verdict(r: ProbeResult): { text: string; icon: string; cls: string } {
  if (r.error) return { text: "응답 없음", icon: "✕", cls: "text-red-400" };
  if (r.ok) return { text: "정상", icon: "✓", cls: "text-emerald-400" };
  return { text: "비정상 응답", icon: "✕", cls: "text-red-400" };
}

export function ProbePanel() {
  const [url, setUrl] = useState("");
  const [expect, setExpect] = useState("");
  const [results, setResults] = useState<ProbeResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [repeatSec, setRepeatSec] = useState(0);
  // The repeating timer must call the current URL, not the one captured when
  // the interval was created.
  const latest = useRef({ url, expect, running });
  latest.current = { url, expect, running };

  const run = async (): Promise<void> => {
    const { url: u, expect: x, running: busy } = latest.current;
    if (!u.trim() || busy) return;
    setRunning(true);
    const parsed = Number(x);
    try {
      const res = await probeUrlAction(u, Number.isFinite(parsed) && parsed > 0 ? parsed : null);
      if (res.ok) {
        setResults((prev) => [res.data, ...prev].slice(0, HISTORY));
        setError(null);
      } else {
        setError(res.error);
      }
    } catch (e) {
      // The action call itself failed to reach the dashboard server. Without
      // this the button would stay disabled forever on a dropped connection.
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    if (repeatSec <= 0) return;
    const id = setInterval(() => void run(), repeatSec * 1000);
    return () => clearInterval(id);
    // `run` reads everything it needs through the ref, so the timer is not
    // rebuilt on every keystroke in the address field.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [repeatSec]);

  const last = results[0] ?? null;
  const done = results.filter((r) => !r.error);
  // Stated over what actually answered: a timed-out probe has no latency, and
  // counting it as 0ms would make an outage look fast.
  const avg =
    done.length > 0 ? Math.round(done.reduce((a, r) => a + r.elapsedMs, 0) / done.length) : null;
  const okRate =
    results.length > 0 ? Math.round((results.filter((r) => r.ok).length / results.length) * 100) : null;

  return (
    <div className="space-y-3">
      <div className="rounded border border-neutral-800 bg-neutral-900/70 px-3 py-2 text-[11px] leading-5 text-neutral-400">
        입력한 주소로 대시보드가 <span className="text-neutral-200">직접 GET 요청을 한 번</span>{" "}
        보냅니다. CloudWatch 지표는 몇 분 늦고 값이 비었을 때 &ldquo;트래픽이 없었다&rdquo;와
        &ldquo;아직 게시되지 않았다&rdquo;를 구분해 주지 않으므로, 지금 응답하는지는 여기서
        확인합니다. 요청에는{" "}
        <code className="text-neutral-300">User-Agent: skills-dashboard/traffic-check</code> 가
        붙으므로 WAF·로그 탭에서 이 요청을 구분할 수 있습니다. 응답 본문은 읽지 않고 버리며, 결과는
        이 화면에만 남습니다.
      </div>

      <Card title="정상 경로 프로브">
        <div className="space-y-2">
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex min-w-0 flex-1 flex-col gap-0.5">
              <span className="font-mono text-[10px] text-neutral-500">주소</span>
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void run();
                }}
                placeholder="http://alb-xxx.ap-northeast-2.elb.amazonaws.com/v1/user"
                spellCheck={false}
                className="w-full rounded border border-neutral-800 bg-neutral-950 px-2 py-1 font-mono text-[11px] text-neutral-200"
              />
            </label>
            <label className="flex w-28 flex-col gap-0.5">
              <span className="font-mono text-[10px] text-neutral-500">기대 코드</span>
              <input
                value={expect}
                onChange={(e) => setExpect(e.target.value)}
                placeholder="비우면 2xx"
                inputMode="numeric"
                className="w-full rounded border border-neutral-800 bg-neutral-950 px-2 py-1 font-mono text-[11px] text-neutral-200"
              />
            </label>
            <button
              type="button"
              onClick={() => void run()}
              disabled={running || !url.trim()}
              className="rounded bg-sky-900 px-3 py-1.5 font-mono text-[11px] font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
            >
              {running ? "점검 중…" : "지금 점검"}
            </button>
            <label className="flex items-center gap-1 font-mono text-[10px] text-neutral-500">
              반복
              <select
                value={repeatSec}
                onChange={(e) => setRepeatSec(Number(e.target.value))}
                className="rounded border border-neutral-800 bg-neutral-900 px-1.5 py-1 font-mono text-[11px] text-neutral-300"
              >
                {REPEAT_CHOICES.map((c) => (
                  <option key={c.seconds} value={c.seconds}>
                    {c.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <ErrorNote error={error} />

          {last ? (
            <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
              <span className={`font-mono text-sm font-bold ${verdict(last).cls}`}>
                {verdict(last).icon} {verdict(last).text}
              </span>
              <span className="font-mono text-[11px] tabular-nums text-neutral-300">
                {last.error ?? `${last.status} · ${fmtNum(last.elapsedMs)}ms`}
              </span>
              <span className="font-mono text-[10px] text-neutral-500">
                {clock(last.at)} · 판정 기준 {last.expect}
              </span>
              {last.finalUrl && (
                <span className="font-mono text-[10px] text-amber-400">
                  리다이렉트됨 → {last.finalUrl}
                </span>
              )}
            </div>
          ) : (
            <div className="py-4 text-center text-[11px] text-neutral-600">아직 점검하지 않았습니다.</div>
          )}
        </div>
      </Card>

      {results.length > 0 && (
        <Card title={`최근 ${results.length}회`}>
          <div className="mb-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Mini label="정상 비율" value={okRate === null ? "—" : `${okRate}%`} />
            <Mini
              label="평균 응답"
              value={avg === null ? "—" : `${fmtNum(avg)}ms`}
            />
            <Mini
              label="최대 응답"
              value={done.length ? `${fmtNum(Math.max(...done.map((r) => r.elapsedMs)))}ms` : "—"}
            />
            <Mini
              label="실패"
              value={fmtNum(results.filter((r) => !r.ok).length)}
            />
          </div>

          <table className="w-full text-left text-[11px]">
            <thead className="text-neutral-500">
              <tr>
                {["시각", "결과", "상태", "소요", "주소"].map((h) => (
                  <th key={h} className="px-2 py-1 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => {
                const v = verdict(r);
                return (
                  <tr key={`${r.at}-${i}`} className="border-t border-neutral-800">
                    <td className="px-2 py-1 font-mono tabular-nums text-neutral-400">{clock(r.at)}</td>
                    <td className={`px-2 py-1 font-semibold ${v.cls}`}>
                      {v.icon} {v.text}
                    </td>
                    <td className="px-2 py-1 font-mono tabular-nums text-neutral-300">
                      {r.status ?? "—"}
                    </td>
                    <td className="px-2 py-1 font-mono tabular-nums text-neutral-300">
                      {fmtNum(r.elapsedMs)}ms
                    </td>
                    <td className="max-w-0 px-2 py-1 font-mono text-neutral-500">
                      <CopyValue value={r.error ?? r.url} className="text-[10px]" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-neutral-800 bg-neutral-950 p-2">
      <div className="text-[10px] text-neutral-500">{label}</div>
      <div className="font-mono text-lg font-bold tabular-nums text-neutral-100">{value}</div>
    </div>
  );
}
