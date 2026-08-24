"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ActionResult, MetricPoint, Status, WarningEvent } from "@/lib/types";
import { TimeChart } from "./TimeChart";

export interface PollState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  // Epoch ms of the last SUCCESSFUL load, not a formatted string. "몇 초 전"
  // has to be recomputed every second, and only a number can do that; the
  // formatting belongs to <LastUpdated>.
  lastUpdated: number | null;
  refresh: () => void;
}

// A Server Action call that never reaches the server rejects with a bare
// TypeError whose message is "Failed to fetch" — rendered as-is it is
// indistinguishable from an AWS/K8s API error, so label the transport case.
function describeError(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  if (/failed to fetch|networkerror|load failed|network request failed/i.test(raw)) {
    return `서버 연결 끊김 — 대시보드 서버 응답 없음 (${raw})`;
  }
  return raw;
}

// Client-side polling with an in-flight guard: a tick is skipped while the
// previous request is still running (spec §24).
//
// `inputs` names the values the callback reads. The callback itself is held in
// a ref (so a new closure every render does not restart the timer), which means
// a changed input would otherwise sit unfetched until the next interval — an
// hour, for the log panel with auto-refresh off. Anything the callback depends
// on must be listed here.
export function usePoll<T>(
  fn: () => Promise<ActionResult<T>>,
  intervalMs: number,
  enabled = true,
  inputs: readonly unknown[] = [],
): PollState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const inflight = useRef(false);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  // Serialized so the effect keeps a fixed-length dependency array.
  const inputKey = JSON.stringify(inputs);
  const lastInputKey = useRef(inputKey);

  const tick = useCallback(async (scheduled = false): Promise<void> => {
    // A scheduled tick is skipped while the page is hidden. Nobody is reading
    // it, and on a low-spec machine each round costs an AWS call, a React
    // render and a canvas redraw across every mounted panel — minimising the
    // window during a match should cost nothing. Manual refreshes and the first
    // load still run, so a panel is never left empty or stuck on "loading".
    if (scheduled && typeof document !== "undefined" && document.visibilityState === "hidden") {
      return;
    }
    if (inflight.current) return;
    inflight.current = true;
    try {
      const res = await fnRef.current();
      if (res.ok) {
        setData(res.data);
        setError(null);
        // Only a success advances the clock — otherwise the sidebar reads
        // "just updated" while the panel is still showing stale data.
        setLastUpdated(Date.now());
      } else {
        setError(res.error);
      }
    } catch (e) {
      setError(describeError(e));
    } finally {
      inflight.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!enabled) {
      // Nothing will run, so nothing will clear the initial loading flag. A
      // disabled poll that reports "loading" forever locks every control bound
      // to it — an on-demand panel would never become clickable.
      setLoading(false);
      return;
    }
    // Inputs changed: what is on screen answers a different question, so drop
    // it rather than label another pod's logs with the newly selected name.
    if (lastInputKey.current !== inputKey) {
      lastInputKey.current = inputKey;
      setData(null);
      setError(null);
    }
    setLoading(true);
    void tick();
    const id = setInterval(() => void tick(true), intervalMs);
    // Coming back to a hidden tab must not show whatever was on screen when it
    // was hidden — that number could be an hour old and carries no marker
    // saying so. One immediate read on return, then the interval resumes.
    const onVisible = (): void => {
      if (document.visibilityState === "visible") void tick();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [tick, intervalMs, enabled, inputKey]);

  return { data, error, loading, lastUpdated, refresh: () => void tick() };
}

export const STATUS_COLORS: Record<Status, string> = {
  NORMAL: "text-emerald-400 border-emerald-800 bg-emerald-950/40",
  WARNING: "text-amber-400 border-amber-700 bg-amber-950/40",
  CRITICAL: "text-red-400 border-red-800 bg-red-950/40",
};

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span
      className={`inline-block rounded-[3px] border px-1.5 py-0.5 font-mono text-[9px] font-bold tracking-[0.08em] ${STATUS_COLORS[status]}`}
    >
      {status}
    </span>
  );
}

// The zoom container both Card and Stat open.
//
// Native <dialog> gives ESC, focus containment and an inert background for
// free, and showModal() is the only way to get them — so the open state is
// pushed into the element rather than rendered as an attribute. Extracted
// because a metric tile needs exactly the same behaviour as a panel, and two
// copies would be two chances for one of them to lose ESC.
export function ZoomDialog({
  open,
  onClose,
  label,
  children,
}: {
  open: boolean;
  onClose: () => void;
  label: string;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDialogElement | null>(null);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      aria-label={label}
      onClose={onClose}
      // A click that lands on the dialog element itself is a backdrop click;
      // anything inside the panel stops at the panel.
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
      // m-auto restores the centering a modal <dialog> gets by default — the
      // CSS reset zeroes every margin, which pins it to the top left.
      className="m-auto w-[92vw] max-w-6xl rounded-[4px] border border-neutral-700 bg-neutral-900 p-0 text-neutral-200 backdrop:bg-black/70"
    >
      {/* A closed <dialog> still renders its children. Left unguarded, every
          panel and every tile would build its expanded body on each refresh. */}
      {open && <div className="max-h-[85vh] overflow-y-auto">{children}</div>}
    </dialog>
  );
}

// No zoom affordance: enlarging a card shows the same rows bigger and gives no
// next action, so drill-down is a tab move instead. The time window is global,
// so it follows on its own.
export function Card({
  title,
  right,
  children,
  className = "",
  // A threshold worth acting on, shown next to the title in grey (e.g. "20/min").
  // Not a caption — the window and the aggregation live in the window bar.
  limit,
}: {
  title: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  limit?: string;
}) {
  return (
    <div className={`rounded-[4px] border border-neutral-800 bg-neutral-900/70 ${className}`}>
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-neutral-800 px-3 py-2">
        <h3 className="flex shrink-0 items-center gap-2 font-mono text-[10px] font-semibold tracking-[0.14em] text-neutral-500 uppercase">
          <span aria-hidden className="h-3 w-0.5 shrink-0 bg-sky-500/70" />
          {title}
          {limit && <span className="font-normal text-neutral-600 normal-case">{limit}</span>}
        </h3>
        <div className="flex min-w-0 items-center gap-2">{right}</div>
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}

export function Sparkline({ points, status }: { points: MetricPoint[]; status: Status }) {
  if (points.length < 2) {
    return <div className="h-8 text-[10px] text-neutral-600">데이터 수집 중…</div>;
  }
  const w = 120;
  const h = 32;
  const values = points.map((p) => p.v);
  const max = Math.max(...values, 0.0001);
  const min = Math.min(...values, 0);
  const range = max - min || 1;
  const coords = values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * w;
      const y = h - ((v - min) / range) * (h - 4) - 2;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const stroke =
    status === "CRITICAL" ? "#ff5c5c" : status === "WARNING" ? "#ffb454" : "#3ddc97";
  return (
    <svg width={w} height={h} className="block" aria-hidden>
      <polyline points={coords} fill="none" stroke={stroke} strokeWidth={1.5} />
    </svg>
  );
}

// The failure, in full, inside the panel that failed.
//
// A shortened message is unactionable: the useful part of an Insights error is
// the tail ("token recognition error at ':' at line 9"), which is precisely
// what a one-line clamp cuts off. It wraps and scrolls instead.
export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div
      role="alert"
      className="max-h-32 overflow-auto rounded border border-red-900 bg-red-950/40 px-2 py-1 font-mono text-[10px] leading-4 whitespace-pre-wrap break-all text-red-300"
    >
      조회 실패: {error}
    </div>
  );
}

// A number the operator will want to paste somewhere — a pod name, a path, an
// ARN, a count. Clicking it copies it; nothing else changes.
export function CopyValue({
  value,
  copy,
  className = "",
  title,
}: {
  value: string;
  // What lands on the clipboard, when that differs from what is shown (a
  // formatted "1,284" is useless in a shell).
  copy?: string;
  className?: string;
  title?: string;
}) {
  const [state, setState] = useState<"idle" | "ok" | "fail">("idle");

  const run = async (): Promise<void> => {
    const text = copy ?? value;
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      // The async clipboard API needs a secure context, and this is served
      // over plain http. Browsers usually treat localhost as secure — usually.
      ok = false;
    }
    setState(ok ? "ok" : "fail");
    setTimeout(() => setState("idle"), 1400);
  };

  return (
    <button
      type="button"
      onClick={() => void run()}
      title={title ?? "클릭해서 복사"}
      className={`group inline-flex max-w-full items-baseline gap-1 rounded px-0.5 text-left break-all hover:bg-neutral-800/70 ${className}`}
    >
      <span>{value}</span>
      <span aria-hidden className="shrink-0 text-[9px] text-neutral-600 group-hover:text-sky-400">
        {state === "ok" ? "✓" : state === "fail" ? "!" : "⧉"}
      </span>
    </button>
  );
}

export function fmtNum(n: number, digits = 0): string {
  return n.toLocaleString("ko-KR", { maximumFractionDigits: digits });
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function fmtClock(ms: number): string {
  return new Date(ms).toLocaleTimeString("ko-KR", { hour12: false });
}

export function fmtAgo(ms: number, nowMs: number): string {
  const s = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (s < 60) return `${s}초 전`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}분 전`;
  return `${Math.floor(m / 60)}시간 전`;
}

// A one-second tick, isolated.
//
// Its own component because the relative reading has to re-render every
// second, and an interval placed in a tab would re-render every panel and
// every chart under it once a second to change five characters.
export function LastUpdated({ at, label }: { at: number | null; label?: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (at === null) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [at]);

  return (
    <span className="font-mono text-[10px] tabular-nums text-neutral-500">
      {label ? `${label} ` : ""}
      {at === null ? "갱신 없음" : `갱신 ${fmtClock(at)} · ${fmtAgo(at, now)}`}
    </span>
  );
}

// Three numbers that are routinely collapsed into one, stated separately:
// how many exist, how many were fetched, how many are drawn. Deriving the
// first from the last is how a header comes to report a capped array's length
// as a total.
export function Counts({
  total,
  fetched,
  shown,
  cap,
}: {
  total: number | null;
  fetched: number;
  shown: number;
  // The row limit, when the fetch hit it.
  cap?: number;
}) {
  return (
    <span className="font-mono text-[10px] tabular-nums text-neutral-500">
      전체 {total === null ? "?" : fmtNum(total)}건 · 조회 {fmtNum(fetched)}건 · 표시{" "}
      {fmtNum(shown)}건
      {cap !== undefined && total !== null && total > fetched && (
        <span className="ml-1 rounded-[3px] bg-amber-950/60 px-1 text-amber-400">
          상위 {fmtNum(cap)}건만 조회됨
        </span>
      )}
    </span>
  );
}

const INTENT_TEXT: Record<Status, string> = {
  NORMAL: "text-neutral-100",
  WARNING: "text-amber-400",
  CRITICAL: "text-red-400",
};

// One headline number. No caption and no expand: the window bar says what span
// every number covers, and the drill-down is a tab move.
export function Stat({
  label,
  value,
  unit,
  status = "NORMAL",
  sub,
  copy,
}: {
  label: string;
  value: string;
  unit?: string;
  status?: Status;
  // A second line the caller owns — a delta, a sparkline, a share.
  sub?: React.ReactNode;
  copy?: string;
}) {
  const loud = status !== "NORMAL";

  return (
    <div
      className={`relative rounded border p-2 ${
        loud ? "border-neutral-700 bg-neutral-900" : "border-neutral-800 bg-neutral-950"
      }`}
    >
      <div className="flex items-start justify-between gap-1">
        <span className="text-[10px] leading-4 text-neutral-500">{label}</span>
        {loud && <StatusBadge status={status} />}
      </div>
      <div
        className={`font-mono font-bold tabular-nums ${loud ? "text-2xl" : "text-xl"} ${INTENT_TEXT[status]}`}
      >
        <CopyValue value={value} copy={copy ?? value} title={`${label} 복사`} />
        {unit && (
          <span className="ml-0.5 font-sans text-[10px] font-normal text-neutral-500">{unit}</span>
        )}
      </div>
      {sub}
    </div>
  );
}

// A statement about where a number came from that contradicts a neighbouring
// panel, placed in the panel rather than in a footnote.
export function SourceNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded border border-neutral-800 bg-neutral-900/60 px-2 py-1 text-[10px] leading-4 text-neutral-400">
      {children}
    </div>
  );
}

export function SectionLoading() {
  return (
    <div aria-busy className="space-y-2 py-2">
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          className="h-3 animate-pulse rounded-[3px] bg-neutral-800"
          style={{ width: `${85 - i * 18}%` }}
        />
      ))}
    </div>
  );
}

export function DetailModal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      role="dialog"
      aria-modal
      aria-label={title}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl rounded-[4px] border border-neutral-700 bg-neutral-900 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-neutral-800 px-3 py-2">
          <h3 className="flex items-center gap-2 font-mono text-[10px] font-semibold tracking-[0.14em] text-neutral-400 uppercase">
            <span aria-hidden className="h-3 w-0.5 shrink-0 bg-sky-500/70" />
            {title}
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="닫기"
            className="rounded px-1.5 py-0.5 text-neutral-500 hover:bg-neutral-800 hover:text-neutral-200"
          >
            ✕
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto p-3 text-[11px]">{children}</div>
      </div>
    </div>
  );
}

export function WarningEventDetailModal({
  event,
  onClose,
  onJumpToLogs,
}: {
  event: WarningEvent;
  onClose: () => void;
  onJumpToLogs?: (pod: string) => void;
}) {
  const rows: [string, React.ReactNode][] = [
    ["시각", fmtTs(event.timestamp)],
    ["Namespace", event.namespace],
    ["대상", `${event.kind}/${event.name}`],
    [
      "사유",
      <span key="r" className={event.highlighted ? "font-semibold text-amber-400" : ""}>
        {event.reason}
      </span>,
    ],
    ["횟수", `×${event.count}`],
  ];
  return (
    <DetailModal title="Warning Event 상세" onClose={onClose}>
      <div className="space-y-1">
        {rows.map(([label, value]) => (
          <div key={label} className="flex gap-3">
            <span className="w-20 shrink-0 text-neutral-500">{label}</span>
            <span className="text-neutral-200">{value}</span>
          </div>
        ))}
        <div className="pt-1">
          <div className="mb-1 text-neutral-500">메시지</div>
          <pre className="rounded border border-neutral-800 bg-neutral-950 p-2 font-mono whitespace-pre-wrap break-all text-neutral-300">
            {event.message || "(메시지 없음)"}
          </pre>
        </div>
        {event.isPod && onJumpToLogs && (
          <div className="pt-2">
            <button
              type="button"
              onClick={() => {
                onJumpToLogs(event.name);
                onClose();
              }}
              className="rounded bg-neutral-800 px-2 py-1 text-neutral-300 hover:bg-neutral-700"
            >
              로그 보기
            </button>
          </div>
        )}
      </div>
    </DetailModal>
  );
}

export function fmtDelta(delta: number, percentChange: number | null): string {
  const sign = delta > 0 ? "▲" : delta < 0 ? "▼" : "―";
  const pct = percentChange === null ? "신규" : `${percentChange >= 0 ? "+" : ""}${percentChange}%`;
  return `${sign} ${Math.abs(delta)} (${pct})`;
}

export function fmtTs(iso: string): string {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleTimeString("ko-KR", { hour12: false });
  } catch {
    return iso;
  }
}

// Truncated text with a hover tooltip that shows the full value in a
// translucent box, clamped so it never leaves the viewport.
//
// Must be a block: an inline box ignores overflow and width, so `truncate` on
// an inline span clips nothing and long values spill across neighbouring
// columns. `min-w-0` lets it shrink inside a flex row, and the width itself
// comes from the caller (a max-w-* class) or from a fixed-layout table column.
export function Truncate({ text, className = "" }: { text: string; className?: string }) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);

  const show = (e: React.MouseEvent<HTMLSpanElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    setPos({ x: r.left, y: r.bottom + 4 });
  };
  const hide = () => setPos(null);

  return (
    <span
      className={`block min-w-0 max-w-full truncate ${className}`}
      // Native tooltip as a fallback for touch/keyboard and for the moment
      // before the styled one renders.
      title={text || undefined}
      onMouseEnter={show}
      onMouseMove={pos ? undefined : show}
      onMouseLeave={hide}
    >
      {text}
      {pos && text && (
        <span
          role="tooltip"
          style={{
            position: "fixed",
            left: `min(${pos.x}px, calc(100vw - 20rem - 8px))`,
            top: pos.y,
            maxWidth: "20rem",
            zIndex: 50,
          }}
          className="pointer-events-none block max-h-40 overflow-hidden rounded border border-neutral-700 bg-neutral-900/85 px-2 py-1 text-[11px] whitespace-pre-wrap break-words text-neutral-100 shadow-lg backdrop-blur-sm"
        >
          {text}
        </span>
      )}
    </span>
  );
}
