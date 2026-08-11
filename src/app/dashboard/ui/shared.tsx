"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ActionResult, MetricPoint, Status, WarningEvent } from "@/lib/types";

export interface PollState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  lastUpdated: string | null;
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
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const inflight = useRef(false);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  // Serialized so the effect keeps a fixed-length dependency array.
  const inputKey = JSON.stringify(inputs);
  const lastInputKey = useRef(inputKey);

  const tick = useCallback(async (): Promise<void> => {
    if (inflight.current) return;
    inflight.current = true;
    try {
      const res = await fnRef.current();
      if (res.ok) {
        setData(res.data);
        setError(null);
        // Only a success advances the clock — otherwise the sidebar reads
        // "just updated" while the panel is still showing stale data.
        setLastUpdated(new Date().toLocaleTimeString("ko-KR"));
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
    if (!enabled) return;
    // Inputs changed: what is on screen answers a different question, so drop
    // it rather than label another pod's logs with the newly selected name.
    if (lastInputKey.current !== inputKey) {
      lastInputKey.current = inputKey;
      setData(null);
      setError(null);
    }
    setLoading(true);
    void tick();
    const id = setInterval(() => void tick(), intervalMs);
    return () => clearInterval(id);
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

export function Card({
  title,
  right,
  children,
  className = "",
}: {
  title: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-[4px] border border-neutral-800 bg-neutral-900/70 ${className}`}>
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-neutral-800 px-3 py-2">
        <h3 className="flex shrink-0 items-center gap-2 font-mono text-[10px] font-semibold tracking-[0.14em] text-neutral-500 uppercase">
          <span aria-hidden className="h-3 w-0.5 shrink-0 bg-sky-500/70" />
          {title}
        </h3>
        <div className="min-w-0">{right}</div>
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

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="rounded border border-red-900 bg-red-950/40 px-2 py-1 text-[11px] text-red-300">
      조회 실패: {error}
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
