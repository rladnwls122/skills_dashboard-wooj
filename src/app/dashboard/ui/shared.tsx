"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ActionResult, MetricPoint, Status } from "@/lib/types";

export interface PollState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  lastUpdated: string | null;
  refresh: () => void;
}

// Client-side polling with an in-flight guard: a tick is skipped while the
// previous request is still running (spec §24).
export function usePoll<T>(
  fn: () => Promise<ActionResult<T>>,
  intervalMs: number,
  enabled = true,
): PollState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const inflight = useRef(false);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const tick = useCallback(async (): Promise<void> => {
    if (inflight.current) return;
    inflight.current = true;
    try {
      const res = await fnRef.current();
      if (res.ok) {
        setData(res.data);
        setError(null);
      } else {
        setError(res.error);
      }
      setLastUpdated(new Date().toLocaleTimeString("ko-KR"));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      inflight.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    void tick();
    const id = setInterval(() => void tick(), intervalMs);
    return () => clearInterval(id);
  }, [tick, intervalMs, enabled]);

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
