"use client";

import { useEffect, useRef } from "react";
import type uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import type { MetricPoint } from "@/lib/types";

// Every time series on the dashboard is drawn here.
//
// The sparkline it replaces could show one series with no axis, no legend and
// no way to read a value off it — which is enough to notice a shape and not
// enough to say what happened at 22:41. uPlot earns its place with three
// things a hand-rolled SVG would not have: a real time axis, a legend that
// reads live values under the cursor and toggles series on click, and
// `cursor.sync`, which ties every chart on the page to one crosshair. Charts
// on a shared window are only worth sharing if the crosshair is shared too.
//
// Nothing is ever dropped for the caller: every series passed in is drawn, and
// the legend decides what is looked at.

export interface ChartSeries {
  label: string;
  points: MetricPoint[];
  // CSS colour. Omitted series take the next palette entry.
  color?: string;
  unit?: string;
}

const PALETTE = [
  "#3ddc97",
  "#ff5c5c",
  "#ffb454",
  "#54b8ff",
  "#c792ea",
  "#7fdbca",
  "#f78c6c",
  "#89ddff",
];

// Aligns series onto one x-axis.
//
// Each series carries its own timestamps. They come from the same window and
// interval, so they normally match — but a metric with no datapoint in a
// bucket simply has no entry there, and drawing that series against its own
// shorter array would slide it along the axis. The union of timestamps is the
// axis; a series with nothing at a timestamp gets null, and uPlot breaks the
// line rather than drawing through a value nobody measured.
export function alignSeries(series: ChartSeries[]): {
  xs: number[];
  ys: (number | null)[][];
} {
  const all = new Set<number>();
  const maps = series.map((s) => {
    const m = new Map<number, number>();
    for (const p of s.points) {
      const t = Date.parse(p.t);
      if (Number.isNaN(t)) continue;
      m.set(t, p.v);
      all.add(t);
    }
    return m;
  });
  const xs = [...all].sort((a, b) => a - b);
  return {
    xs: xs.map((t) => t / 1000),
    ys: maps.map((m) => xs.map((t) => m.get(t) ?? null)),
  };
}

export function TimeChart({
  series,
  height = 180,
  syncKey = "dashboard",
}: {
  series: ChartSeries[];
  height?: number;
  syncKey?: string;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const chart = useRef<uPlot | null>(null);
  // Identifies the SHAPE of the chart — how many series and what they are
  // called. uPlot fixes its options at construction, so a change here needs a
  // rebuild; new numbers for the same shape do not.
  const shape = series.map((s) => `${s.label}|${s.color ?? ""}|${s.unit ?? ""}`).join("");
  const built = useRef<string>("");

  useEffect(() => {
    let disposed = false;
    let plot: uPlot | null = null;
    let ro: ResizeObserver | null = null;

    // Imported here rather than at module scope: uPlot touches `document` on
    // load, and this file is prerendered on the server.
    void import("uplot").then(({ default: UPlot }) => {
      const el = host.current;
      if (disposed || !el) return;
      const { xs, ys } = alignSeries(series);

      plot = new UPlot(
        {
          width: el.clientWidth || 600,
          height,
          cursor: { sync: { key: syncKey }, points: { size: 6 } },
          scales: { x: { time: true } },
          legend: { live: true },
          axes: [
            { stroke: "#737373", grid: { stroke: "#262626", width: 1 }, ticks: { stroke: "#262626" } },
            {
              stroke: "#737373",
              grid: { stroke: "#262626", width: 1 },
              ticks: { stroke: "#262626" },
              size: 52,
            },
          ],
          series: [
            { label: "시각" },
            ...series.map((s, i) => ({
              label: s.label,
              stroke: s.color ?? PALETTE[i % PALETTE.length],
              width: 1.5,
              // A gap stays a gap.
              spanGaps: false,
              value: (_u: uPlot, v: number | null) =>
                v === null ? "—" : `${v.toLocaleString("ko-KR", { maximumFractionDigits: 3 })}${s.unit ?? ""}`,
            })),
          ],
        },
        [xs, ...ys] as unknown as uPlot.AlignedData,
        el,
      );
      chart.current = plot;
      built.current = shape;

      ro = new ResizeObserver((entries) => {
        const w = entries[0]?.contentRect.width;
        if (w && w > 0) plot?.setSize({ width: w, height });
      });
      ro.observe(el);
    });

    return () => {
      disposed = true;
      ro?.disconnect();
      plot?.destroy();
      chart.current = null;
      built.current = "";
    };
    // The data is deliberately absent: a refresh must not tear the canvas down
    // and build a new one. New numbers are pushed in by the effect below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shape, height, syncKey]);

  useEffect(() => {
    const plot = chart.current;
    if (!plot || built.current !== shape) return;
    const { xs, ys } = alignSeries(series);
    plot.setData([xs, ...ys] as unknown as uPlot.AlignedData);
  }, [series, shape]);

  if (series.length === 0) {
    return <div className="py-6 text-center text-[11px] text-neutral-600">이 구간에 데이터가 없습니다.</div>;
  }

  return <div ref={host} className="w-full overflow-hidden" style={{ minHeight: height }} />;
}
