"use client";

import { useEffect, useState } from "react";
import {
  getKubePanelAction,
  getMetricsPanelAction,
  getWafPanelAction,
} from "@/app/actions/dashboard";
import type { KubePanel, MetricsPanel, WafPanel, WindowSelection } from "@/lib/types";
import { fmtClock, usePoll, ZoomDialog, type PollState } from "./shared";
import { WindowBar } from "./WindowBar";
import { PerformanceTab } from "./PerformanceTab";
import { TrafficTab } from "./TrafficTab";
import { AiTab } from "./AiTab";
import { SettingsTab } from "./SettingsTab";

// Three tabs, one question each: is anything wrong right now (성능), what is
// arriving (트래픽), what do we block (규칙 생성).
//
// Settings is not a tab: values are discovered automatically, and the screen
// only exists to override a wrong guess — so it lives behind the gear.
const TABS = [
  { id: "Performance", ko: "성능" },
  { id: "Traffic", ko: "트래픽" },
  { id: "Generate", ko: "규칙 생성" },
] as const;
type Tab = (typeof TABS)[number]["id"];

export interface PodSelection {
  pod: string;
  container: string;
}

function Clock() {
  const [now, setNow] = useState<string | null>(null);
  useEffect(() => {
    const pad = (n: number): string => String(n).padStart(2, "0");
    const tick = (): void => {
      const d = new Date();
      setNow(`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <time className="font-mono text-sm font-bold tracking-[0.08em] text-neutral-300 tabular-nums">
      {now ?? "--:--:--"}
    </time>
  );
}

export function DashboardClient() {
  const [tab, setTab] = useState<Tab>("Performance");
  const [podSelection, setPodSelection] = useState<PodSelection | null>(null);
  const [refreshSec, setRefreshSec] = useState<number>(5);
  const [settingsOpen, setSettingsOpen] = useState(false);
  // One window for the whole page. Every panel that reads a time range reads
  // this one, so two numbers on screen always cover the same span.
  const [win, setWin] = useState<WindowSelection>({ windowMin: 60, intervalMin: 1 });

  // User-selected auto-refresh interval drives all panels; server-side TTL
  // caps upstream AWS/K8s calls, so faster polling stays safe.
  const kube: PollState<KubePanel> = usePoll(getKubePanelAction, refreshSec * 1000);
  const metrics: PollState<MetricsPanel> = usePoll(
    () => getMetricsPanelAction(win),
    refreshSec * 1000,
    true,
    [win.windowMin, win.intervalMin],
  );
  const waf: PollState<WafPanel> = usePoll(
    () => getWafPanelAction(win),
    Math.max(refreshSec, 30) * 1000,
    tab === "Traffic" || tab === "Generate",
    [win.windowMin, win.intervalMin],
  );

  const refreshAll = (): void => {
    kube.refresh();
    metrics.refresh();
    waf.refresh();
  };

  // Drill-down is a tab move. The window is global, so the span follows on its
  // own and nothing else needs to be carried across.
  const jumpToLogs = (pod: string, container: string): void => {
    setPodSelection({ pod, container });
    setTab("Traffic");
  };

  const navButton = (t: (typeof TABS)[number]): React.ReactNode => {
    const active = tab === t.id;
    return (
      <button
        key={t.id}
        type="button"
        onClick={() => setTab(t.id)}
        aria-current={active ? "page" : undefined}
        className={`flex shrink-0 items-baseline gap-1.5 rounded-[4px] px-2.5 py-1.5 transition-colors ${
          active
            ? "bg-neutral-800 text-neutral-100"
            : "text-neutral-500 hover:bg-neutral-900 hover:text-neutral-300"
        }`}
      >
        <span className="font-mono text-[11px] font-bold tracking-[0.1em] uppercase">{t.id}</span>
        {/* The Korean name is what the runbook calls the tab, so it stays
            visible where there is room rather than only in a tooltip. */}
        <span className="hidden text-[10px] text-neutral-600 sm:inline">{t.ko}</span>
      </button>
    );
  };

  return (
    <div className="min-h-screen">
      {/* Everything that steers the page lives in this bar: which tab, which
          window, how fresh. The sidebar it replaces cost 176px of width on
          every screen to hold three buttons. */}
      <header className="sticky top-0 z-10 border-b border-neutral-800 bg-neutral-950/90 backdrop-blur">
        <div className="flex items-center gap-3 px-4 py-2">
          <div className="min-w-0 shrink-0">
            <div className="font-mono text-[9px] font-bold tracking-[0.3em] text-sky-400">
              SKILLS // OPS
            </div>
            <h1 className="truncate font-mono text-[9px] text-neutral-600">
              skills-eks · ap-northeast-2
            </h1>
          </div>

          <nav
            aria-label="주요 메뉴"
            className="flex min-w-0 flex-1 gap-1 overflow-x-auto border-l border-neutral-800 pl-3"
          >
            {TABS.map((t) => navButton(t))}
          </nav>

          <div className="hidden shrink-0 font-mono text-[9px] leading-4 text-neutral-600 xl:block">
            <div>
              K8S {kube.lastUpdated === null ? "--" : fmtClock(kube.lastUpdated)} · CW{" "}
              {metrics.lastUpdated === null ? "--" : fmtClock(metrics.lastUpdated)}
            </div>
            <div>WAF {waf.lastUpdated === null ? "--" : fmtClock(waf.lastUpdated)}</div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Clock />
            <button
              type="button"
              onClick={() => setSettingsOpen(true)}
              aria-label="설정"
              title="설정"
              className="rounded-[4px] px-2 py-1 font-mono text-sm text-neutral-500 hover:bg-neutral-900 hover:text-neutral-200"
            >
              ⚙
            </button>
          </div>
        </div>
        {/* The window is a caption for every number below it, so it sits on
            its own row at full width rather than being squeezed into the
            status row and truncated. */}
        <div className="border-t border-neutral-800/60 px-4 py-1.5">
          <WindowBar
            window={win}
            onChange={setWin}
            resolved={metrics.data?.window ?? null}
            refreshSec={refreshSec}
            onRefreshSec={setRefreshSec}
            onRefresh={refreshAll}
            lastUpdated={metrics.lastUpdated}
            busy={metrics.loading}
          />
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] p-4">
        {tab === "Performance" && (
          <PerformanceTab kube={kube} metrics={metrics} onJumpToLogs={jumpToLogs} window={win} />
        )}
        {tab === "Traffic" && (
          <TrafficTab
            kube={kube}
            metrics={metrics}
            selection={podSelection}
            onSelect={setPodSelection}
            onMakeUaRule={() => setTab("Generate")}
            window={win}
          />
        )}
        {tab === "Generate" && <AiTab waf={waf} window={win} />}
      </main>

      <ZoomDialog open={settingsOpen} onClose={() => setSettingsOpen(false)} label="설정">
        <div className="p-4">
          <SettingsTab />
        </div>
      </ZoomDialog>
    </div>
  );
}
