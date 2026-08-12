"use client";

import { useEffect, useState } from "react";
import {
  getKubePanelAction,
  getMetricsPanelAction,
  getWafPanelAction,
} from "@/app/actions/dashboard";
import type {
  KubePanel,
  MetricsPanel,
  Status,
  WafPanel,
  WindowSelection,
} from "@/lib/types";
import { fmtClock, usePoll, type PollState } from "./shared";
import { WindowBar } from "./WindowBar";
import { OverviewTab } from "./OverviewTab";
import { PerformanceTab } from "./PerformanceTab";
import { WafTab } from "./WafTab";
import { LogTab } from "./LogTab";
import { SandboxTab } from "./SandboxTab";
import { AiTab } from "./AiTab";
import { CheckTab } from "./CheckTab";

// One tab per job: what is happening (요약), how the workload performs and how
// to change it (성능), what the firewall sees and does (방화벽), what the logs
// say (로그), whether the service answers right now (점검), whether a rule is
// safe (시험), and what to hand to Amazon Q (AI).
const TABS = [
  { id: "Overview", ko: "요약" },
  { id: "Performance", ko: "성능" },
  { id: "WAF", ko: "방화벽" },
  { id: "Logs", ko: "로그" },
  { id: "Check", ko: "점검" },
  { id: "Sandbox", ko: "시험" },
  { id: "AI", ko: "규칙생성" },
] as const;
type Tab = (typeof TABS)[number]["id"];

export interface PodSelection {
  pod: string;
  container: string;
}

type SegStatus = Status | "NODATA";

interface Segment {
  label: string;
  status: SegStatus;
}

function worst(...statuses: (Status | undefined)[]): SegStatus {
  const present = statuses.filter((s): s is Status => s !== undefined);
  if (present.length === 0) return "NODATA";
  if (present.includes("CRITICAL")) return "CRITICAL";
  if (present.includes("WARNING")) return "WARNING";
  return "NORMAL";
}

function buildSegments(
  kube: KubePanel | null,
  kubeError: string | null,
  metrics: MetricsPanel | null,
): Segment[] {
  const m = (key: string): Status | undefined =>
    metrics?.metrics.find((x) => x.key === key)?.status;

  const alb = worst(m("targetResponseTime"), m("http4xx"), m("http5xx"));
  const rds = worst(m("rdsClientConnections"), m("rdsDatabaseConnections"));
  const waf = worst(m("wafBlocked"), m("wafAllowed"));

  let k8s: SegStatus = "NODATA";
  if (kube) {
    k8s =
      kube.nodesTotal === 0
        ? "NODATA"
        : kube.nodesReady < kube.nodesTotal
          ? "WARNING"
          : "NORMAL";
  } else if (kubeError) {
    k8s = "NODATA";
  }

  let pods: SegStatus = "NODATA";
  if (kube && kube.statusBreakdown.total > 0) {
    const b = kube.statusBreakdown;
    pods =
      b.crashLoop > 0 || b.oom > 0 || b.failed > 0
        ? "CRITICAL"
        : b.running < b.total
          ? "WARNING"
          : "NORMAL";
  }

  let anom: SegStatus = "NODATA";
  if (metrics) {
    anom =
      metrics.anomalies.length === 0
        ? "NORMAL"
        : metrics.anomalies.some((a) => a.severity === "CRITICAL")
          ? "CRITICAL"
          : "WARNING";
  }

  return [
    { label: "ALB", status: alb },
    { label: "RDS", status: rds },
    { label: "WAF", status: waf },
    { label: "K8S", status: k8s },
    { label: "PODS", status: pods },
    { label: "ANOM", status: anom },
  ];
}

const SEG_CLASS: Record<SegStatus, string> = {
  NORMAL: "bg-emerald-950/70 text-emerald-400",
  WARNING: "bg-amber-950/70 text-amber-400",
  CRITICAL: "ann-crit bg-red-950/80 text-red-400",
  NODATA: "bg-neutral-900 text-neutral-600",
};

function Annunciator({ segments }: { segments: Segment[] }) {
  return (
    <div
      role="status"
      aria-label="서브시스템 상태"
      className="flex overflow-hidden rounded-[4px] border border-neutral-800 bg-neutral-800"
    >
      {segments.map((s, i) => (
        <div
          key={s.label}
          title={`${s.label}: ${s.status}`}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 font-mono text-[10px] font-bold tracking-[0.12em] ${SEG_CLASS[s.status]} ${i > 0 ? "border-l border-neutral-800" : ""}`}
        >
          <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-current" />
          {s.label}
        </div>
      ))}
    </div>
  );
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
  const [tab, setTab] = useState<Tab>("Overview");
  const [podSelection, setPodSelection] = useState<PodSelection | null>(null);
  const [refreshSec, setRefreshSec] = useState<number>(5);
  const [incomingRule, setIncomingRule] = useState<{ id: number; ruleJson: string } | null>(null);
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
    tab === "WAF" || tab === "Overview" || tab === "Sandbox",
    [win.windowMin, win.intervalMin],
  );

  const refreshAll = (): void => {
    kube.refresh();
    metrics.refresh();
    waf.refresh();
  };

  const jumpToLogs = (pod: string, container: string): void => {
    setPodSelection({ pod, container });
    setTab("Logs");
  };

  // The AI tab builds a rule; the sandbox is where it gets judged. The id
  // makes a repeat send a new value, so the editor refills either way.
  const sendToSandbox = (ruleJson: string): void => {
    setIncomingRule({ id: Date.now(), ruleJson });
    setTab("Sandbox");
  };

  const anomalyCount = metrics.data?.anomalies.length ?? 0;
  const warningCount = kube.data?.events.length ?? 0;
  const segments = buildSegments(kube.data, kube.error, metrics.data);

  const navButton = (t: (typeof TABS)[number], compact: boolean): React.ReactNode => {
    const active = tab === t.id;
    const badge =
      t.id === "Overview" && anomalyCount > 0 ? (
        <span className="rounded-[3px] bg-red-900 px-1 font-mono text-[9px] text-red-200">
          {anomalyCount}
        </span>
      ) : t.id === "Performance" && warningCount > 0 ? (
        <span className="rounded-[3px] bg-amber-900 px-1 font-mono text-[9px] text-amber-200">
          {warningCount}
        </span>
      ) : null;
    return (
      <button
        key={t.id}
        type="button"
        onClick={() => setTab(t.id)}
        aria-current={active ? "page" : undefined}
        className={
          compact
            ? `flex shrink-0 items-center gap-1.5 rounded-[4px] px-2.5 py-1.5 font-mono text-[11px] font-semibold tracking-wide transition-colors ${
                active
                  ? "bg-neutral-800 text-neutral-100"
                  : "text-neutral-500 hover:bg-neutral-900 hover:text-neutral-300"
              }`
            : `flex w-full items-center justify-between border-l-2 px-4 py-2.5 text-left transition-colors ${
                active
                  ? "border-sky-400 bg-neutral-900 text-neutral-100"
                  : "border-transparent text-neutral-500 hover:bg-neutral-900/60 hover:text-neutral-300"
              }`
        }
      >
        <span className={compact ? "" : "flex items-baseline gap-2"}>
          <span className="font-mono text-[11px] font-bold tracking-[0.1em] uppercase">
            {t.id}
          </span>
          {!compact && <span className="text-[10px] text-neutral-600">{t.ko}</span>}
        </span>
        {badge}
      </button>
    );
  };

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-44 shrink-0 flex-col border-r border-neutral-800 bg-neutral-950 lg:flex">
        <div className="border-b border-neutral-800 px-4 py-4">
          <div className="font-mono text-[9px] font-bold tracking-[0.3em] text-sky-400">
            SKILLS // OPS
          </div>
          <h1 className="mt-1 text-sm font-bold text-neutral-100">트러블슈팅 콘솔</h1>
          <div className="mt-0.5 font-mono text-[9px] text-neutral-600">
            skills-eks · ap-northeast-2
          </div>
        </div>
        <nav aria-label="주요 메뉴" className="flex-1 py-2">
          {TABS.map((t) => navButton(t, false))}
        </nav>
        <div className="border-t border-neutral-800 px-4 py-3 font-mono text-[9px] leading-4 text-neutral-600">
          <div>K8S {kube.lastUpdated === null ? "--" : fmtClock(kube.lastUpdated)}</div>
          <div>CW&nbsp; {metrics.lastUpdated === null ? "--" : fmtClock(metrics.lastUpdated)}</div>
          <div>WAF {waf.lastUpdated === null ? "--" : fmtClock(waf.lastUpdated)}</div>
          <div className="mt-1 text-neutral-500">구간 {metrics.data?.window.label ?? "--"}</div>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-10 border-b border-neutral-800 bg-neutral-950/90 backdrop-blur">
          <div className="flex items-center justify-between gap-3 px-4 py-2">
            <div className="min-w-0 lg:hidden">
              <div className="font-mono text-[9px] font-bold tracking-[0.3em] text-sky-400">
                SKILLS // OPS
              </div>
            </div>
            <div className="hidden min-w-0 lg:block">
              <Annunciator segments={segments} />
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Clock />
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
          <div className="px-4 pb-2 lg:hidden">
            <div className="mb-2 overflow-x-auto">
              <Annunciator segments={segments} />
            </div>
            <nav aria-label="주요 메뉴" className="flex gap-1 overflow-x-auto">
              {TABS.map((t) => navButton(t, true))}
            </nav>
          </div>
        </header>

        <main className="mx-auto max-w-[1500px] p-4">
          {tab === "Overview" && (
            <OverviewTab kube={kube} metrics={metrics} waf={waf} onJumpToLogs={jumpToLogs} />
          )}
          {tab === "Performance" && (
            <PerformanceTab
              kube={kube}
              metrics={metrics}
              onJumpToLogs={jumpToLogs}
              window={win}
            />
          )}
          {tab === "WAF" && <WafTab waf={waf} metrics={metrics} />}
          {tab === "Logs" && (
            <LogTab
              kube={kube}
              selection={podSelection}
              onSelect={setPodSelection}
              window={win}
            />
          )}
          {tab === "Check" && <CheckTab />}
          {tab === "Sandbox" && <SandboxTab waf={waf} incomingRule={incomingRule} />}
          {tab === "AI" && <AiTab onSendToSandbox={sendToSandbox} window={win} />}
        </main>
      </div>
    </div>
  );
}
