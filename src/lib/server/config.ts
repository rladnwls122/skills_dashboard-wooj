import "server-only";
import type { Status } from "@/lib/types";

export const ENV = {
  region: process.env.AWS_REGION ?? "ap-northeast-2",
  wafScope: (process.env.WAF_SCOPE === "REGIONAL" ? "REGIONAL" : "CLOUDFRONT") as
    | "REGIONAL"
    | "CLOUDFRONT",
  wafWebAclName: process.env.WAF_WEB_ACL_NAME ?? "skills-waf",
  albName: process.env.ALB_NAME ?? "skills-alb",
  eksClusterName: process.env.EKS_CLUSTER_NAME ?? "skills-eks",
  rdsProxyName: process.env.RDS_PROXY_NAME ?? "skills-db-proxy",
  wafLogGroup: process.env.WAF_LOG_GROUP ?? "",
  targetNamespace: process.env.TARGET_NAMESPACE ?? "default",
  maxReplicas: Number(process.env.MAX_REPLICAS ?? "20"),
  dbPath: process.env.DB_PATH ?? "./data/dashboard.db",
  appLogGroup:
    process.env.APP_LOG_GROUP ??
    `/aws/containerinsights/${process.env.EKS_CLUSTER_NAME ?? "skills-eks"}/application`,
} as const;

// WAF metrics/API for CLOUDFRONT scope live in us-east-1 only.
export const WAF_REGION = ENV.wafScope === "CLOUDFRONT" ? "us-east-1" : ENV.region;

// Paths excluded (or down-weighted) from anomaly scoring. `/healthcheck` is the
// task-3 app's ALB health check path.
export const LOW_PRIORITY_PATHS = [
  "/health",
  "/healthz",
  "/ready",
  "/readyz",
  "/liveness",
  "/healthcheck",
];

export function isLowPriorityPath(path: string): boolean {
  const p = path.split("?")[0] ?? path;
  return LOW_PRIORITY_PATHS.some((h) => p === h || p.startsWith(`${h}/`));
}

// The API surface this environment actually serves (ALB listener rules).
// Competition rule: the scenario's own load generator drives heavy traffic at
// these paths from a single IP, so request volume against them is never
// treated as an attack — no volumetric detection, no rate-based rule, no
// mention in the Amazon Q handoff. Traffic aimed anywhere else stays in scope.
export const APP_TRAFFIC_PATHS = (
  process.env.APP_TRAFFIC_PATHS ?? "/v1/user,/v1/product,/v1/stress,/v1/image"
)
  .split(",")
  .map((p) => p.trim())
  .filter((p) => p.length > 0);

export function isAppTrafficPath(path: string): boolean {
  const p = path.split("?")[0] ?? path;
  return APP_TRAFFIC_PATHS.some((a) => p === a || p.startsWith(`${a}/`));
}

export interface MetricThreshold {
  // WARNING when (abs >= warnAbs) OR (pct >= warnPct AND abs >= minAbs).
  // CRITICAL requires BOTH abs >= critAbs AND pct >= critPct — a single
  // criterion is never enough (false-positive guard, spec §8).
  warnAbs: number;
  critAbs: number;
  warnPct: number;
  critPct: number;
  minAbs: number;
}

export const THRESHOLDS: Record<string, MetricThreshold> = {
  targetResponseTime: { warnAbs: 0.5, critAbs: 2.0, warnPct: 80, critPct: 200, minAbs: 0.2 },
  http4xx: { warnAbs: 50, critAbs: 300, warnPct: 100, critPct: 300, minAbs: 20 },
  http5xx: { warnAbs: 20, critAbs: 100, warnPct: 100, critPct: 300, minAbs: 10 },
  rdsClientConnections: { warnAbs: 80, critAbs: 200, warnPct: 80, critPct: 200, minAbs: 20 },
  rdsDatabaseConnections: { warnAbs: 60, critAbs: 150, warnPct: 80, critPct: 200, minAbs: 15 },
  wafBlocked: { warnAbs: 50, critAbs: 500, warnPct: 100, critPct: 400, minAbs: 20 },
};

export function statusFor(key: string, current: number, percentChange: number | null): Status {
  const t = THRESHOLDS[key];
  if (!t) return "NORMAL";
  const pct = percentChange ?? 0;
  if (current >= t.critAbs && pct >= t.critPct) return "CRITICAL";
  if (current >= t.warnAbs) return "WARNING";
  if (pct >= t.warnPct && current >= t.minAbs) return "WARNING";
  return "NORMAL";
}

export const POLLING = {
  kubeTtlMs: 2_500,
  metricsTtlMs: 25_000,
  wafTtlMs: 25_000,
  // Logs Insights bills per byte scanned — auto refresh minimum 30s, results
  // cached 30s, failures cached 10s.
  logAutoRefreshMs: 30_000,
  logCacheTtlMs: 30_000,
  logFailTtlMs: 10_000,
  verificationDelayMs: 120_000,
} as const;

export const INSIGHTS_LIMITS = {
  // Hard cap on any single query window — bounds bytes scanned structurally.
  maxWindowMs: 4 * 60 * 60_000,
  defaultWindowMs: 60 * 60_000,
  queryDeadlineMs: 20_000,
  maxConcurrent: 2,
} as const;

export const WAF_LIMITS = {
  // Default WCU quota per WebACL.
  maxWcu: 5_000,
  sampleWindowMinutes: 15,
} as const;
