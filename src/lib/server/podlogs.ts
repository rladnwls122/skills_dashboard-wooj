import "server-only";
import { ENV } from "./config";
import { getPodLogs } from "./k8s";
import { runInsightsQuery } from "./logsinsights";
import { maskLines } from "./mask";
import { PARSE_FIELDS, hhmmss, toIso } from "./logfields";
import type { RequestLogAnalysis, RequestLogEntry } from "@/lib/types";

export interface PodLogsFetch {
  lines: string[];
  scannedBytes: number;
  windowLabel: string;
  source: "insights" | "kubernetes";
  analysis: RequestLogAnalysis | null;
}

// Pod/container names reach Logs Insights query strings — refuse anything that
// is not a plain DNS-1123 name instead of trying to escape it.
const NAME_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

function assertName(value: string, what: string): void {
  if (!NAME_RE.test(value)) throw new Error(`invalid ${what}: ${value}`);
}

function podScope(pod: string, container: string): string {
  assertName(pod, "pod");
  let f = `kubernetes.pod_name = "${pod}"`;
  if (container) {
    assertName(container, "container");
    f += ` and kubernetes.container_name = "${container}"`;
  }
  return f;
}

// All log reads and aggregations run in CloudWatch Logs Insights — nothing is
// accumulated locally, so cost/latency stays flat no matter how long the app
// runs. Aggregate numbers come from query statistics (recordsMatched) or full
// stats rows, never from the length of a truncated sample list.
export async function fetchPodLogsInsights(params: {
  pod: string;
  container: string;
  tailLines: number;
}): Promise<PodLogsFetch> {
  const scope = podScope(params.pod, params.container);
  const tail = Math.min(Math.max(params.tailLines, 10), 2000);

  const [tailQ, statsQ, nonOkQ, errWarnQ] = await Promise.allSettled([
    runInsightsQuery({
      logGroup: ENV.appLogGroup,
      query: `fields @timestamp, log | filter ${scope} | sort @timestamp desc | limit ${tail}`,
    }),
    runInsightsQuery({
      logGroup: ENV.appLogGroup,
      query: `filter ${scope} | ${PARSE_FIELDS} | filter ispresent(path) | stats count(*) as cnt, avg(latency_ms) as avgMs, max(latency_ms) as maxMs, sum(status >= 300) as nonOk by path | sort cnt desc | limit 1000`,
    }),
    runInsightsQuery({
      logGroup: ENV.appLogGroup,
      query: `filter ${scope} | ${PARSE_FIELDS} | filter status >= 300 | fields @timestamp, method, path, status, latency_ms | sort @timestamp desc | limit 100`,
    }),
    runInsightsQuery({
      logGroup: ENV.appLogGroup,
      query: `fields @timestamp, log | filter ${scope} and log like /(?i)(error|warn)/ | sort @timestamp desc | limit 100`,
    }),
  ]);

  if (tailQ.status === "rejected") throw tailQ.reason;

  const lines = maskLines(
    tailQ.value.rows
      .slice()
      .reverse()
      .map((r) => `${toIso(r["@timestamp"] ?? "")} ${r["log"] ?? ""}`),
  );

  let scannedBytes = tailQ.value.bytesScanned;
  const windowLabel = tailQ.value.windowLabel;

  let analysis: RequestLogAnalysis | null = null;
  if (statsQ.status === "fulfilled") {
    scannedBytes += statsQ.value.bytesScanned;
    const byPath = statsQ.value.rows.map((r) => ({
      path: r["path"] ?? "",
      count: Number(r["cnt"] ?? "0"),
      avgLatencyMs: Math.round(Number(r["avgMs"] ?? "0") * 100) / 100,
      maxLatencyMs: Math.round(Number(r["maxMs"] ?? "0") * 100) / 100,
      nonOkCount: Number(r["nonOk"] ?? "0"),
    }));
    const totalRequests = byPath.reduce((a, p) => a + p.count, 0);
    const weighted = byPath.reduce((a, p) => a + p.avgLatencyMs * p.count, 0);

    let nonOkEntries: RequestLogEntry[] = [];
    let nonOkTotal = byPath.reduce((a, p) => a + p.nonOkCount, 0);
    if (nonOkQ.status === "fulfilled") {
      scannedBytes += nonOkQ.value.bytesScanned;
      nonOkTotal = nonOkQ.value.recordsMatched;
      nonOkEntries = nonOkQ.value.rows.map((r) => ({
        ts: hhmmss(toIso(r["@timestamp"] ?? "")),
        method: r["method"] ?? "",
        path: r["path"] ?? "",
        status: Number(r["status"] ?? "0"),
        latencyMs: Number(r["latency_ms"] ?? "0"),
      }));
    }

    let errorWarnLines: string[] = [];
    let errorWarnTotal = 0;
    if (errWarnQ.status === "fulfilled") {
      scannedBytes += errWarnQ.value.bytesScanned;
      errorWarnTotal = errWarnQ.value.recordsMatched;
      errorWarnLines = maskLines(
        errWarnQ.value.rows.map((r) => `${toIso(r["@timestamp"] ?? "")} ${r["log"] ?? ""}`),
      );
    }

    analysis = {
      entries: [],
      nonOkEntries,
      errorWarnLines,
      avgLatencyMs:
        totalRequests > 0 ? Math.round((weighted / totalRequests) * 100) / 100 : null,
      maxLatencyMs:
        byPath.length > 0
          ? Math.max(...byPath.map((p) => p.maxLatencyMs))
          : null,
      byPath: byPath.slice(0, 20),
      totalRequests,
      nonOkTotal,
      errorWarnTotal,
      basis: `Logs Insights ${windowLabel} 전체 (샘플 목록은 최근 100건)`,
    };
  }

  return { lines, scannedBytes, windowLabel, source: "insights", analysis };
}

// Fallback: direct Kubernetes API tail. Used for previous-container logs
// (restart forensics — Insights cannot separate container instances) and when
// Insights itself fails.
export async function fetchPodLogsKube(params: {
  pod: string;
  container: string;
  previous: boolean;
  tailLines: number;
}): Promise<PodLogsFetch> {
  const lines = await getPodLogs(params);
  return {
    lines,
    scannedBytes: 0,
    windowLabel: `tail ${params.tailLines}`,
    source: "kubernetes",
    analysis: null,
  };
}
