// Pod log reads and the app request-log query. Log reads/aggregations go to
// CloudWatch Logs Insights (bills per byte scanned — results cached 30s,
// failures 10s); the k8s API remains for previous-container logs and as a
// fallback.
//
// Every query here parses the competition binaries' gin access line (see
// analysis/logfields.ts) — the log group may be an ECS awslogs group or an
// EKS Container Insights group, and the parse handles both.

import { ACCESS_LOG_FILTER, cleanPath, ERROR_LINE_LIKE, PARSE_FIELDS } from "../analysis/logfields.ts";
import { hhmmss, toIso } from "../analysis/logfields.ts";
import { maskLine, maskLines } from "../analysis/mask.ts";
import { errMsg } from "../awsx/clients.ts";
import { RID_PARSE, UA_PARSE } from "./waflog.ts";
import { aggregateFingerprints } from "../analysis/fingerprint.ts";
import { analyzeRequestLog } from "../analysis/requestlog.ts";
import { runInsightsQuery, type InsightsParams, type InsightsResult } from "../awsx/insights.ts";
import { cached, put } from "../cache/cache.ts";
import { POLLING } from "../config/config.ts";
import type {
  PathLatencyStat,
  PodLogsResult,
  RequestLogAnalysis,
  RequestLogEntry,
  RequestLogQueryResult,
  RequestLogRow,
  ResolvedWindow,
} from "../../src/lib/types.ts";
import type { PodLogsParams, RequestLogParams } from "../service/provider.ts";
import type { LiveProvider } from "./live.ts";
import { atoiF, parseF, validatePathFilter, windowKey } from "./shared.ts";

/**
 * Pod/container names reach Logs Insights query strings — refuse anything that
 * is not a plain DNS-1123 name instead of trying to escape it.
 */
const POD_NAME_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

/**
 * Narrows a query to one pod/task. Container Insights tags every event with
 * kubernetes.pod_name; an ECS awslogs group has no such field but names its
 * streams "<prefix>/<container>/<task-id>", so the stream name is the fallback.
 * A missing field is simply false in Insights, never an error.
 */
function podScope(pod: string, container: string): string {
  if (!POD_NAME_RE.test(pod)) throw new Error(`invalid pod: ${pod}`);
  let f = `(kubernetes.pod_name = "${pod}" or @logStream like "${pod}")`;
  if (container !== "") {
    if (!POD_NAME_RE.test(container)) throw new Error(`invalid container: ${container}`);
    f += ` and (kubernetes.container_name = "${container}" or @logStream like "/${container}/")`;
  }
  return f;
}

/**
 * The log line as the binary wrote it: the "log" field when a Container
 * Insights shipper wrapped it in JSON, the raw @message otherwise.
 */
const LINE_FIELD = "coalesce(log, @message) as line";

interface PodLogsFetch {
  lines: string[];
  scannedBytes: number;
  windowLabel: string;
  source: "insights" | "kubernetes";
  analysis: RequestLogAnalysis | null;
}

function clampTail(n: number): number {
  return Math.min(Math.max(n, 10), 2000);
}

async function fetchPodLogsInsights(
  p: LiveProvider,
  params: PodLogsParams,
  win: ResolvedWindow,
): Promise<PodLogsFetch> {
  const scope = podScope(params.pod, params.container);
  const tail = clampTail(params.tailLines);
  const base: Omit<InsightsParams, "query"> = {
    logGroup: p.settings.appLogGroup(),
    startMs: win.startMs,
    endMs: win.endMs,
  };
  const run = (query: string): Promise<InsightsResult> =>
    runInsightsQuery(p.aws, { ...base, query });

  // The four reads are independent; the semaphore in runInsightsQuery caps real
  // concurrency at the account-safe limit.
  const [tailQ, statsQ, nonOkQ, errWarnQ] = await Promise.allSettled([
    run(
      `fields @timestamp, ${LINE_FIELD} | filter ${scope} | sort @timestamp desc | limit ${tail}`,
    ),
    run(
      `filter ${scope} | ${PARSE_FIELDS} | ${ACCESS_LOG_FILTER} | stats count(*) as cnt, avg(latency_ms) as avgMs, max(latency_ms) as maxMs, sum(status < 200 or status >= 300) as nonOk by path | sort cnt desc | limit 1000`,
    ),
    run(
      `filter ${scope} | ${PARSE_FIELDS} | filter ispresent(status) and (status < 200 or status >= 300) | display @timestamp, method, path, status, latency_ms, client_ip, requestid | sort @timestamp desc | limit 100`,
    ),
    run(
      `fields @timestamp, ${LINE_FIELD} | filter ${scope} and @message like ${ERROR_LINE_LIKE} | sort @timestamp desc | limit 100`,
    ),
  ]);

  if (tailQ.status === "rejected") throw tailQ.reason as Error;

  const lines = maskLines(
    [...tailQ.value.rows]
      .reverse()
      .map((r) => toIso(r["@timestamp"] ?? "") + " " + (r.line ?? "").replace(/\n+$/, "")),
  );

  const fetch: PodLogsFetch = {
    lines,
    scannedBytes: tailQ.value.bytesScanned,
    windowLabel: tailQ.value.windowLabel,
    source: "insights",
    analysis: null,
  };

  if (statsQ.status === "fulfilled") {
    fetch.scannedBytes += statsQ.value.bytesScanned;
    const byPath: PathLatencyStat[] = [];
    let totalRequests = 0;
    let weighted = 0;
    let maxLatency = 0;
    let nonOkFromStats = 0;

    for (const r of statsQ.value.rows) {
      const count = atoiF(r.cnt);
      const avg = Math.round(parseF(r.avgMs) * 100) / 100;
      const max = Math.round(parseF(r.maxMs) * 100) / 100;
      const nonOk = atoiF(r.nonOk);
      byPath.push({
        path: cleanPath(r.path ?? ""),
        count,
        avgLatencyMs: avg,
        maxLatencyMs: max,
        nonOkCount: nonOk,
      });
      totalRequests += count;
      weighted += avg * count;
      if (max > maxLatency) maxLatency = max;
      nonOkFromStats += nonOk;
    }

    const nonOkEntries: RequestLogEntry[] = [];
    let nonOkTotal = nonOkFromStats;
    if (nonOkQ.status === "fulfilled") {
      fetch.scannedBytes += nonOkQ.value.bytesScanned;
      nonOkTotal = nonOkQ.value.recordsMatched;
      for (const r of nonOkQ.value.rows) {
        nonOkEntries.push({
          ts: hhmmss(toIso(r["@timestamp"] ?? "")),
          method: r.method ?? "",
          path: cleanPath(r.path ?? ""),
          status: atoiF(r.status),
          latencyMs: parseF(r.latency_ms),
          clientIp: r.client_ip ?? "",
          requestId: r.requestid ?? "",
        });
      }
    }

    let errorWarnLines: string[] = [];
    let errorWarnTotal = 0;
    if (errWarnQ.status === "fulfilled") {
      fetch.scannedBytes += errWarnQ.value.bytesScanned;
      errorWarnTotal = errWarnQ.value.recordsMatched;
      errorWarnLines = maskLines(
        errWarnQ.value.rows.map(
          (r) => toIso(r["@timestamp"] ?? "") + " " + (r.line ?? "").replace(/\n+$/, ""),
        ),
      );
    }

    fetch.analysis = {
      entries: [],
      nonOkEntries,
      errorWarnLines,
      avgLatencyMs: totalRequests > 0 ? Math.round((weighted / totalRequests) * 100) / 100 : null,
      maxLatencyMs: byPath.length > 0 ? maxLatency : null,
      byPath: byPath.slice(0, 20),
      totalRequests,
      nonOkTotal,
      errorWarnTotal,
      basis: `Logs Insights ${fetch.windowLabel} 전체 — [GIN] 액세스 라인 기준 (샘플 목록은 최근 100건)`,
    };
  }

  return fetch;
}

async function fetchPodLogsKube(
  p: LiveProvider,
  params: PodLogsParams,
): Promise<PodLogsFetch> {
  const lines = await p.kube.getPodLogs(
    params.pod,
    params.container,
    params.previous,
    params.tailLines,
  );
  return {
    lines,
    scannedBytes: 0,
    windowLabel: `tail ${params.tailLines}`,
    source: "kubernetes",
    analysis: null,
  };
}

export async function podLogs(
  p: LiveProvider,
  params: PodLogsParams,
  win: ResolvedWindow,
): Promise<PodLogsResult> {
  const key = `logs:${params.pod}:${params.container}:${params.previous}:${params.tailLines}:${windowKey(win)}`;
  const fetched = await cached(
    key,
    POLLING.logCacheTtl,
    async () => {
      if (params.previous) return fetchPodLogsKube(p, params);
      try {
        return await fetchPodLogsInsights(p, params, win);
      } catch {
        return fetchPodLogsKube(p, params);
      }
    },
    POLLING.logFailTtl,
  );

  const fingerprints = aggregateFingerprints([{ pod: params.pod, lines: fetched.lines }]);
  let requestLog: RequestLogAnalysis;
  if (fetched.analysis) {
    requestLog = fetched.analysis;
  } else {
    requestLog = analyzeRequestLog(fetched.lines);
    requestLog.basis = `tail ${params.tailLines} 샘플 (k8s API)`;
  }

  put("panel:fingerprints", 10 * 60_000, fingerprints);
  put("panel:" + (params.previous ? "lastprevlogs" : "lastlogs"), 10 * 60_000, {
    pod: params.pod,
    container: params.container,
    previous: params.previous,
    lines: fetched.lines,
  });

  return {
    lines: fetched.lines,
    container: params.container,
    previous: params.previous,
    fingerprints,
    requestLog,
    source: fetched.source,
    windowLabel: fetched.windowLabel,
    scannedBytes: fetched.source === "insights" ? fetched.scannedBytes : 0,
  };
}

// --- app request-log query ---------------------------------------------------

const ROW_LIMIT = 200;
/**
 * How many requestids one WAF-side join query carries. Insights truncates
 * silently past 10,000 rows; this stays far under it.
 */
const UA_JOIN_BATCH = 200;

const STATUS_RANGE: Record<string, [number, number]> = {
  "2xx": [200, 300],
  "3xx": [300, 400],
  "4xx": [400, 500],
  "5xx": [500, 600],
};

function buildRequestLogQuery(statusClass: string, pathContains: string): string {
  const parts = [PARSE_FIELDS, ACCESS_LOG_FILTER];
  if (statusClass !== "ALL") {
    const r = STATUS_RANGE[statusClass];
    if (!r) throw new Error(`알 수 없는 상태 클래스: ${statusClass}`);
    parts.push(`filter status >= ${r[0]} and status < ${r[1]}`);
  }
  const path = validatePathFilter(pathContains);
  if (path !== "") parts.push(`filter path like "${path}"`);
  parts.push(
    "display @timestamp, method, path, status, latency_ms, client_ip, requestid, @message",
    "sort @timestamp desc",
    `limit ${ROW_LIMIT}`,
  );
  return parts.join(" | ");
}

/**
 * The WAF side of the User-Agent join: the WAF log has the UA the app never
 * writes, keyed by the same requestid the app's access line carries in its
 * query string.
 */
function buildUaJoinQuery(requestIds: string[]): string {
  const quoted = requestIds.map((id) => `"${id.replaceAll('"', "")}"`);
  return [
    "fields @timestamp",
    UA_PARSE,
    RID_PARSE,
    `filter rid in [${quoted.join(", ")}]`,
    "display rid, ua",
    `limit ${requestIds.length * 2}`,
  ].join(" | ");
}

/**
 * Fills userAgent from the WAF log for every row that carries a requestid. Best
 * effort: a failed or absent WAF log leaves the rows as they were and says why
 * in uaJoinNote.
 */
async function joinUserAgents(
  p: LiveProvider,
  out: RequestLogQueryResult,
  win: ResolvedWindow,
): Promise<void> {
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const r of out.rows) {
    if (r.requestId === "" || seen.has(r.requestId)) continue;
    seen.add(r.requestId);
    ids.push(r.requestId);
  }
  if (ids.length === 0) {
    if (out.rows.length > 0) {
      out.uaJoinNote =
        "requestid 가 있는 행이 없음 (POST 는 requestid 를 body 로 보내 액세스 라인에 남지 않는다)";
    }
    return;
  }
  const wafGroup = p.settings.wafLogGroup();
  if (wafGroup === "") {
    out.uaJoinNote = "WAF_LOG_GROUP 미설정 — User-Agent 결합 불가";
    return;
  }
  const uaById = new Map<string, string>();
  for (let start = 0; start < ids.length; start += UA_JOIN_BATCH) {
    const batch = ids.slice(start, start + UA_JOIN_BATCH);
    let res;
    try {
      res = await runInsightsQuery(p.aws, {
        logGroup: wafGroup,
        region: p.settings.wafRegion(),
        query: buildUaJoinQuery(batch),
        startMs: win.startMs,
        endMs: win.endMs,
      });
    } catch (e) {
      out.uaJoinNote = "WAF 로그 결합 실패: " + errMsg(e);
      return;
    }
    out.scannedBytes += res.bytesScanned;
    for (const r of res.rows) {
      const rid = r.rid ?? "";
      const ua = r.ua ?? "";
      if (rid !== "" && ua !== "") uaById.set(rid, ua);
    }
  }
  for (const row of out.rows) {
    const ua = uaById.get(row.requestId);
    if (ua !== undefined) {
      row.userAgent = ua;
      row.uaSource = "waf";
      out.uaJoined++;
    }
  }
  if (out.uaJoined === 0) {
    out.uaJoinNote = "WAF 로그에서 같은 requestid 를 찾지 못함 (WAF 로그 구간·샘플링 확인)";
  }
}

export function requestLogRows(
  p: LiveProvider,
  params: RequestLogParams,
  win: ResolvedWindow,
): Promise<RequestLogQueryResult> {
  // Validation lives in the query builder and fails before anything is cached —
  // a rejected filter is a user error, not a cacheable result.
  const query = buildRequestLogQuery(params.statusClass, params.pathContains);
  const key = `applog:rows:${params.statusClass}:${params.pathContains}:${win.windowMin}-${win.endMs}`;
  return cached(
    key,
    POLLING.logCacheTtl,
    async () => {
      const res = await runInsightsQuery(p.aws, {
        logGroup: p.settings.appLogGroup(),
        query,
        startMs: win.startMs,
        endMs: win.endMs,
      });
      const rows: RequestLogRow[] = res.rows.map((r) => ({
        ts: toIso(r["@timestamp"] ?? ""),
        method: r.method ?? "",
        path: cleanPath(r.path ?? ""),
        status: atoiF(r.status),
        latencyMs: parseF(r.latency_ms),
        clientIp: r.client_ip ?? "",
        requestId: r.requestid ?? "",
        userAgent: "",
        uaSource: "",
        raw: maskLine((r["@message"] ?? "").replace(/\n+$/, "")),
      }));
      const out: RequestLogQueryResult = {
        rows,
        totalMatched: res.recordsMatched,
        scannedBytes: res.bytesScanned,
        windowLabel: res.windowLabel,
        truncated: rows.length >= ROW_LIMIT,
        uaJoined: 0,
        uaJoinNote: "",
      };
      await joinUserAgents(p, out, win);
      return out;
    },
    POLLING.logFailTtl,
  );
}
