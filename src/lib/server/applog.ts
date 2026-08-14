import "server-only";
import { cached } from "./cache";
import { ENV, LOW_PRIORITY_PATHS, POLLING } from "./config";
import { runInsightsQuery } from "./logsinsights";
import { maskLine } from "./mask";
import type { RequestLogRow, ResolvedWindow } from "@/lib/types";
import { ROW_LIMIT, buildRequestLogQuery, toRequestLogRow, type StatusClass } from "./applogquery";
import { fetchUaByRequestId } from "./waflog";
import type { RequestLogQueryResult } from "@/lib/types";

// Filling in the User-Agent the app does not log.
//
// The app writes app/client_ip/latency_ms/method/path/status/ts/requestid/uuid
// and no header, so its own request log can never say who sent a request — the
// one column a rule is built from. The WAF logged the same request one hop
// earlier, with the headers, and both sides carry the task's requestid: the
// app because it writes it as a field, the WAF because it arrives in the query
// string. So the two rows are joined on that id.
//
// Deliberately not joined on time. At this traffic rate a second holds dozens
// of requests to the same path, so a timestamp match would attach a plausible
// User-Agent to the wrong request — and a wrong UA is worse than a blank one
// here, because it is what a blocking rule gets written from.
//
// POST and PUT keep an empty column: the app only reads requestid from the
// query string, so its log line has no id to join on.
async function joinUserAgents(
  rows: RequestLogRow[],
  win: ResolvedWindow | undefined,
): Promise<{ joined: number; note: string }> {
  const missing = rows.filter((r) => !r.userAgent);
  if (!win || missing.length === 0) return { joined: 0, note: "" };
  if (!ENV.wafLogGroup) {
    return {
      joined: 0,
      note: "User-Agent 는 앱 로그에 없습니다 — WAF_LOG_GROUP 을 설정하면 requestid 로 WAF 로그와 결합해 채웁니다.",
    };
  }
  const joinable = missing.filter((r) => r.requestId);
  try {
    const uaByRid = await fetchUaByRequestId(win);
    let joined = 0;
    for (const row of missing) {
      const ua = row.requestId ? uaByRid.get(row.requestId) : undefined;
      if (!ua) continue;
      row.userAgent = ua;
      row.uaSource = "waf";
      joined += 1;
    }
    const noId = missing.length - joinable.length;
    const note =
      joined === 0 && joinable.length > 0
        ? "WAF 로그에서 같은 requestid 를 찾지 못했습니다 — 창이 어긋났거나 WAF 로그가 그 구간을 담고 있지 않습니다."
        : noId > 0
          ? `${noId}건은 requestid 가 없어 결합 대상이 아닙니다 (앱이 POST·PUT 에서는 requestid 를 기록하지 않음).`
          : "";
    return { joined, note };
  } catch (e) {
    // A failed join must not take the request log down with it — the rows are
    // the point, the User-Agent is the bonus.
    return { joined: 0, note: `WAF 로그 결합 실패: ${e instanceof Error ? e.message : String(e)}` };
  }
}

// Logs Insights bills per byte scanned, so this never polls on a timer — it
// runs on mount, on a filter change, and on an explicit refresh. Results are
// cached per filter combination so toggling back and forth is free.
export async function fetchRequestLogRows(params: {
  statusClass: StatusClass;
  pathContains: string;
  windowMs?: number;
  win?: ResolvedWindow;
}): Promise<RequestLogQueryResult> {
  // Validation lives in the query builder and throws before anything is
  // cached — a rejected filter is a user error, not a cacheable result.
  const query = buildRequestLogQuery({ ...params, excludePaths: LOW_PRIORITY_PATHS });
  const key = `applog:rows:${params.statusClass}:${params.pathContains}:${params.win ? `${params.win.windowMin}-${params.win.endMs}` : (params.windowMs ?? "default")}`;
  return cached(
    key,
    POLLING.logCacheTtlMs,
    async () => {
      // Query to *now*, not to the window's end. Every other panel draws
      // buckets, so the shared window floors its end to an interval boundary to
      // keep the last bucket complete — but this panel is a tail, and that floor
      // is a full minute of requests it would refuse to show. The cache key
      // still carries the floored end; the 30s TTL is what bounds staleness.
      const res = await runInsightsQuery({
        logGroup: ENV.appLogGroup,
        query,
        windowMs: params.windowMs,
        startMs: params.win?.startMs,
        endMs: params.win ? Math.max(params.win.endMs, Date.now()) : undefined,
      });
      // Every log line leaves the server masked (spec §20) — the raw line
      // carried for the header view is no exception.
      const rows = res.rows.map(toRequestLogRow).map((r) => ({ ...r, raw: maskLine(r.raw) }));
      const { joined, note } = await joinUserAgents(rows, params.win);
      return {
        rows,
        totalMatched: res.recordsMatched,
        scannedBytes: res.bytesScanned,
        windowLabel: res.windowLabel,
        truncated: rows.length >= ROW_LIMIT,
        uaJoined: joined,
        uaJoinNote: note,
      };
    },
    POLLING.logFailTtlMs,
  );
}
