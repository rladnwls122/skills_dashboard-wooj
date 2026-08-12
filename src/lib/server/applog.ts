import "server-only";
import { cached } from "./cache";
import { ENV, POLLING } from "./config";
import { runInsightsQuery } from "./logsinsights";
import type { ResolvedWindow } from "@/lib/types";
import { ROW_LIMIT, buildRequestLogQuery, toRequestLogRow, type StatusClass } from "./applogquery";
import type { RequestLogQueryResult } from "@/lib/types";

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
  const query = buildRequestLogQuery(params);
  const key = `applog:rows:${params.statusClass}:${params.pathContains}:${params.win ? `${params.win.windowMin}-${params.win.endMs}` : (params.windowMs ?? "default")}`;
  return cached(
    key,
    POLLING.logCacheTtlMs,
    async () => {
      const res = await runInsightsQuery({
        logGroup: ENV.appLogGroup,
        query,
        windowMs: params.windowMs,
        startMs: params.win?.startMs,
        endMs: params.win?.endMs,
      });
      const rows = res.rows.map(toRequestLogRow);
      return {
        rows,
        totalMatched: res.recordsMatched,
        scannedBytes: res.bytesScanned,
        windowLabel: res.windowLabel,
        truncated: rows.length >= ROW_LIMIT,
      };
    },
    POLLING.logFailTtlMs,
  );
}
