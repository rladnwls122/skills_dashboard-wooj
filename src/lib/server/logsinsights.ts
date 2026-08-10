import "server-only";
import {
  GetQueryResultsCommand,
  StartQueryCommand,
  StopQueryCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { logsClientRegional } from "./aws";
import { INSIGHTS_LIMITS } from "./config";

export interface InsightsRow {
  [field: string]: string;
}

export interface InsightsResult {
  rows: InsightsRow[];
  bytesScanned: number;
  recordsMatched: number;
  windowLabel: string;
}

// Concurrency semaphore — Logs Insights allows few concurrent queries per
// account and each one costs money; queue instead of fanning out.
let active = 0;
const waiters: (() => void)[] = [];

async function acquire(): Promise<void> {
  if (active < INSIGHTS_LIMITS.maxConcurrent) {
    active += 1;
    return;
  }
  await new Promise<void>((resolve) => waiters.push(resolve));
  active += 1;
}

function release(): void {
  active -= 1;
  waiters.shift()?.();
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// Runs one Logs Insights query with a hard deadline. The window is clamped to
// INSIGHTS_LIMITS.maxWindowMs so scan volume stays bounded no matter what the
// caller asks for. On deadline the query is stopped server-side (StopQuery).
export async function runInsightsQuery(params: {
  logGroup: string;
  query: string;
  windowMs?: number;
  deadlineMs?: number;
}): Promise<InsightsResult> {
  const windowMs = Math.min(
    params.windowMs ?? INSIGHTS_LIMITS.defaultWindowMs,
    INSIGHTS_LIMITS.maxWindowMs,
  );
  const deadlineMs = params.deadlineMs ?? INSIGHTS_LIMITS.queryDeadlineMs;
  const endSec = Math.floor(Date.now() / 1000);
  const startSec = endSec - Math.floor(windowMs / 1000);
  const windowLabel = `${Math.round(windowMs / 60_000)}m`;

  const client = logsClientRegional();
  await acquire();
  try {
    const started = await client.send(
      new StartQueryCommand({
        logGroupName: params.logGroup,
        startTime: startSec,
        endTime: endSec,
        queryString: params.query,
      }),
    );
    const queryId = started.queryId;
    if (!queryId) throw new Error("StartQuery failed (no queryId)");

    const deadline = Date.now() + deadlineMs;
    for (;;) {
      await sleep(700);
      const res = await client.send(new GetQueryResultsCommand({ queryId }));
      if (res.status === "Complete") {
        const rows: InsightsRow[] = (res.results ?? []).map((fields) => {
          const row: InsightsRow = {};
          for (const f of fields) {
            if (f.field !== undefined && f.value !== undefined) row[f.field] = f.value;
          }
          return row;
        });
        return {
          rows,
          bytesScanned: res.statistics?.bytesScanned ?? 0,
          recordsMatched: res.statistics?.recordsMatched ?? 0,
          windowLabel,
        };
      }
      if (res.status === "Failed" || res.status === "Cancelled" || res.status === "Timeout") {
        throw new Error(`Logs Insights query ${res.status}`);
      }
      if (Date.now() > deadline) {
        try {
          await client.send(new StopQueryCommand({ queryId }));
        } catch {
          // best effort — the deadline error is the one that matters
        }
        throw new Error(`Logs Insights 쿼리 데드라인 초과 (${deadlineMs / 1000}s)`);
      }
    }
  } finally {
    release();
  }
}

export function fmtBytes(n: number): string {
  if (n >= 1024 * 1024 * 1024) return `${(n / 1024 / 1024 / 1024).toFixed(2)}GB`;
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)}MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${n}B`;
}
