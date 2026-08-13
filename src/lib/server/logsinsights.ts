import "server-only";
import {
  GetQueryResultsCommand,
  StartQueryCommand,
  StopQueryCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { logsClientFor, logsClientRegional } from "./aws";
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
  // Explicit bounds from the page's shared window. Given these, the query
  // covers exactly the span every other panel covers — a lookback computed
  // from "now" at call time would drift panel by panel.
  startMs?: number;
  endMs?: number;
  deadlineMs?: number;
  // Which region's Logs endpoint holds this group. The application log lives in
  // the workload region, but a CLOUDFRONT-scope WAF log group only exists in
  // us-east-1 — querying it from the workload region returns
  // ResourceNotFoundException, which reads as "logging is off" and sends the
  // operator to fix something that is not broken.
  region?: string;
}): Promise<InsightsResult> {
  const deadlineMs = params.deadlineMs ?? INSIGHTS_LIMITS.queryDeadlineMs;
  const explicit = params.startMs !== undefined && params.endMs !== undefined;
  // The cap applies either way: it is what bounds bytes scanned, and a caller
  // asking for more than four hours is asking for an unbounded bill.
  const windowMs = Math.min(
    explicit
      ? (params.endMs as number) - (params.startMs as number)
      : (params.windowMs ?? INSIGHTS_LIMITS.defaultWindowMs),
    INSIGHTS_LIMITS.maxWindowMs,
  );
  const endSec = Math.floor((explicit ? (params.endMs as number) : Date.now()) / 1000);
  const startSec = endSec - Math.floor(windowMs / 1000);
  const windowLabel = `${Math.round(windowMs / 60_000)}m`;

  const client = params.region ? logsClientFor(params.region) : logsClientRegional();
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
