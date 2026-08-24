// CloudWatch Logs Insights runner. One query with a hard deadline; the window is
// clamped so scan volume stays bounded no matter what the caller asks for. On
// deadline the query is stopped server-side (StopQuery).

import {
  GetQueryResultsCommand,
  StartQueryCommand,
  StopQueryCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { setTimeout as sleep } from "node:timers/promises";

import { INSIGHTS_LIMITS } from "../config/thresholds.ts";
import type { AWS } from "./clients.ts";

export type InsightsRow = Record<string, string>;

export interface InsightsResult {
  rows: InsightsRow[];
  bytesScanned: number;
  recordsMatched: number;
  windowLabel: string;
}

export interface InsightsParams {
  /**
   * One log group, or several separated by commas — ECS task definitions
   * usually give each service its own awslogs group (/ecs/user, /ecs/product,
   * /ecs/stress), and one query over all of them is what the panels want.
   */
  logGroup: string;
  query: string;
  windowMs?: number;
  /**
   * Explicit bounds from the page's shared window. Given these, the query covers
   * exactly the span every other panel covers.
   */
  startMs?: number;
  endMs?: number;
  deadlineMs?: number;
  /**
   * Which region's Logs endpoint holds this group. A CLOUDFRONT-scope WAF log
   * group only exists in us-east-1 — querying it from the workload region
   * returns ResourceNotFoundException, which reads as "logging is off".
   */
  region?: string;
}

/**
 * Queues behind a small semaphore — Logs Insights allows few concurrent queries
 * per account and each one costs money.
 */
export async function runInsightsQuery(a: AWS, p: InsightsParams): Promise<InsightsResult> {
  const deadlineMs = p.deadlineMs ?? INSIGHTS_LIMITS.queryDeadlineMs;
  const explicit = p.startMs !== undefined && p.endMs !== undefined;

  let windowMs: number;
  if (explicit) windowMs = p.endMs! - p.startMs!;
  else if (p.windowMs && p.windowMs > 0) windowMs = p.windowMs;
  else windowMs = INSIGHTS_LIMITS.defaultWindowMs;
  // The cap applies either way: it is what bounds bytes scanned.
  windowMs = Math.min(windowMs, INSIGHTS_LIMITS.maxWindowMs);

  const endMs = explicit ? p.endMs! : Date.now();
  const endSec = Math.floor(endMs / 1000);
  const startSec = endSec - Math.floor(windowMs / 1000);
  const windowLabel = `${Math.floor((windowMs + 30_000) / 60_000)}m`;

  const client = a.logs(p.region || a.settings.region());

  return a.insightsSem.run(async () => {
    const groups = splitLogGroups(p.logGroup);
    const started = await client.send(
      new StartQueryCommand({
        // StartQuery takes either one name or a list, never both.
        ...(groups.length > 1 ? { logGroupNames: groups } : { logGroupName: p.logGroup }),
        startTime: startSec,
        endTime: endSec,
        queryString: p.query,
      }),
    );
    const queryId = started.queryId;
    if (!queryId) throw new Error("StartQuery failed (no queryId)");

    const stopAt = Date.now() + deadlineMs;
    for (;;) {
      await sleep(700);
      const res = await client.send(new GetQueryResultsCommand({ queryId }));

      if (res.status === "Complete") {
        const rows: InsightsRow[] = (res.results ?? []).map((fields) => {
          const row: InsightsRow = {};
          for (const f of fields) {
            if (f.field && f.value !== undefined) row[f.field] = f.value;
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
      if (Date.now() > stopAt) {
        // Best effort — the deadline error is the one that matters.
        try {
          await client.send(new StopQueryCommand({ queryId }));
        } catch {
          // ignored
        }
        throw new Error(`Logs Insights 쿼리 데드라인 초과 (${Math.round(deadlineMs / 1000)}s)`);
      }
    }
  });
}

/**
 * Turns the setting's comma-separated value into the list StartQuery takes.
 * A single name comes back as a one-element list.
 */
export function splitLogGroups(raw: string): string[] {
  return raw
    .split(",")
    .map((g) => g.trim())
    .filter((g) => g !== "");
}

export function fmtBytes(n: number): string {
  if (n >= 1024 * 1024 * 1024) return `${(n / 1024 / 1024 / 1024).toFixed(2)}GB`;
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)}MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${n}B`;
}
