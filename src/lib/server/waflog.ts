import "server-only";

// The WAF's own record of each request, as rows rather than aggregates.
//
// Everything else on this dashboard reads the WAF through counters: how many
// were blocked, which paths, which User-Agents. That answers "what is
// happening" and cannot answer "what happened to *this* request" — which rule
// ended it, what the client sent, what code went back. Those questions come up
// exactly when a block is disputed, and the only place the answer exists is the
// full log.
//
// GetSampledRequests is not a substitute: it samples 500 per rule over WAF's
// own three-hour window, it only ever sees requests a rule matched, and it
// cannot follow the window the operator selected.
//
// The User-Agent is pulled off the raw message rather than a JSON field:
// headers arrive as an array whose index varies per request, so
// `httpRequest.headers.3.value` names a different header on every row.

import { cached } from "./cache";
import { ENV, POLLING, wafRegion } from "./config";
import { validatePathFilter } from "./applogquery";
import { runInsightsQuery } from "./logsinsights";
import { maskText } from "./mask";
import type { WafLogQueryResult, WafLogRow, ResolvedWindow } from "@/lib/types";

export type WafActionFilter = "ALL" | "BLOCK" | "ALLOW" | "COUNT";

export const WAF_ROW_LIMIT = 500;

// Same convention as the app-log query: one parse per field, and the UA regex
// keeps the inline (?i) flag because this log's header names are written by
// CloudFront in mixed case ("User-Agent") and the WAF stats queries already
// depend on it working here.
const UA_PARSE = 'parse @message /"name":"(?i)user-agent","value":"(?<ua>[^"]*)"/';
// The task appends requestid to the query string, so the WAF sees it in args.
// It is what lines a WAF row up with the app's log line for the same request.
const RID_PARSE = 'parse httpRequest.args /requestid=(?<rid>[0-9A-Za-z-]+)/';

export function buildWafLogQuery(params: {
  action: WafActionFilter;
  pathContains: string;
}): string {
  const parts = [
    "fields @timestamp, action, terminatingRuleId, terminatingRuleType, responseCodeSent," +
      " httpRequest.clientIp as ip, httpRequest.country as country," +
      " httpRequest.httpMethod as method, httpRequest.uri as uri, httpRequest.args as args," +
      " ruleGroupList.0.terminatingRule.ruleId as sub0, ruleGroupList.1.terminatingRule.ruleId as sub1",
    UA_PARSE,
    RID_PARSE,
  ];
  if (params.action !== "ALL") parts.push(`filter action = "${params.action}"`);
  const path = validatePathFilter(params.pathContains);
  if (path) parts.push(`filter uri like "${path}"`);
  parts.push("sort @timestamp desc");
  parts.push(`limit ${WAF_ROW_LIMIT}`);
  return parts.join(" | ");
}

function toWafLogRow(r: Record<string, string>): WafLogRow {
  const code = Number(r["responseCodeSent"] ?? "");
  return {
    ts: `${(r["@timestamp"] ?? "").replace(" ", "T")}Z`,
    action: r["action"] ?? "",
    rule: r["terminatingRuleId"] ?? "",
    // A managed group reports itself as the terminating rule; the sub-rule is
    // the one an operator can actually act on (override it, scope it down).
    subRule: r["sub1"] || r["sub0"] || "",
    ip: r["ip"] ?? "",
    country: r["country"] ?? "",
    method: r["method"] ?? "",
    uri: r["uri"] ?? "",
    // Query strings carry ids and e-mail addresses in this scenario, so they
    // leave the server masked like every other log text (spec §20).
    args: maskText(r["args"] ?? "").slice(0, 200),
    requestId: r["rid"] ?? "",
    userAgent: r["ua"] ?? "",
    responseCode: Number.isFinite(code) && code > 0 ? code : null,
  };
}

export const NO_WAF_LOG_GROUP =
  "WAF 로그 그룹이 설정되지 않았습니다 — 설정 화면의 WAF_LOG_GROUP 에 로그 그룹 이름을 넣으세요. " +
  "(CLOUDFRONT 스코프의 WAF 로그는 us-east-1 에만 존재합니다.)";

export async function fetchWafLogRows(params: {
  action: WafActionFilter;
  pathContains: string;
  win: ResolvedWindow;
}): Promise<WafLogQueryResult> {
  if (!ENV.wafLogGroup) throw new Error(NO_WAF_LOG_GROUP);
  const query = buildWafLogQuery(params);
  const key = `waflog:rows:${ENV.wafLogGroup}:${params.action}:${params.pathContains}:${params.win.windowMin}-${params.win.endMs}`;
  return cached(
    key,
    POLLING.logCacheTtlMs,
    async () => {
      const res = await runInsightsQuery({
        logGroup: ENV.wafLogGroup,
        region: wafRegion(),
        query,
        startMs: params.win.startMs,
        // To now, not to the window's floored end — this is a tail, and the
        // last partial minute is the part being watched (same reason as the
        // app request log).
        endMs: Math.max(params.win.endMs, Date.now()),
      });
      const rows = res.rows.map(toWafLogRow);
      return {
        rows,
        totalMatched: res.recordsMatched,
        scannedBytes: res.bytesScanned,
        windowLabel: res.windowLabel,
        truncated: rows.length >= WAF_ROW_LIMIT,
        logGroup: ENV.wafLogGroup,
      };
    },
    POLLING.logFailTtlMs,
  );
}

// requestId -> User-Agent, for joining the app's request log to what the WAF
// saw. Cached on the slow tier: it is a full-window scan of the WAF log, the
// answer barely moves between two app-log refreshes, and paying for it every
// 30s would triple this panel's bill.
export function fetchUaByRequestId(win: ResolvedWindow): Promise<Map<string, string>> {
  return cached(
    `waflog:ua-by-rid:${ENV.wafLogGroup}:${win.windowMin}-${win.endMs}`,
    POLLING.wafInsightsTtlMs,
    async () => {
      const res = await runInsightsQuery({
        logGroup: ENV.wafLogGroup,
        region: wafRegion(),
        // Grouped rather than listed: one row per (request, UA) would be
        // hundreds of thousands of rows for a map that only needs the pair.
        query: [
          UA_PARSE,
          RID_PARSE,
          "filter ispresent(rid) and ispresent(ua)",
          "stats count(*) as cnt by rid, ua",
          "sort cnt desc",
          "limit 10000",
        ].join(" | "),
        startMs: win.startMs,
        endMs: Math.max(win.endMs, Date.now()),
      });
      const map = new Map<string, string>();
      for (const row of res.rows) {
        const rid = row["rid"];
        const ua = row["ua"];
        if (rid && ua && !map.has(rid)) map.set(rid, ua);
      }
      return map;
    },
    POLLING.logFailTtlMs,
  );
}
