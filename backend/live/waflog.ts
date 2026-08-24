// The WAF's own record of each request, as rows rather than aggregates.
//
// Everything else on this dashboard reads the WAF through counters: how many
// were blocked, which paths, which User-Agents. That answers "what is happening"
// and cannot answer "what happened to *this* request" — which rule ended it,
// what the client sent, what code went back. Those questions come up exactly
// when a block is disputed, and the only place the answer exists is the full
// log.
//
// GetSampledRequests is not a substitute: it samples 500 per rule over WAF's own
// three-hour window, it only ever sees requests a rule matched, and it cannot
// follow the window the operator selected.

import { toIso } from "../analysis/logfields.ts";
import { maskText } from "../analysis/mask.ts";
import { runInsightsQuery, type InsightsRow } from "../awsx/insights.ts";
import { cached } from "../cache/cache.ts";
import { POLLING } from "../config/config.ts";
import type { ResolvedWindow, WafLogQueryResult, WafLogRow } from "../../src/lib/types.ts";
import type { WafLogParams } from "../service/provider.ts";
import type { LiveProvider } from "./live.ts";
import { atoiF, firstNonEmpty, validatePathFilter } from "./shared.ts";

const WAF_ROW_LIMIT = 500;

/**
 * Same convention as the app-log query: one parse per field. The UA regex keeps
 * the inline (?i) flag because this log's header names are written by CloudFront
 * in mixed case ("User-Agent").
 */
export const UA_PARSE = `parse @message /"name":"(?i)user-agent","value":"(?<ua>[^"]*)"/`;

/**
 * The task appends requestid to the query string, so the WAF sees it in args. It
 * is what lines a WAF row up with the app's log line for the same request.
 */
export const RID_PARSE = `parse httpRequest.args /requestid=(?<rid>[0-9A-Za-z-]+)/`;

const WAF_ACTIONS = new Set(["ALL", "BLOCK", "ALLOW", "COUNT"]);

const NO_WAF_LOG_GROUP =
  "WAF 로그 그룹이 설정되지 않았습니다 — 설정 화면의 WAF_LOG_GROUP 에 로그 그룹 이름을 넣으세요. " +
  "(CLOUDFRONT 스코프의 WAF 로그는 us-east-1 에만 존재합니다.)";

export function buildWafLogQuery(action: string, pathContains: string): string {
  const want = action || "ALL";
  if (!WAF_ACTIONS.has(want)) throw new Error(`알 수 없는 동작 필터: ${want}`);

  const parts = [
    "fields @timestamp, action, terminatingRuleId, terminatingRuleType, responseCodeSent," +
      " httpRequest.clientIp as ip, httpRequest.country as country," +
      " httpRequest.httpMethod as method, httpRequest.uri as uri, httpRequest.args as args," +
      " ruleGroupList.0.terminatingRule.ruleId as sub0, ruleGroupList.1.terminatingRule.ruleId as sub1",
    UA_PARSE,
    RID_PARSE,
  ];
  if (want !== "ALL") parts.push(`filter action = "${want}"`);
  const path = validatePathFilter(pathContains);
  if (path !== "") parts.push(`filter uri like "${path}"`);
  parts.push("sort @timestamp desc", `limit ${WAF_ROW_LIMIT}`);
  return parts.join(" | ");
}

function toWafLogRow(r: InsightsRow): WafLogRow {
  const code = atoiF(r.responseCodeSent);
  return {
    ts: toIso(r["@timestamp"] ?? ""),
    action: r.action ?? "",
    rule: r.terminatingRuleId ?? "",
    // A managed group reports itself as the terminating rule; the sub-rule is
    // the one an operator can actually act on (override it, scope it down).
    subRule: firstNonEmpty(r.sub1, r.sub0),
    ip: r.ip ?? "",
    country: r.country ?? "",
    method: r.method ?? "",
    uri: r.uri ?? "",
    // Query strings carry ids and e-mail addresses in this scenario, so they
    // leave the server masked like every other log text (spec §20).
    args: maskText(r.args ?? "").slice(0, 200),
    requestId: r.rid ?? "",
    userAgent: r.ua ?? "",
    responseCode: code > 0 ? code : null,
  };
}

export function wafLogRows(
  p: LiveProvider,
  params: WafLogParams,
  win: ResolvedWindow,
): Promise<WafLogQueryResult> {
  const logGroup = p.settings.wafLogGroup();
  if (logGroup === "") return Promise.reject(new Error(NO_WAF_LOG_GROUP));

  // Validation fails before anything is cached — a rejected filter is a user
  // error, not a cacheable result.
  const query = buildWafLogQuery(params.action, params.pathContains);
  const key = `waflog:rows:${logGroup}:${params.action}:${params.pathContains}:${win.windowMin}-${win.endMs}`;

  return cached(
    key,
    POLLING.logCacheTtl,
    async () => {
      // To now, not to the window's floored end — this is a tail, and the last
      // partial minute is the part being watched (same reason as the app request
      // log).
      const endMs = Math.max(win.endMs, p.now());
      const res = await runInsightsQuery(p.aws, {
        logGroup,
        region: p.settings.wafRegion(),
        query,
        startMs: win.startMs,
        endMs,
      });
      const rows = res.rows.map(toWafLogRow);
      return {
        rows,
        totalMatched: res.recordsMatched,
        scannedBytes: res.bytesScanned,
        windowLabel: res.windowLabel,
        truncated: rows.length >= WAF_ROW_LIMIT,
        logGroup,
      };
    },
    POLLING.logFailTtl,
  );
}
