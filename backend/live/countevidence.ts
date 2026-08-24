// What a COUNT rule actually caught, and whether any of it was legitimate.
//
// A count of matches is not enough to promote a rule to BLOCK: twenty matches
// could be twenty attacks or twenty real users. The only way to tell from the
// outside is to line each matched request up with what the application did with
// it — a 2xx means the request was served normally, and blocking it would have
// cost availability.
//
// Two queries, not one. The WAF log for a CLOUDFRONT-scope Web ACL lives in
// us-east-1 while the application log lives in the workload region, and Logs
// Insights cannot cross regions. So: pull the matched requests, take their
// request ids, ask the application log about those ids, and join here.
//
// GET only, and that is final. The task appends requestid/uuid to the query
// string and the app reads them from there, so POST/PUT carry no join key on
// either side. Those matches are reported as unjoinable rather than folded into
// either bucket — the screen must not invent evidence it does not have.

import { ACCESS_LOG_FILTER, PARSE_FIELDS, toIso } from "../analysis/logfields.ts";
import { errMsg } from "../awsx/clients.ts";
import { runInsightsQuery } from "../awsx/insights.ts";
import type { CountEvidence, CountMatch, CountVerdict, ResolvedWindow } from "../../src/lib/types.ts";
import type { LiveProvider } from "./live.ts";
import { atoiF, parseF } from "./shared.ts";

/**
 * GetSampledRequests caps at 500 per rule and the count set is small by
 * construction; a higher cap would only add rows nobody scrolls to.
 */
const MATCH_LIMIT = 500;
/**
 * How many ids one join query carries. Insights takes an `in` list inline, so
 * this bounds the query text as well as the scan.
 */
const JOIN_BATCH = 200;

/** Escapes a rule name for embedding in an Insights regex literal. */
function escapeForRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

/**
 * Finds the requests a COUNT rule matched.
 *
 * The obvious filter — `action = "COUNT"` — never matches anything. A counting
 * rule does not terminate evaluation, so the request's action is whatever the
 * rest of the ACL decided, normally ALLOW. The match is recorded in
 * `nonTerminatingMatchingRules`, which appears both at the top level and again
 * inside each `ruleGroupList` entry.
 *
 * Matched by regex on the raw message rather than by enumerating
 * `nonTerminatingMatchingRules.<i>.ruleId` at every index and nesting depth. Two
 * known imprecisions, both acceptable here: a request this rule counted but
 * another rule blocked is excluded (we only care whether the rule would break
 * legitimate traffic, and that traffic was not served either way), and a rule
 * whose name is quoted inside another field would false-positive.
 */
export function buildCountQuery(ruleName: string): string {
  return [
    // One `fields` stage, not two. Every stage of an Insights pipeline must
    // begin with a command; a bare field expression on its own is a
    // MalformedQueryException, which made this whole query fail every time.
    "fields @timestamp, httpRequest.uri as uri, httpRequest.args as args, httpRequest.httpMethod as method",
    `filter @message like /"ruleId":"${escapeForRegex(ruleName)}"/`,
    `filter action != "BLOCK"`,
    "sort @timestamp desc",
    `limit ${MATCH_LIMIT}`,
  ].join(" | ");
}

/**
 * The application's side of the join. `limit` is explicit because Insights
 * truncates at 10,000 rows silently, and a silent truncation here would read as
 * "no legitimate traffic was caught".
 */
function buildJoinQuery(requestIds: string[]): string {
  const quoted = requestIds.map((id) => `"${id.replaceAll('"', "")}"`);
  return [
    PARSE_FIELDS,
    ACCESS_LOG_FILTER,
    `filter requestid in [${quoted.join(", ")}]`,
    "fields requestid, status, latency_ms, path, method",
    `limit ${requestIds.length}`,
  ].join(" | ");
}

/**
 * Reads the join key out of the query string. The WAF log stores it verbatim,
 * with or without a leading "?". `requestid` is the key the app side parses out
 * of its access line; `uuid` is kept as a fallback for a row that only carries
 * that one.
 */
export function extractRequestId(args: string): string | null {
  if (args === "") return null;
  const q = args.replace(/^\?/, "");
  for (const pair of q.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const key = pair.slice(0, eq);
    if (key !== "requestid" && key !== "uuid") continue;
    const raw = pair.slice(eq + 1);
    if (raw === "") continue;
    try {
      return decodeURIComponent(raw);
    } catch {
      // A malformed escape is still a usable literal key.
      return raw;
    }
  }
  return null;
}

/**
 * A served request is one the application answered 2xx. Anything else — an
 * error, a 404, a redirect — is not evidence that blocking would have cost
 * anything.
 */
export function verdictFor(status: number | null): CountVerdict {
  if (status === null) return "unjoinable";
  return status >= 200 && status < 300 ? "normal" : "abnormal";
}

function summarize(ruleName: string, matches: CountMatch[]): CountEvidence {
  const out: CountEvidence = {
    ruleName,
    total: matches.length,
    matches,
    normal: 0,
    abnormal: 0,
    unjoinable: 0,
    bytesScanned: 0,
    notes: [],
  };
  for (const m of matches) {
    if (m.verdict === "normal") out.normal++;
    else if (m.verdict === "abnormal") out.abnormal++;
    else out.unjoinable++;
  }
  return out;
}

/**
 * Says whether the evidence supports promoting the rule to BLOCK. Advisory only
 * — the button is never disabled by this, because waiting for a sample during a
 * two-hour match can cost more than the rule is worth.
 */
export function promotionNote(e: CountEvidence): string {
  if (e.normal > 0) {
    return `정상 응답을 받은 요청 ${e.normal}건이 이 규칙에 걸렸습니다 — 승격하면 그만큼 403이 나갑니다.`;
  }
  if (e.total < 20) {
    return `표본 부족 (${e.total}건). 20건 이상 쌓인 뒤 판단하는 편이 안전합니다.`;
  }
  return `매칭 ${e.total}건 중 정상 응답 0건. 승격해도 정상 트래픽에 닿지 않습니다.`;
}

export async function countEvidence(
  p: LiveProvider,
  ruleName: string,
  win: ResolvedWindow,
): Promise<CountEvidence> {
  if (ruleName.trim() === "") throw new Error("규칙 이름이 비어 있습니다.");

  const logGroup = p.settings.wafLogGroup();
  if (logGroup === "") {
    const out = summarize(ruleName, []);
    out.notes = ["WAF 로그 그룹이 설정되지 않아 COUNT 실측을 읽을 수 없습니다. 설정에서 지정하세요."];
    return out;
  }

  const wafRes = await runInsightsQuery(p.aws, {
    logGroup,
    region: p.settings.wafRegion(),
    query: buildCountQuery(ruleName),
    startMs: win.startMs,
    endMs: win.endMs,
  });

  const notes: string[] = [];
  const matches: CountMatch[] = wafRes.rows.map((r) => {
    const args = r.args ?? "";
    return {
      ts: toIso(r["@timestamp"] ?? ""),
      method: r.method ?? "",
      uri: r.uri ?? "",
      args,
      requestId: extractRequestId(args),
      status: null,
      latencyMs: null,
      verdict: "unjoinable",
    };
  });
  if (matches.length === MATCH_LIMIT) {
    notes.push(`매칭이 ${MATCH_LIMIT}건 상한에 닿았습니다 — 실제로는 더 많습니다.`);
  }

  const ids: string[] = [];
  const seen = new Set<string>();
  for (const m of matches) {
    if (!m.requestId || seen.has(m.requestId)) continue;
    seen.add(m.requestId);
    ids.push(m.requestId);
  }

  let bytes = wafRes.bytesScanned;
  if (ids.length > 0 && p.settings.appLogGroup() !== "") {
    const byId = new Map<string, { status: number | null; latency: number | null }>();
    for (let start = 0; start < ids.length; start += JOIN_BATCH) {
      const batch = ids.slice(start, start + JOIN_BATCH);
      let appRes;
      try {
        appRes = await runInsightsQuery(p.aws, {
          logGroup: p.settings.appLogGroup(),
          region: p.settings.region(),
          query: buildJoinQuery(batch),
          startMs: win.startMs,
          endMs: win.endMs,
        });
      } catch (e) {
        // The WAF half is still worth showing: the matches are real and the join
        // is what could not be made.
        notes.push("앱 로그 조인 실패 — 정상/비정상 판정 없이 매칭만 표시합니다: " + errMsg(e));
        break;
      }
      bytes += appRes.bytesScanned;
      for (const row of appRes.rows) {
        // Insights results are sparse: a field with no value is absent, not
        // empty, so every read has to tolerate the missing value.
        const id = row.requestid;
        if (!id) continue;
        byId.set(id, {
          status: row.status ? atoiF(row.status) : null,
          latency: row.latency_ms ? parseF(row.latency_ms) : null,
        });
      }
    }
    for (const m of matches) {
      if (!m.requestId) continue;
      const hit = byId.get(m.requestId);
      if (!hit) continue;
      m.status = hit.status;
      m.latencyMs = hit.latency;
      m.verdict = verdictFor(hit.status);
    }
  }

  const noKey = matches.filter((m) => !m.requestId).length;
  if (noKey > 0) {
    notes.push(
      `${noKey}건은 조인 키가 없습니다 (POST/PUT은 requestid가 쿼리스트링에 실리지 않습니다). 정상/비정상 어느 쪽으로도 세지 않았습니다.`,
    );
  }

  const out = summarize(ruleName, matches);
  out.bytesScanned = bytes;
  out.notes = [...notes, promotionNote(out)];
  return out;
}
