import "server-only";

// What a COUNT rule actually caught, and whether any of it was legitimate.
//
// A count of matches is not enough to promote a rule to BLOCK: twenty matches
// could be twenty attacks or twenty real users. The only way to tell from the
// outside is to line each matched request up with what the application did
// with it — a 2xx means the request was served normally, and blocking it would
// have cost availability.
//
// Two queries, not one. The WAF log for a CLOUDFRONT-scope Web ACL lives in
// us-east-1 while the application log lives in the workload region, and Logs
// Insights cannot cross regions. So: pull the matched requests, take their
// request ids, ask the application log about those ids, and join here.
//
// GET only, and that is final. The task appends requestid/uuid to the query
// string and the app reads them from there, so POST/PUT carry no join key on
// either side. Those matches are reported as unjoinable rather than folded
// into either bucket — the screen must not invent evidence it does not have.

import { ENV, wafRegion } from "./config";
import { PARSE_FIELDS, toIso } from "./logfields";
import { runInsightsQuery } from "./logsinsights";

// GetSampledRequests caps at 500 per rule and the count set is small by
// construction; a higher cap would only add rows nobody scrolls to.
const MATCH_LIMIT = 500;
// How many ids one join query carries. Insights takes an `in` list inline, so
// this bounds the query text as well as the scan.
const JOIN_BATCH = 200;

export type CountVerdict = "normal" | "abnormal" | "unjoinable";

export interface CountMatch {
  ts: string;
  method: string;
  uri: string;
  args: string;
  requestId: string | null;
  // Filled from the application log when the ids line up.
  status: number | null;
  latencyMs: number | null;
  verdict: CountVerdict;
}

export interface CountEvidence {
  ruleName: string;
  total: number;
  normal: number;
  abnormal: number;
  unjoinable: number;
  matches: CountMatch[];
  bytesScanned: number;
  notes: string[];
}

// --- query construction ----------------------------------------------------

// Escapes a rule name for embedding in an Insights regex literal.
export function escapeForRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

// Requests a COUNT rule matched.
//
// The obvious filter — `action = "COUNT"` — never matches anything. A counting
// rule does not terminate evaluation, so the request's action is whatever the
// rest of the ACL decided, normally ALLOW. The match is recorded in
// `nonTerminatingMatchingRules`, which appears both at the top level and again
// inside each `ruleGroupList` entry.
//
// ponytail: matched by regex on the raw message rather than by enumerating
// `nonTerminatingMatchingRules.<i>.ruleId` at every index and nesting depth.
// Two known imprecisions, both acceptable here: a request this rule counted but
// another rule blocked is excluded (we only care whether the rule would break
// legitimate traffic, and that traffic was not served either way), and a rule
// whose name is quoted inside another field would false-positive. Enumerate the
// indices if either ever bites.
export function buildCountQuery(ruleName: string): string {
  return [
    "fields @timestamp, httpRequest.uri as uri, httpRequest.args as args",
    "httpRequest.httpMethod as method",
    `filter @message like /"ruleId":"${escapeForRegex(ruleName)}"/`,
    'filter action != "BLOCK"',
    "sort @timestamp desc",
    `limit ${MATCH_LIMIT}`,
  ].join(" | ");
}

// The application's side of the join. `limit` is explicit because Insights
// truncates at 10,000 rows silently, and a silent truncation here would read
// as "no legitimate traffic was caught".
export function buildJoinQuery(requestIds: string[]): string {
  const list = requestIds.map((id) => `"${id.replace(/"/g, "")}"`).join(", ");
  return [
    "fields @timestamp, log",
    PARSE_FIELDS,
    `filter requestid in [${list}]`,
    "fields requestid, status, latency_ms, path, method",
    `limit ${requestIds.length}`,
  ].join(" | ");
}

// --- join key --------------------------------------------------------------

// The WAF log stores the query string verbatim, with or without a leading "?".
// Either `requestid` or `uuid` is the join key — the task appends both and the
// app writes both, but only one is present on some paths.
export function extractRequestId(args: string): string | null {
  if (!args) return null;
  const q = args.startsWith("?") ? args.slice(1) : args;
  for (const pair of q.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const key = pair.slice(0, eq);
    if (key !== "requestid" && key !== "uuid") continue;
    const raw = pair.slice(eq + 1);
    if (!raw) continue;
    try {
      return decodeURIComponent(raw);
    } catch {
      // A malformed escape is still a usable literal key.
      return raw;
    }
  }
  return null;
}

// --- classification --------------------------------------------------------

// A served request is one the application answered 2xx. Anything else — an
// error, a 404, a redirect — is not evidence that blocking would have cost
// anything.
export function verdictFor(status: number | null): CountVerdict {
  if (status === null) return "unjoinable";
  return status >= 200 && status < 300 ? "normal" : "abnormal";
}

export function summarize(ruleName: string, matches: CountMatch[]): Omit<
  CountEvidence,
  "bytesScanned" | "notes"
> {
  let normal = 0;
  let abnormal = 0;
  let unjoinable = 0;
  for (const m of matches) {
    if (m.verdict === "normal") normal += 1;
    else if (m.verdict === "abnormal") abnormal += 1;
    else unjoinable += 1;
  }
  return { ruleName, total: matches.length, normal, abnormal, unjoinable, matches };
}

// Whether the evidence supports promoting the rule to BLOCK. Advisory only —
// the button is never disabled by this, because waiting for a sample during a
// two-hour match can cost more than the rule is worth.
export function promotionNote(e: Pick<CountEvidence, "total" | "normal">): string {
  if (e.normal > 0) {
    return `정상 응답을 받은 요청 ${e.normal}건이 이 규칙에 걸렸습니다 — 승격하면 그만큼 403이 나갑니다.`;
  }
  if (e.total < 20) return `표본 부족 (${e.total}건). 20건 이상 쌓인 뒤 판단하는 편이 안전합니다.`;
  return `매칭 ${e.total}건 중 정상 응답 0건. 승격해도 정상 트래픽에 닿지 않습니다.`;
}

// --- the two-stage read ----------------------------------------------------

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export async function countEvidence(
  ruleName: string,
  startMs: number,
  endMs: number,
): Promise<CountEvidence> {
  const notes: string[] = [];
  if (!ENV.wafLogGroup) {
    return {
      ...summarize(ruleName, []),
      bytesScanned: 0,
      notes: [
        "WAF 로그 그룹이 설정되지 않아 COUNT 실측을 읽을 수 없습니다. 설정에서 지정하세요.",
      ],
    };
  }

  const wafRes = await runInsightsQuery({
    logGroup: ENV.wafLogGroup,
    query: buildCountQuery(ruleName),
    startMs,
    endMs,
    region: wafRegion(),
  });

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
      verdict: "unjoinable" as CountVerdict,
    };
  });

  if (matches.length === MATCH_LIMIT) {
    notes.push(`매칭이 ${MATCH_LIMIT}건 상한에 닿았습니다 — 실제로는 더 많습니다.`);
  }

  const ids = [...new Set(matches.map((m) => m.requestId).filter((id): id is string => !!id))];
  let bytes = wafRes.bytesScanned;

  if (ids.length > 0 && ENV.appLogGroup) {
    const byId = new Map<string, { status: number | null; latencyMs: number | null }>();
    for (const batch of chunk(ids, JOIN_BATCH)) {
      const appRes = await runInsightsQuery({
        logGroup: ENV.appLogGroup,
        query: buildJoinQuery(batch),
        startMs,
        endMs,
        region: ENV.region,
      });
      bytes += appRes.bytesScanned;
      for (const row of appRes.rows) {
        // Insights results are sparse: a field with no value is absent, not
        // empty, so every read has to tolerate undefined.
        const id = row.requestid;
        if (!id) continue;
        const status = Number(row.status);
        const latency = Number(row.latency_ms);
        byId.set(id, {
          status: Number.isFinite(status) ? status : null,
          latencyMs: Number.isFinite(latency) ? latency : null,
        });
      }
    }
    for (const m of matches) {
      const hit = m.requestId ? byId.get(m.requestId) : undefined;
      if (!hit) continue;
      m.status = hit.status;
      m.latencyMs = hit.latencyMs;
      m.verdict = verdictFor(hit.status);
    }
  }

  const noKey = matches.filter((m) => !m.requestId).length;
  if (noKey > 0) {
    notes.push(
      `${noKey}건은 조인 키가 없습니다 (POST/PUT은 requestid가 쿼리스트링에 실리지 않습니다). 정상/비정상 어느 쪽으로도 세지 않았습니다.`,
    );
  }

  const summary = summarize(ruleName, matches);
  notes.push(promotionNote(summary));
  return { ...summary, bytesScanned: bytes, notes };
}
