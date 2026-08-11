import "server-only";
import { APP_TRAFFIC_PATHS } from "./config";
import { parseJsonDocuments } from "./rulejson";
import { normalizeRequest } from "./rulerequest";
import { evalStatement, newEvalContext, type EvalContext } from "./rulestatement";
import type {
  RuleTestAction,
  RuleTestResult,
  RuleTestRow,
  TestRequest,
} from "@/lib/types";

// User-supplied regex runs here, so every input is bounded (spec B5).
// The cap covers a whole WebACL export, not just one rule, since that is what
// `aws wafv2 get-web-acl` hands an operator.
export const RULE_JSON_MAX = 65_536;
export const MAX_REQUESTS = 50;
export const MAX_RULES = 40;
export const FIELD_MAX = 500;
export const BODY_MAX = 4_096;

const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

// Seeded from APP_TRAFFIC_PATHS so the set stays in step with the volumetric
// policy: one ordinary browser request per served path, the scenario's load
// generator, and the ALB health check.
export function defaultTestRequests(): TestRequest[] {
  const rows: TestRequest[] = APP_TRAFFIC_PATHS.map((p, i) => ({
    id: `app-${i}`,
    method: "GET",
    path: p,
    query: "",
    userAgent: BROWSER_UA,
    ip: "10.0.2.88",
    country: "KR",
    benign: true,
    headers: { host: "app.example.com", accept: "application/json" },
    body: "",
    labels: [],
  }));
  rows.push({
    id: "loadgen",
    method: "GET",
    path: APP_TRAFFIC_PATHS[0] ?? "/v1/user",
    query: "",
    userAgent: "Go-http-client/2.0",
    ip: "10.0.2.23",
    country: "KR",
    benign: true,
    headers: { host: "app.example.com" },
    body: "",
    labels: [],
  });
  rows.push({
    id: "healthcheck",
    method: "GET",
    path: "/healthcheck",
    query: "",
    userAgent: "ELB-HealthChecker/2.0",
    ip: "10.0.2.1",
    country: "KR",
    benign: true,
    headers: { host: "app.example.com" },
    body: "",
    labels: [],
  });
  return rows;
}

// Deliberately malicious sample requests. Blocking any of these is the point of
// a WAF rule — the sandbox scores them as caught, not as a false positive.
// The set exercises every field the evaluator models (path, query, header,
// cookie, body) so a pasted rule can be checked against the surface it aims at.
export function maliciousExampleRequests(): TestRequest[] {
  const base = { method: "GET", query: "", body: "", benign: false as const, labels: [] };
  return [
    { ...base, id: "mal-wplogin", path: "/wp-login.php", userAgent: "Mozilla/5.0", ip: "203.0.113.7", country: "CN", headers: { host: "app.example.com" } },
    { ...base, id: "mal-sqlmap", path: "/v1/user", query: "id=1%20OR%201=1", userAgent: "sqlmap/1.7", ip: "203.0.113.8", country: "RU", headers: { host: "app.example.com" } },
    { ...base, id: "mal-env", path: "/.env", userAgent: "python-requests/2.31", ip: "203.0.113.9", country: "CN", headers: { host: "app.example.com" } },
    { ...base, id: "mal-jndi", path: "/v1/user", userAgent: "${jndi:ldap://x/a}", ip: "203.0.113.10", country: "US", headers: { host: "app.example.com" } },
    { ...base, id: "mal-b64", path: "/v1/product", query: "cmd=Z2V0fHBvc3RfZGF0YV9leGZpbA==", userAgent: "Mozilla/5.0", ip: "203.0.113.11", country: "CN", headers: { host: "app.example.com" } },
    { ...base, id: "mal-gobuster", path: "/admin", userAgent: "gobuster/3.6", ip: "203.0.113.12", country: "RU", headers: { host: "app.example.com" } },
    { ...base, id: "mal-xss", path: "/v1/product", query: "q=%3Cscript%3Ealert(1)%3C/script%3E", userAgent: BROWSER_UA, ip: "203.0.113.13", country: "US", headers: { host: "app.example.com" } },
    { ...base, id: "mal-traversal", path: "/v1/image/../../etc/passwd", userAgent: "curl/8.4.0", ip: "203.0.113.14", country: "CN", headers: { host: "app.example.com" } },
    { ...base, id: "mal-sqli-body", method: "POST", path: "/v1/user", userAgent: BROWSER_UA, ip: "203.0.113.15", country: "RU", headers: { host: "app.example.com", "content-type": "application/json" }, body: '{"name":"a\' UNION SELECT password FROM users--"}' },
    { ...base, id: "mal-cookie", path: "/v1/user", userAgent: BROWSER_UA, ip: "203.0.113.16", country: "CN", headers: { host: "app.example.com", cookie: "session=abc; tracker=<script>x</script>" } },
  ];
}

// --- input parsing -----------------------------------------------------------

interface ParsedRule {
  name: string;
  action: RuleTestAction;
  priority: number;
  statement: unknown;
  labels: string[];
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function readAction(rule: Record<string, unknown>): RuleTestAction {
  const pick = (v: unknown): RuleTestAction | null => {
    const o = asRecord(v);
    if (!o) return null;
    if ("Block" in o) return "Block";
    if ("Count" in o) return "Count";
    if ("Allow" in o) return "Allow";
    if ("Captcha" in o) return "Captcha";
    if ("Challenge" in o) return "Challenge";
    // OverrideAction: { None: {} } leaves the group's own actions in force,
    // which for a blocking managed group means Block.
    if ("None" in o) return "Block";
    return null;
  };
  return pick(rule["Action"]) ?? pick(rule["OverrideAction"]) ?? "(none)";
}

const STATEMENT_KEY_RE = /Statement$/;

function looksLikeStatement(v: Record<string, unknown>): boolean {
  return Object.keys(v).some((k) => STATEMENT_KEY_RE.test(k));
}

function toRule(value: unknown, index: number): ParsedRule | null {
  const r = asRecord(value);
  if (!r) return null;

  // A bare Statement body, pasted without the surrounding Rule wrapper.
  if (!("Statement" in r) && looksLikeStatement(r)) {
    return { name: "(문장만 붙여넣음)", action: "(none)", priority: index, statement: r, labels: [] };
  }
  if (!("Statement" in r)) return null;

  return {
    name: typeof r["Name"] === "string" ? r["Name"] : `(이름 없음 #${index + 1})`,
    action: readAction(r),
    priority: typeof r["Priority"] === "number" ? r["Priority"] : index,
    statement: r["Statement"],
    labels: Array.isArray(r["RuleLabels"])
      ? r["RuleLabels"]
          .map((l) => asRecord(l)?.["Name"])
          .filter((n): n is string => typeof n === "string")
      : [],
  };
}

function readSetMap(value: unknown): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const rec = asRecord(value);
  if (!rec) return out;
  for (const [key, entries] of Object.entries(rec)) {
    if (!Array.isArray(entries)) continue;
    const list = entries.filter((e): e is string => typeof e === "string");
    if (list.length === 0) continue;
    out.set(key.toLowerCase(), list);
    // Also key by the ARN tail so "…/ipset/office-ips/abcd" resolves by name.
    for (const part of key.toLowerCase().split("/")) {
      if (part.length > 0 && !out.has(part)) out.set(part, list);
    }
  }
  return out;
}

interface ParsedInput {
  rules: ParsedRule[];
  ipSets: Map<string, string[]>;
  regexSets: Map<string, string[]>;
  notes: string[];
}

// Pulls the rule-shaped entries out of one pasted document: an array of Rules,
// a WebACL (from `aws wafv2 get-web-acl`, wrapped or not), or a single Rule /
// bare Statement.
function documentEntries(
  doc: unknown,
  ipSets: Map<string, string[]>,
  regexSets: Map<string, string[]>,
  notes: string[],
): unknown[] {
  const top = asRecord(doc);
  for (const [key, target] of [
    ["IPSets", ipSets],
    ["RegexPatternSets", regexSets],
  ] as const) {
    for (const [name, list] of readSetMap(top?.[key])) target.set(name, list);
  }

  if (Array.isArray(doc)) return doc;

  const acl = asRecord(top?.["WebACL"]) ?? top;
  if (acl && Array.isArray(acl["Rules"])) {
    const aclName = typeof acl["Name"] === "string" ? acl["Name"] : null;
    if (aclName) notes.push(`WebACL "${aclName}"에서 규칙 ${acl["Rules"].length}건을 읽음`);
    return acl["Rules"];
  }
  if (top) return [top];
  throw new Error("규칙 JSON이 객체나 배열이 아님 — WAFv2 Rule/WebACL JSON을 붙여넣어야 함");
}

// Accepts every shape an operator realistically has in hand: one Rule, an array
// of Rules, a WebACL, a bare Statement — and any number of those pasted one
// after another, which is what copying rules out of the console produces.
// Referenced IP / regex sets can ride along at the top level of any document.
function parseInput(ruleJson: string): ParsedInput {
  if (ruleJson.length > RULE_JSON_MAX) {
    throw new Error(`규칙 JSON이 너무 큼 (최대 ${Math.floor(RULE_JSON_MAX / 1024)}KB)`);
  }

  const notes: string[] = [];
  const ipSets = new Map<string, string[]>();
  const regexSets = new Map<string, string[]>();

  const documents = parseJsonDocuments(ruleJson);
  const raw = documents.flatMap((doc) => documentEntries(doc, ipSets, regexSets, notes));

  if (raw.length > MAX_RULES) {
    throw new Error(`규칙이 너무 많음 (최대 ${MAX_RULES}건)`);
  }

  const rules: ParsedRule[] = [];
  raw.forEach((r, i) => {
    const rule = toRule(r, i);
    if (rule) rules.push(rule);
  });
  if (rules.length > 1) {
    notes.push(
      documents.length > 1
        ? `붙여넣은 JSON ${documents.length}덩어리에서 규칙 ${rules.length}건을 읽어 우선순위 순서로 평가함`
        : `규칙 ${rules.length}건을 우선순위 순서로 평가함`,
    );
  }

  if (rules.length === 0) {
    throw new Error(
      "평가할 규칙을 찾지 못함 — WAFv2 Rule 하나, Rule 배열, WebACL JSON, 또는 Statement 본문을 붙여넣어야 함",
    );
  }
  if (rules.length < raw.length) {
    notes.push(`Statement가 없는 항목 ${raw.length - rules.length}건은 건너뜀`);
  }

  rules.sort((a, b) => a.priority - b.priority);
  return { rules, ipSets, regexSets, notes };
}

function validateRequests(requests: TestRequest[]): void {
  if (requests.length === 0) throw new Error("시험할 요청이 없음 — 최소 1건 필요");
  if (requests.length > MAX_REQUESTS) {
    throw new Error(`요청이 너무 많음 (최대 ${MAX_REQUESTS}건)`);
  }
  for (const r of requests) {
    for (const [field, value] of [
      ["method", r.method],
      ["path", r.path],
      ["query", r.query],
      ["userAgent", r.userAgent],
      ["ip", r.ip],
      ["country", r.country],
    ] as const) {
      if (value.length > FIELD_MAX) {
        throw new Error(`요청 ${r.id}의 ${field}가 너무 김 (최대 ${FIELD_MAX}자)`);
      }
    }
    for (const [name, value] of Object.entries(r.headers ?? {})) {
      if (value.length > FIELD_MAX) {
        throw new Error(`요청 ${r.id}의 헤더 ${name}가 너무 김 (최대 ${FIELD_MAX}자)`);
      }
    }
    if ((r.body ?? "").length > BODY_MAX) {
      throw new Error(`요청 ${r.id}의 바디가 너무 김 (최대 ${BODY_MAX}자)`);
    }
  }
}

// --- evaluation --------------------------------------------------------------

// Block / Allow / Captcha / Challenge end the WebACL walk for that request;
// Count only records and evaluation continues to the next rule.
function isTerminating(action: RuleTestAction): boolean {
  return action === "Block" || action === "Allow" || action === "Captcha" || action === "Challenge";
}

function outcomeFor(
  action: RuleTestAction,
  benign: boolean,
): { outcome: RuleTestRow["outcome"]; reason: string } {
  switch (action) {
    case "Block":
      return benign
        ? { outcome: "BLOCKED", reason: "정상 요청이 매칭되고 Block — 오탐 위험" }
        : { outcome: "CAUGHT", reason: "악성 예시가 매칭되고 Block — 정탐(차단)" };
    case "Count":
      return { outcome: "COUNTED", reason: "매칭되지만 Action이 Count — 차단되지 않고 계측만" };
    case "Allow":
      return { outcome: "PASS", reason: "규칙에 매칭되고 Action이 Allow — 통과" };
    case "Captcha":
      return {
        outcome: "CHALLENGED",
        reason: benign
          ? "정상 요청이 CAPTCHA 대상 — 사용자에게 퍼즐이 뜸"
          : "악성 예시가 CAPTCHA 대상 — 자동화 도구는 대개 여기서 멈춤",
      };
    case "Challenge":
      return {
        outcome: "CHALLENGED",
        reason: benign
          ? "정상 요청이 Challenge 대상 — 브라우저 검증 후 통과"
          : "악성 예시가 Challenge 대상 — 스크립트는 대개 통과하지 못함",
      };
    default:
      return { outcome: "MATCHED", reason: "매칭되지만 규칙에 Action이 없음 — 차단 여부 판단 불가" };
  }
}

function evaluateRequest(
  req: TestRequest,
  rules: ParsedRule[],
  ctx: EvalContext,
): RuleTestRow {
  // Labels are per request: a rule only sees what earlier rules added to *this*
  // request.
  ctx.emitted = new Set();
  const normalized = normalizeRequest(req);

  let counted: ParsedRule | null = null;
  let matchedNoAction: ParsedRule | null = null;

  for (const rule of rules) {
    const verdict = evalStatement(rule.statement, normalized, ctx);
    if (verdict === "UNKNOWN") {
      return {
        requestId: req.id,
        matched: null,
        outcome: "UNKNOWN",
        reason: `"${rule.name}"을 로컬에서 평가할 수 없음 — 이후 규칙 판정도 신뢰할 수 없어 중단`,
        ruleName: rule.name,
      };
    }
    if (!verdict) continue;

    for (const l of rule.labels) ctx.emitted.add(l);

    if (isTerminating(rule.action)) {
      const { outcome, reason } = outcomeFor(rule.action, req.benign);
      return { requestId: req.id, matched: true, outcome, reason, ruleName: rule.name };
    }
    if (rule.action === "Count") counted ??= rule;
    else matchedNoAction ??= rule;
  }

  if (counted) {
    const { outcome, reason } = outcomeFor("Count", req.benign);
    return { requestId: req.id, matched: true, outcome, reason, ruleName: counted.name };
  }
  if (matchedNoAction) {
    const { outcome, reason } = outcomeFor("(none)", req.benign);
    return { requestId: req.id, matched: true, outcome, reason, ruleName: matchedNoAction.name };
  }
  return {
    requestId: req.id,
    matched: false,
    outcome: "PASS",
    reason: req.benign
      ? "정상 요청이 어떤 규칙에도 매칭되지 않음 — 통과"
      : "악성 예시가 어떤 규칙에도 걸리지 않음 — 미탐(놓침)",
    ruleName: null,
  };
}

export function testRule(params: { ruleJson: string; requests: TestRequest[] }): RuleTestResult {
  validateRequests(params.requests);
  const { rules, ipSets, regexSets, notes: parseNotes } = parseInput(params.ruleJson);

  const ctx = newEvalContext({ ipSets, regexSets });
  const rows = params.requests.map((req) => evaluateRequest(req, rules, ctx));

  const count = (o: RuleTestRow["outcome"]): number => rows.filter((r) => r.outcome === o).length;
  const blocked = count("BLOCKED");
  const unknown = count("UNKNOWN");
  const caught = count("CAUGHT");
  const challenged = count("CHALLENGED");
  const byId = new Map(params.requests.map((r) => [r.id, r]));
  const missed = rows.filter(
    (r) =>
      byId.get(r.requestId)?.benign === false &&
      r.outcome !== "CAUGHT" &&
      r.outcome !== "CHALLENGED" &&
      r.outcome !== "UNKNOWN",
  ).length;
  const challengedBenign = rows.filter(
    (r) => r.outcome === "CHALLENGED" && byId.get(r.requestId)?.benign !== false,
  ).length;

  const notes = [...parseNotes, ...ctx.notes];
  if (ctx.unsupported.size > 0) {
    notes.push(
      `로컬에서 평가할 수 없는 문법: ${[...ctx.unsupported].join(", ")} — 해당 요청은 판정 불가로 표시됨`,
    );
  }
  if (ctx.approximated.size > 0) {
    notes.push(
      `근사 평가된 문법: ${[...ctx.approximated].join(", ")} — 로컬 판정과 실제 WAF 판정이 다를 수 있으므로 COUNT 검증 필수`,
    );
  }
  if (rules.every((r) => r.action === "Count")) {
    notes.push("전부 COUNT 모드 — 매칭돼도 실제 차단은 발생하지 않음");
  }
  notes.push("합성 요청에 대한 로컬 평가 결과 — 실제 적용 전 COUNT로 검증 필요");
  if (caught > 0) notes.push(`악성 예시 ${caught}건 차단(정탐)`);
  if (challengedBenign > 0) {
    notes.push(`정상 요청 ${challengedBenign}건이 CAPTCHA/Challenge 대상 — 사용자 마찰 발생`);
  }
  if (missed > 0) notes.push(`악성 예시 ${missed}건이 규칙을 통과함(미탐) — 규칙이 공격을 놓침`);

  const primary = rules[0];
  return {
    ruleName: rules.length === 1 ? (primary?.name ?? "(이름 없음)") : `규칙 ${rules.length}건`,
    action: rules.length === 1 ? (primary?.action ?? "(none)") : "(none)",
    ruleCount: rules.length,
    unsupported: [...ctx.unsupported],
    approximated: [...ctx.approximated],
    rows,
    passed: count("PASS"),
    blocked,
    counted: count("COUNTED"),
    challenged,
    matched: count("MATCHED"),
    caught,
    missed,
    unknown,
    // Only a blocked *benign* request is a false positive; caught malicious
    // traffic is the goal, not a risk.
    verdict: blocked > 0 ? "FALSE_POSITIVE_RISK" : unknown > 0 ? "INCONCLUSIVE" : "SAFE",
    notes,
  };
}
