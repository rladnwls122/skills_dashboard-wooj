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
  }));
  rows.push({
    id: "loadgen",
    method: "GET",
    path: APP_TRAFFIC_PATHS[0] ?? "/v1/user",
    query: "",
    userAgent: "Go-http-client/2.0",
    ip: "10.0.2.23",
    country: "KR",
  });
  rows.push({
    id: "healthcheck",
    method: "GET",
    path: "/healthcheck",
    query: "",
    userAgent: "ELB-HealthChecker/2.0",
    ip: "10.0.2.1",
    country: "KR",
  });
  return rows;
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
): { outcome: RuleTestRow["outcome"]; reason: string } {
  if (matched === null) {
    return { outcome: "UNKNOWN", reason: "규칙을 로컬에서 평가할 수 없음 — 미지원 문법 포함" };
  }
  if (!matched) return { outcome: "PASS", reason: "규칙에 매칭되지 않음 — 통과" };
  switch (action) {
    case "Block":
      return { outcome: "BLOCKED", reason: "규칙에 매칭되고 Action이 Block — 차단됨" };
    case "Count":
      return { outcome: "COUNTED", reason: "규칙에 매칭되지만 Action이 Count — 차단되지 않고 계측만" };
    case "Allow":
      return { outcome: "PASS", reason: "규칙에 매칭되고 Action이 Allow — 통과" };
    default:
      return {
        outcome: "UNKNOWN",
        reason: "규칙에 매칭되지만 Action이 없어 차단 여부를 알 수 없음",
      };
  }
}

export function testRule(params: { ruleJson: string; requests: TestRequest[] }): RuleTestResult {
  validateRequests(params.requests);
  const { name, action, statement } = parseRule(params.ruleJson);

  const ctx: EvalContext = { unsupported: new Set(), notes: new Set() };
  const rows: RuleTestRow[] = params.requests.map((req) => {
    const v = evalStatement(statement, req, ctx);
    const matched = v === "UNKNOWN" ? null : v;
    const { outcome, reason } = outcomeFor(matched, action);
    return { requestId: req.id, matched, outcome, reason };
  });

  const count = (o: RuleTestRow["outcome"]): number => rows.filter((r) => r.outcome === o).length;
  const blocked = count("BLOCKED");
  const unknown = count("UNKNOWN");

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

  return {
    ruleName: name,
    action,
    unsupported: [...ctx.unsupported],
    rows,
    passed: count("PASS"),
    blocked,
    counted: count("COUNTED"),
    unknown,
    // A blocked normal request is actionable, so it outranks an unknown.
    verdict: blocked > 0 ? "FALSE_POSITIVE_RISK" : unknown > 0 ? "INCONCLUSIVE" : "SAFE",
    notes,
  };
}
