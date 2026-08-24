// The rule sandbox evaluator. User-supplied regex runs here, so every input is
// bounded (spec B5).

import type { RuleTestRow, TestRequest } from "../../src/lib/types.ts";
import type { RuleTestResultFull } from "../types/types.ts";
import { parseJsonDocuments } from "./jsondoc.ts";
import { normalizeRequest } from "./request.ts";
import { EvalContext, evalStatement } from "./statement.ts";
import { VERDICT_TRUE, VERDICT_UNKNOWN } from "./verdict.ts";

/** Covers a whole WebACL export, not just one rule. */
export const RULE_JSON_MAX = 65_536;
export const MAX_REQUESTS = 50;
export const MAX_RULES = 40;
export const FIELD_MAX = 500;
export const BODY_MAX = 4_096;

type Rec = Record<string, unknown>;

interface ParsedRule {
  name: string;
  action: string;
  priority: number;
  statement: unknown;
  labels: string[];
}

function asRecord(v: unknown): Rec | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function readAction(rule: Rec): string {
  const pick = (v: unknown): string => {
    const o = asRecord(v);
    if (!o) return "";
    for (const a of ["Block", "Count", "Allow", "Captcha", "Challenge"]) {
      if (a in o) return a;
    }
    // OverrideAction: { None: {} } leaves the group's own actions in force,
    // which for a blocking managed group means Block.
    if ("None" in o) return "Block";
    return "";
  };
  return pick(rule.Action) || pick(rule.OverrideAction) || "(none)";
}

function looksLikeStatement(v: Rec): boolean {
  return Object.keys(v).some((k) => k.endsWith("Statement"));
}

function toRule(value: unknown, index: number): ParsedRule | null {
  const r = asRecord(value);
  if (!r) return null;

  // A bare Statement body, pasted without the surrounding Rule wrapper.
  if (!("Statement" in r)) {
    if (looksLikeStatement(r)) {
      return {
        name: "(문장만 붙여넣음)",
        action: "(none)",
        priority: index,
        statement: r,
        labels: [],
      };
    }
    return null;
  }

  const labels: string[] = [];
  if (Array.isArray(r.RuleLabels)) {
    for (const l of r.RuleLabels) {
      const n = str(asRecord(l)?.Name);
      if (n !== null) labels.push(n);
    }
  }

  return {
    name: str(r.Name) ?? `(이름 없음 #${index + 1})`,
    action: readAction(r),
    priority: typeof r.Priority === "number" ? r.Priority : index,
    statement: r.Statement,
    labels,
  };
}

function readSetMap(value: unknown, target: Map<string, string[]>): void {
  const rec = asRecord(value);
  if (!rec) return;
  for (const [key, entries] of Object.entries(rec)) {
    const list = strList(entries);
    if (list.length === 0) continue;
    const lower = key.toLowerCase();
    target.set(lower, list);
    // Also key by the ARN tail so "…/ipset/office-ips/abcd" resolves by name.
    for (const part of lower.split("/")) {
      if (part !== "" && !target.has(part)) target.set(part, list);
    }
  }
}

/**
 * Pulls the rule-shaped entries out of one pasted document: an array of Rules, a
 * WebACL (wrapped or not), or a single Rule / bare Statement.
 */
function documentEntries(
  doc: unknown,
  ipSets: Map<string, string[]>,
  regexSets: Map<string, string[]>,
  notes: string[],
): unknown[] {
  const top = asRecord(doc);
  if (top) {
    readSetMap(top.IPSets, ipSets);
    readSetMap(top.RegexPatternSets, regexSets);
  }

  if (Array.isArray(doc)) return doc;

  const acl = asRecord(top?.WebACL) ?? top;
  if (acl && Array.isArray(acl.Rules)) {
    const aclName = str(acl.Name);
    if (aclName !== null) {
      notes.push(`WebACL "${aclName}"에서 규칙 ${acl.Rules.length}건을 읽음`);
    }
    return acl.Rules;
  }
  if (top) return [top];
  throw new Error("규칙 JSON이 객체나 배열이 아님 — WAFv2 Rule/WebACL JSON을 붙여넣어야 함");
}

interface ParsedInput {
  rules: ParsedRule[];
  ipSets: Map<string, string[]>;
  regexSets: Map<string, string[]>;
  notes: string[];
}

function parseInput(ruleJson: string): ParsedInput {
  if (ruleJson.length > RULE_JSON_MAX) {
    throw new Error(`규칙 JSON이 너무 큼 (최대 ${RULE_JSON_MAX / 1024}KB)`);
  }

  const notes: string[] = [];
  const ipSets = new Map<string, string[]>();
  const regexSets = new Map<string, string[]>();

  const documents = parseJsonDocuments(ruleJson);
  const raw: unknown[] = [];
  for (const doc of documents) {
    raw.push(...documentEntries(doc, ipSets, regexSets, notes));
  }

  if (raw.length > MAX_RULES) throw new Error(`규칙이 너무 많음 (최대 ${MAX_RULES}건)`);

  const parsed = raw.map(toRule).filter((r): r is ParsedRule => r !== null);
  if (parsed.length > 1) {
    notes.push(
      documents.length > 1
        ? `붙여넣은 JSON ${documents.length}덩어리에서 규칙 ${parsed.length}건을 읽어 우선순위 순서로 평가함`
        : `규칙 ${parsed.length}건을 우선순위 순서로 평가함`,
    );
  }

  if (parsed.length === 0) {
    throw new Error(
      "평가할 규칙을 찾지 못함 — WAFv2 Rule 하나, Rule 배열, WebACL JSON, 또는 Statement 본문을 붙여넣어야 함",
    );
  }
  if (parsed.length < raw.length) {
    notes.push(`Statement가 없는 항목 ${raw.length - parsed.length}건은 건너뜀`);
  }

  // Array#sort is stable, so equal priorities keep their pasted order.
  parsed.sort((a, b) => a.priority - b.priority);
  return { rules: parsed, ipSets, regexSets, notes };
}

function validateRequests(requests: TestRequest[]): void {
  if (requests.length === 0) throw new Error("시험할 요청이 없음 — 최소 1건 필요");
  if (requests.length > MAX_REQUESTS) throw new Error(`요청이 너무 많음 (최대 ${MAX_REQUESTS}건)`);

  for (const r of requests) {
    const fields: [string, string][] = [
      ["method", r.method ?? ""],
      ["path", r.path ?? ""],
      ["query", r.query ?? ""],
      ["userAgent", r.userAgent ?? ""],
      ["ip", r.ip ?? ""],
      ["country", r.country ?? ""],
    ];
    for (const [name, value] of fields) {
      if (value.length > FIELD_MAX) {
        throw new Error(`요청 ${r.id}의 ${name}가 너무 김 (최대 ${FIELD_MAX}자)`);
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

/**
 * Block / Allow / Captcha / Challenge end the WebACL walk for that request;
 * Count only records and evaluation continues to the next rule.
 */
function isTerminating(action: string): boolean {
  return action === "Block" || action === "Allow" || action === "Captcha" || action === "Challenge";
}

function outcomeFor(action: string, benign: boolean): { outcome: string; reason: string } {
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
  ruleList: ParsedRule[],
  ctx: EvalContext,
): RuleTestRow {
  // Labels are per request: a rule only sees what earlier rules added to *this*
  // request.
  ctx.emitted.clear();
  const normalized = normalizeRequest(req);

  let counted: ParsedRule | null = null;
  let matchedNoAction: ParsedRule | null = null;

  for (const rule of ruleList) {
    const verdict = evalStatement(rule.statement, normalized, ctx);
    if (verdict === VERDICT_UNKNOWN) {
      return {
        requestId: req.id,
        matched: null,
        outcome: "UNKNOWN",
        reason: `"${rule.name}"을 로컬에서 평가할 수 없음 — 이후 규칙 판정도 신뢰할 수 없어 중단`,
        ruleName: rule.name,
      };
    }
    if (verdict !== VERDICT_TRUE) continue;

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

function sortedKeys(s: Set<string>): string[] {
  return [...s].sort();
}

export function testRule(ruleJson: string, requests: TestRequest[]): RuleTestResultFull {
  validateRequests(requests);
  const input = parseInput(ruleJson);

  const ctx = new EvalContext();
  for (const [k, v] of input.ipSets) ctx.ipSets.set(k, v);
  for (const [k, v] of input.regexSets) ctx.regexSets.set(k, v);

  const rows = requests.map((req) => evaluateRequest(req, input.rules, ctx));

  const count = (o: string): number => rows.filter((r) => r.outcome === o).length;
  const blocked = count("BLOCKED");
  const unknown = count("UNKNOWN");
  const caught = count("CAUGHT");
  const challenged = count("CHALLENGED");

  const byId = new Map(requests.map((r) => [r.id, r]));
  let missed = 0;
  let challengedBenign = 0;
  for (const r of rows) {
    const req = byId.get(r.requestId);
    if (
      req &&
      !req.benign &&
      r.outcome !== "CAUGHT" &&
      r.outcome !== "CHALLENGED" &&
      r.outcome !== "UNKNOWN"
    ) {
      missed++;
    }
    if (r.outcome === "CHALLENGED" && (!req || req.benign)) challengedBenign++;
  }

  const notes = [...input.notes, ...sortedKeys(ctx.notes)];
  if (ctx.unsupported.size > 0) {
    notes.push(
      `로컬에서 평가할 수 없는 문법: ${sortedKeys(ctx.unsupported).join(", ")} — 해당 요청은 판정 불가로 표시됨`,
    );
  }
  if (ctx.approximated.size > 0) {
    notes.push(
      `근사 평가된 문법: ${sortedKeys(ctx.approximated).join(", ")} — 로컬 판정과 실제 WAF 판정이 다를 수 있으므로 COUNT 검증 필수`,
    );
  }
  if (input.rules.every((r) => r.action === "Count")) {
    notes.push("전부 COUNT 모드 — 매칭돼도 실제 차단은 발생하지 않음");
  }
  notes.push("합성 요청에 대한 로컬 평가 결과 — 실제 적용 전 COUNT로 검증 필요");
  if (caught > 0) notes.push(`악성 예시 ${caught}건 차단(정탐)`);
  if (challengedBenign > 0) {
    notes.push(`정상 요청 ${challengedBenign}건이 CAPTCHA/Challenge 대상 — 사용자 마찰 발생`);
  }
  if (missed > 0) notes.push(`악성 예시 ${missed}건이 규칙을 통과함(미탐) — 규칙이 공격을 놓침`);

  const single = input.rules.length === 1 ? input.rules[0]! : null;

  // Only a blocked *benign* request is a false positive; caught malicious
  // traffic is the goal, not a risk.
  let verdict = "SAFE";
  if (blocked > 0) verdict = "FALSE_POSITIVE_RISK";
  else if (unknown > 0) verdict = "INCONCLUSIVE";

  return {
    ruleName: single ? single.name : `규칙 ${input.rules.length}건`,
    action: single ? single.action : "(none)",
    ruleCount: input.rules.length,
    unsupported: sortedKeys(ctx.unsupported),
    approximated: sortedKeys(ctx.approximated),
    rows,
    passed: count("PASS"),
    blocked,
    counted: count("COUNTED"),
    challenged,
    matched: count("MATCHED"),
    caught,
    missed,
    unknown,
    verdict,
    notes,
  };
}
