# WAF 규칙 시험 샌드박스 (파트 B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 운영자가 직접 쓴(또는 Amazon Q가 돌려준) WAFv2 Rule JSON을 편집 가능한 정상 요청 집합에 대해 로컬 평가해, 적용 전에 정상 요청이 차단되는지 확인한다.

**Architecture:** 평가기는 AWS 의존이 전혀 없는 순수 모듈 두 개로 나뉜다 — `rulestatement.ts`(Statement 평가)와 `rulesim.ts`(Rule 파싱·상한·기본 요청·판정). 핵심은 **3값 논리** `true | false | "UNKNOWN"`이다. 로컬에서 평가할 수 없는 문법을 절대 "통과"로 접지 않는다. 틀린 답을 주는 시험 도구는 없는 것보다 나쁘다. UI는 새 최상위 탭이며 서버 액션 한 번에 전체 요청 집합을 평가한다 (캐시 없음 — 순수·즉시).

**Tech Stack:** Next.js 15 App Router (Server Actions), React 19, TypeScript strict (`noUncheckedIndexedAccess`), Tailwind v4. 평가기는 표준 JS만 사용하고 AWS SDK를 임포트하지 않는다. 테스트는 파트 A가 만든 Node 타입 스트리핑 하네스 — **새 의존성 없음**.

## Global Constraints

- 브랜치: `feat/waf-log-query-and-rule-sandbox`. `main`에 직접 커밋 금지
- 스펙: `docs/superpowers/specs/2026-08-10-waf-log-query-and-rule-sandbox-design.md` — **파트 B만** 이번 범위
- **선행 조건: 파트 A의 Task 1(테스트 하네스)이 완료돼 있어야 한다.** `scripts/testing/register.mjs`가 없으면 파트 A Task 1을 먼저 수행한다
- 새 npm 의존성 추가 금지 (dev 포함)
- 평가기 모듈(`rulestatement.ts`, `rulesim.ts`)은 AWS SDK를 임포트하지 않는다. 순수해야 AWS 없이 단위 테스트된다
- 모든 서버 액션은 기존 `ok()` / `fail()` 패턴을 따르고 절대 throw하지 않는다
- **평가할 수 없는 것은 `UNKNOWN`이다. 절대 `PASS`가 아니다.** 이 규칙을 어기는 구현은 기능이 아니라 결함이다
- 입력 상한 (스펙 B5): `ruleJson` 20KB · `RegexString` 200자 · 요청 행 50개 · 요청 필드별 500자
- 사용자 노출 문구는 한국어, 코드 주석은 영어 (기존 코드 관례)
- 각 태스크 종료 시 `npx tsc --noEmit`이 통과해야 한다

## 스펙과의 의도적 차이 1건 — `SearchString` 인코딩

스펙 B2는 `SearchString`의 **평문과 base64 양쪽 수용**을 요구한다. 이 계획은 **평문만** 해석하고, 값이 base64로도 해석 가능할 때 경고 노트를 붙인다.

이유: 자동 판별이 불가능하다. `"/v1/user"`는 8자이고 모든 문자가 base64 알파벳에 속해 길이도 4의 배수이므로, **유효한 base64로도 평문으로도 읽힌다.** 어느 쪽인지 추측하면 이 도구가 존재하는 이유인 "조용히 틀린 답을 내지 않는다"를 정면으로 위반한다. 두 해석을 모두 평가해 결과가 다르면 UNKNOWN으로 만드는 방안도 검토했으나, 그러면 가장 흔한 평문 케이스가 거의 항상 UNKNOWN이 되어 도구가 쓸모없어진다.

대시보드가 생성하는 `ruleJson`은 평문이며(`types.ts`의 `WafRecommendation.ruleJson` 주석: "SearchString decoded to plain text — same format the WAF console JSON editor accepts"), Amazon Q도 그 포맷을 받아 같은 포맷으로 답한다. 따라서 평문이 이 워크플로의 실제 포맷이다. base64가 필요해지면 UI에 명시적 토글을 추가하는 것이 옳은 해결이다 — 추측이 아니라.

---

## File Structure

| 파일 | 책임 |
|---|---|
| `src/lib/server/rulestatement.ts` (신규, 순수) | Statement 평가 — 필드 추출, 텍스트 변환, 매처, 3값 논리 |
| `src/lib/server/rulesim.ts` (신규, 순수) | Rule JSON 파싱, 입력 상한, 기본 요청 집합, 요청별 실행, 최종 판정 |
| `src/lib/types.ts` (수정) | `TestRequest`, `RuleTestOutcome`, `RuleTestRow`, `RuleTestResult` |
| `src/app/actions/dashboard.ts` (수정) | `testRuleJsonAction`, `getDefaultTestRequestsAction` |
| `src/app/dashboard/ui/SandboxTab.tsx` (신규) | 규칙 JSON 입력 · 요청 표 편집 · 결과 표 |
| `src/app/dashboard/ui/DashboardClient.tsx` (수정) | `TABS`에 항목 추가 + 렌더 분기 |
| `scripts/rulestatement.test.mjs` (신규) | 매처·변환·3값 논리 단위 테스트 |
| `scripts/rulesim.test.mjs` (신규) | 파싱·상한·판정·통합 단위 테스트 |
| `package.json` (수정) | 테스트 스크립트 |

평가기를 두 모듈로 나누는 이유는 각각 한 가지 책임만 갖게 하고 따로 테스트하기 위함이다. `rulestatement.ts`는 "이 Statement가 이 요청에 매칭되는가"만 답하고, `rulesim.ts`는 규칙 문서 전체와 판정을 다룬다.

---

## Task 1: 타입 + Statement 평가기

**Files:**
- Modify: `src/lib/types.ts`
- Create: `src/lib/server/rulestatement.ts`
- Create: `scripts/rulestatement.test.mjs`
- Modify: `package.json`

**Interfaces:**
- Consumes: 파트 A Task 1의 테스트 진입점 `scripts/testing/register.mjs`
- Produces:
  - `type TestRequest` (types.ts)
  - `type Verdict3 = boolean | "UNKNOWN"`
  - `interface EvalContext { unsupported: Set<string>; notes: Set<string> }`
  - `evalStatement(stmt: unknown, req: TestRequest, ctx: EvalContext): Verdict3`
  - `REGEX_MAX = 200`

- [ ] **Step 1: 타입 추가**

`src/lib/types.ts` 끝에 추가한다:

```ts
export interface TestRequest {
  // stable key for the UI row
  id: string;
  method: string;
  path: string;
  // query string without the leading "?"
  query: string;
  userAgent: string;
  ip: string;
}

export type RuleTestOutcome = "PASS" | "BLOCKED" | "COUNTED" | "UNKNOWN";

export interface RuleTestRow {
  requestId: string;
  // null when the statement could not be evaluated locally
  matched: boolean | null;
  outcome: RuleTestOutcome;
  reason: string;
}

export interface RuleTestResult {
  ruleName: string;
  action: "Block" | "Count" | "Allow" | "(none)";
  // statement types encountered that cannot be evaluated locally
  unsupported: string[];
  rows: RuleTestRow[];
  passed: number;
  blocked: number;
  counted: number;
  unknown: number;
  verdict: "SAFE" | "FALSE_POSITIVE_RISK" | "INCONCLUSIVE";
  notes: string[];
}
```

- [ ] **Step 2: 실패하는 테스트 작성**

`scripts/rulestatement.test.mjs`:

```js
// The evaluator's contract: everything it cannot decide locally is UNKNOWN,
// never a pass. These cases pin that down alongside the matchers.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { evalStatement, REGEX_MAX } = await import(`${SRC}rulestatement.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const REQ = {
  id: "r1",
  method: "GET",
  path: "/v1/user",
  query: "id=3&name=kim",
  userAgent: "Mozilla/5.0 (Windows NT 10.0)",
  ip: "10.0.2.88",
};
const ctx = () => ({ unsupported: new Set(), notes: new Set() });
const ev = (stmt, req = REQ) => evalStatement(stmt, req, ctx());

const byteMatch = (search, field, constraint, transforms = [{ Priority: 0, Type: "NONE" }]) => ({
  ByteMatchStatement: {
    SearchString: search,
    FieldToMatch: field,
    TextTransformations: transforms,
    PositionalConstraint: constraint,
  },
});
const URI = { UriPath: {} };

// --- PositionalConstraint, all five ---
check("EXACTLY hit", ev(byteMatch("/v1/user", URI, "EXACTLY")), true);
check("EXACTLY miss", ev(byteMatch("/v1/use", URI, "EXACTLY")), false);
check("STARTS_WITH hit", ev(byteMatch("/v1/", URI, "STARTS_WITH")), true);
check("STARTS_WITH miss", ev(byteMatch("v1/", URI, "STARTS_WITH")), false);
check("ENDS_WITH hit", ev(byteMatch("user", URI, "ENDS_WITH")), true);
check("ENDS_WITH miss", ev(byteMatch("users", URI, "ENDS_WITH")), false);
check("CONTAINS hit", ev(byteMatch("1/us", URI, "CONTAINS")), true);
check("CONTAINS miss", ev(byteMatch("admin", URI, "CONTAINS")), false);
check("CONTAINS_WORD hit", ev(byteMatch("user", URI, "CONTAINS_WORD")), true);
check("CONTAINS_WORD rejects a substring inside a word", ev(byteMatch("use", URI, "CONTAINS_WORD")), false);

// --- FieldToMatch ---
check("Method field", ev(byteMatch("GET", { Method: {} }, "EXACTLY")), true);
check("QueryString field", ev(byteMatch("name=kim", { QueryString: {} }, "CONTAINS")), true);
check("AllQueryArguments field", ev(byteMatch("id=3", { AllQueryArguments: {} }, "CONTAINS")), true);
check(
  "SingleHeader user-agent",
  ev(byteMatch("Mozilla", { SingleHeader: { Name: "user-agent" } }, "CONTAINS")),
  true,
);
check(
  "SingleHeader we do not model is UNKNOWN, not a pass",
  ev(byteMatch("x", { SingleHeader: { Name: "x-forwarded-for" } }, "CONTAINS")),
  "UNKNOWN",
);
check("Body field is UNKNOWN", ev(byteMatch("x", { Body: {} }, "CONTAINS")), "UNKNOWN");

// --- TextTransformations ---
check(
  "LOWERCASE applies",
  ev(byteMatch("mozilla", { SingleHeader: { Name: "user-agent" } }, "CONTAINS", [
    { Priority: 0, Type: "LOWERCASE" },
  ])),
  true,
);
check(
  "transforms run in Priority order",
  ev(
    byteMatch("a b", { QueryString: {} }, "CONTAINS", [
      { Priority: 1, Type: "COMPRESS_WHITE_SPACE" },
      { Priority: 0, Type: "URL_DECODE" },
    ]),
    { ...REQ, query: "a%20%20%20b" },
  ),
  true,
);
check(
  "TRIM applies",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "TRIM" }]), {
    ...REQ,
    path: "  /v1/user  ",
  }),
  true,
);
check(
  "HTML_ENTITY_DECODE applies",
  ev(
    byteMatch("<script>", { QueryString: {} }, "CONTAINS", [
      { Priority: 0, Type: "HTML_ENTITY_DECODE" },
    ]),
    { ...REQ, query: "q=&lt;script&gt;" },
  ),
  true,
);
check(
  "an unknown transform is UNKNOWN, not a pass",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "BASE64_DECODE" }])),
  "UNKNOWN",
);

// --- RegexMatchStatement ---
const regex = (s) => ({
  RegexMatchStatement: {
    RegexString: s,
    FieldToMatch: URI,
    TextTransformations: [{ Priority: 0, Type: "NONE" }],
  },
});
check("regex hit", ev(regex("^/v1/(user|product)$")), true);
check("regex miss", ev(regex("^/admin")), false);
check("invalid regex is UNKNOWN", ev(regex("([unclosed")), "UNKNOWN");
check("over-long regex is UNKNOWN", ev(regex("a".repeat(REGEX_MAX + 1))), "UNKNOWN");

// --- SizeConstraintStatement ---
const size = (op, size) => ({
  SizeConstraintStatement: {
    FieldToMatch: URI,
    ComparisonOperator: op,
    Size: size,
    TextTransformations: [{ Priority: 0, Type: "NONE" }],
  },
});
// "/v1/user" is 8 bytes
check("size EQ", ev(size("EQ", 8)), true);
check("size NE", ev(size("NE", 8)), false);
check("size GT", ev(size("GT", 7)), true);
check("size GE", ev(size("GE", 8)), true);
check("size LT", ev(size("LT", 8)), false);
check("size LE", ev(size("LE", 8)), true);

// --- Three-valued And / Or / Not ---
const T = byteMatch("/v1/", URI, "STARTS_WITH");
const F = byteMatch("/admin", URI, "STARTS_WITH");
const U = { ManagedRuleGroupStatement: { VendorName: "AWS", Name: "AWSManagedRulesCommonRuleSet" } };

check("And all true", ev({ AndStatement: { Statements: [T, T] } }), true);
check("And with a false is false", ev({ AndStatement: { Statements: [T, F] } }), false);
check("And false beats UNKNOWN", ev({ AndStatement: { Statements: [F, U] } }), false);
check("And true plus UNKNOWN is UNKNOWN", ev({ AndStatement: { Statements: [T, U] } }), "UNKNOWN");
check("Or with a true is true", ev({ OrStatement: { Statements: [F, T] } }), true);
check("Or true beats UNKNOWN", ev({ OrStatement: { Statements: [U, T] } }), true);
check("Or false plus UNKNOWN is UNKNOWN", ev({ OrStatement: { Statements: [F, U] } }), "UNKNOWN");
check("Or all false", ev({ OrStatement: { Statements: [F, F] } }), false);
check("Not inverts true", ev({ NotStatement: { Statement: T } }), false);
check("Not inverts false", ev({ NotStatement: { Statement: F } }), true);
check("Not keeps UNKNOWN", ev({ NotStatement: { Statement: U } }), "UNKNOWN");
check(
  "nested And/Or/Not",
  ev({
    AndStatement: {
      Statements: [T, { NotStatement: { Statement: { OrStatement: { Statements: [F, F] } } } }],
    },
  }),
  true,
);

// --- Unsupported statements are all UNKNOWN and are reported by name ---
const unsupported = [
  ["IPSetReferenceStatement", { IPSetReferenceStatement: { ARN: "arn:aws:wafv2:...:ipset/x" } }],
  ["RegexPatternSetReferenceStatement", { RegexPatternSetReferenceStatement: { ARN: "arn:...", FieldToMatch: URI, TextTransformations: [] } }],
  ["ManagedRuleGroupStatement", U],
  ["LabelMatchStatement", { LabelMatchStatement: { Scope: "NAMESPACE", Key: "awswaf:managed:aws:" } }],
  ["RateBasedStatement", { RateBasedStatement: { Limit: 2000, AggregateKeyType: "IP" } }],
  ["SqliMatchStatement", { SqliMatchStatement: { FieldToMatch: URI, TextTransformations: [] } }],
  ["XssMatchStatement", { XssMatchStatement: { FieldToMatch: URI, TextTransformations: [] } }],
];
for (const [name, stmt] of unsupported) {
  const c = ctx();
  check(`${name} evaluates to UNKNOWN`, evalStatement(stmt, REQ, c), "UNKNOWN");
  check(`${name} is reported by name`, [...c.unsupported], [name]);
}

// --- Malformed input ---
check("empty statement is UNKNOWN", ev({}), "UNKNOWN");
check("null statement is UNKNOWN", ev(null), "UNKNOWN");
check("unknown statement key is UNKNOWN", ev({ FutureStatement: {} }), "UNKNOWN");

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
```

`package.json`의 `scripts`에 추가한다 (파트 A가 만든 항목은 유지):

```json
    "test": "pnpm test:ddos && pnpm test:applog && pnpm test:rulestatement && pnpm test:rulesim",
    "test:rulestatement": "node --import ./scripts/testing/register.mjs scripts/rulestatement.test.mjs",
    "test:rulesim": "node --import ./scripts/testing/register.mjs scripts/rulesim.test.mjs",
```

- [ ] **Step 3: 실패 확인**

Run: `pnpm test:rulestatement`
Expected: FAIL — `rulestatement.ts` 모듈 없음 (`ERR_MODULE_NOT_FOUND`)

- [ ] **Step 4: Statement 평가기 구현**

`src/lib/server/rulestatement.ts`:

```ts
import "server-only";
import type { TestRequest } from "@/lib/types";

// Three-valued: UNKNOWN means "this cannot be decided locally". It is never
// collapsed into false or true — a rule tester that guesses is worse than none.
export type Verdict3 = boolean | "UNKNOWN";

export interface EvalContext {
  // statement type names encountered that cannot be evaluated locally
  unsupported: Set<string>;
  // operator-facing explanations
  notes: Set<string>;
}

export const REGEX_MAX = 200;

// Statement types that exist in WAFv2 but cannot be decided from a synthetic
// request: ARN references need an API read, managed groups and Sqli/Xss use
// AWS-internal tokenizing, labels need a prior rule to have run, and rate
// limits are a property of traffic volume rather than of one request.
const UNSUPPORTED_STATEMENTS = [
  "IPSetReferenceStatement",
  "RegexPatternSetReferenceStatement",
  "ManagedRuleGroupStatement",
  "RuleGroupReferenceStatement",
  "LabelMatchStatement",
  "RateBasedStatement",
  "SqliMatchStatement",
  "XssMatchStatement",
] as const;

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

// Returns null when the field is one we do not model — the caller turns that
// into UNKNOWN rather than a miss.
function fieldValue(req: TestRequest, field: unknown): string | null {
  const f = asRecord(field);
  if (!f) return null;
  if ("UriPath" in f) return req.path;
  if ("QueryString" in f || "AllQueryArguments" in f) return req.query;
  if ("Method" in f) return req.method;
  if ("SingleHeader" in f) {
    const name = str(asRecord(f["SingleHeader"])?.["Name"])?.toLowerCase();
    // The synthetic request models only the User-Agent header.
    if (name === "user-agent") return req.userAgent;
    return null;
  }
  return null;
}

const HTML_ENTITIES: Record<string, string> = {
  "&lt;": "<",
  "&gt;": ">",
  "&amp;": "&",
  "&quot;": '"',
  "&apos;": "'",
  "&nbsp;": " ",
};

function htmlEntityDecode(s: string): string {
  return s
    .replace(/&(?:lt|gt|amp|quot|apos|nbsp);/gi, (m) => HTML_ENTITIES[m.toLowerCase()] ?? m)
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h: string) => String.fromCodePoint(Number.parseInt(h, 16)));
}

function urlDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    // A malformed percent-escape decodes to itself in WAF; keep the raw value.
    return s;
  }
}

// Returns null when a transform type is one we do not implement.
function applyTransforms(value: string, transforms: unknown): string | null {
  const list = Array.isArray(transforms) ? transforms : [];
  const ordered = list
    .map((t) => asRecord(t))
    .filter((t): t is Record<string, unknown> => t !== null)
    .sort((a, b) => Number(a["Priority"] ?? 0) - Number(b["Priority"] ?? 0));
  let out = value;
  for (const t of ordered) {
    switch (str(t["Type"])) {
      case "NONE":
        break;
      case "LOWERCASE":
        out = out.toLowerCase();
        break;
      case "URL_DECODE":
        out = urlDecode(out);
        break;
      case "TRIM":
        out = out.trim();
        break;
      case "COMPRESS_WHITE_SPACE":
        out = out.replace(/[\s]+/g, " ");
        break;
      case "HTML_ENTITY_DECODE":
        out = htmlEntityDecode(out);
        break;
      default:
        return null;
    }
  }
  return out;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function positional(haystack: string, needle: string, constraint: string | null): Verdict3 {
  switch (constraint) {
    case "EXACTLY":
      return haystack === needle;
    case "STARTS_WITH":
      return haystack.startsWith(needle);
    case "ENDS_WITH":
      return haystack.endsWith(needle);
    case "CONTAINS":
      return haystack.includes(needle);
    case "CONTAINS_WORD":
      // WAF: the search string must appear delimited by characters outside
      // [A-Za-z0-9_].
      if (needle.length === 0) return false;
      return new RegExp(`(^|[^A-Za-z0-9_])${escapeRe(needle)}($|[^A-Za-z0-9_])`).test(haystack);
    default:
      return "UNKNOWN";
  }
}

function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

function compare(actual: number, op: string | null, size: number): Verdict3 {
  switch (op) {
    case "EQ":
      return actual === size;
    case "NE":
      return actual !== size;
    case "LE":
      return actual <= size;
    case "LT":
      return actual < size;
    case "GE":
      return actual >= size;
    case "GT":
      return actual > size;
    default:
      return "UNKNOWN";
  }
}

// Prepares the field value for a matcher. Returns null when either the field or
// a transform is unsupported, which the caller reports as UNKNOWN.
function preparedField(req: TestRequest, body: Record<string, unknown>): string | null {
  const raw = fieldValue(req, body["FieldToMatch"]);
  if (raw === null) return null;
  return applyTransforms(raw, body["TextTransformations"]);
}

export function evalStatement(stmt: unknown, req: TestRequest, ctx: EvalContext): Verdict3 {
  const s = asRecord(stmt);
  if (!s) return "UNKNOWN";

  const and = asRecord(s["AndStatement"]);
  if (and) {
    const parts = Array.isArray(and["Statements"]) ? and["Statements"] : [];
    const results = parts.map((p) => evalStatement(p, req, ctx));
    if (results.some((r) => r === false)) return false;
    if (results.some((r) => r === "UNKNOWN")) return "UNKNOWN";
    return results.length > 0;
  }

  const or = asRecord(s["OrStatement"]);
  if (or) {
    const parts = Array.isArray(or["Statements"]) ? or["Statements"] : [];
    const results = parts.map((p) => evalStatement(p, req, ctx));
    if (results.some((r) => r === true)) return true;
    if (results.some((r) => r === "UNKNOWN")) return "UNKNOWN";
    return false;
  }

  const not = asRecord(s["NotStatement"]);
  if (not) {
    const inner = evalStatement(not["Statement"], req, ctx);
    return inner === "UNKNOWN" ? "UNKNOWN" : !inner;
  }

  const byte = asRecord(s["ByteMatchStatement"]);
  if (byte) {
    const search = str(byte["SearchString"]);
    if (search === null) {
      ctx.notes.add("ByteMatchStatement의 SearchString이 문자열이 아님 — 평가 불가");
      return "UNKNOWN";
    }
    // Plain text only; see the plan's SearchString note. Warn when the value
    // would also decode as base64 so an operator is never silently misled.
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(search) && search.length % 4 === 0 && search.length >= 4) {
      ctx.notes.add(
        `SearchString "${search}"은 base64로도 해석될 수 있음 — 평문으로 간주해 평가함`,
      );
    }
    const value = preparedField(req, byte);
    if (value === null) {
      ctx.notes.add("ByteMatchStatement의 FieldToMatch 또는 TextTransformation이 미지원 — 평가 불가");
      return "UNKNOWN";
    }
    const transformed = applyTransforms(search, byte["TextTransformations"]);
    if (transformed === null) return "UNKNOWN";
    return positional(value, transformed, str(byte["PositionalConstraint"]));
  }

  const re = asRecord(s["RegexMatchStatement"]);
  if (re) {
    const pattern = str(re["RegexString"]);
    if (pattern === null) return "UNKNOWN";
    if (pattern.length > REGEX_MAX) {
      ctx.notes.add(`RegexString이 상한 ${REGEX_MAX}자를 초과 — 평가 불가`);
      return "UNKNOWN";
    }
    const value = preparedField(req, re);
    if (value === null) {
      ctx.notes.add("RegexMatchStatement의 FieldToMatch 또는 TextTransformation이 미지원 — 평가 불가");
      return "UNKNOWN";
    }
    try {
      return new RegExp(pattern).test(value);
    } catch {
      ctx.notes.add(`RegexString을 컴파일할 수 없음: ${pattern}`);
      return "UNKNOWN";
    }
  }

  const size = asRecord(s["SizeConstraintStatement"]);
  if (size) {
    const value = preparedField(req, size);
    if (value === null) {
      ctx.notes.add("SizeConstraintStatement의 FieldToMatch 또는 TextTransformation이 미지원 — 평가 불가");
      return "UNKNOWN";
    }
    return compare(byteLength(value), str(size["ComparisonOperator"]), Number(size["Size"] ?? 0));
  }

  for (const name of UNSUPPORTED_STATEMENTS) {
    if (name in s) {
      ctx.unsupported.add(name);
      return "UNKNOWN";
    }
  }

  const keys = Object.keys(s);
  ctx.unsupported.add(keys[0] ?? "(empty)");
  return "UNKNOWN";
}
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `pnpm test:rulestatement`
Expected: 전부 `PASS`, `ALL PASS`. 특히 `And false beats UNKNOWN`, `Or true beats UNKNOWN`, 그리고 미지원 문법 7종이 모두 `UNKNOWN`인 케이스가 통과해야 한다.

- [ ] **Step 6: 타입체크 + 커밋**

Run: `npx tsc --noEmit`
Expected: 출력 없음

```bash
git add src/lib/types.ts src/lib/server/rulestatement.ts scripts/rulestatement.test.mjs package.json
git commit -m "Add a three-valued WAF statement evaluator"
```

---

## Task 2: Rule 파싱 · 상한 · 기본 요청 · 판정

**Files:**
- Create: `src/lib/server/rulesim.ts`
- Create: `scripts/rulesim.test.mjs`

**Interfaces:**
- Consumes: Task 1의 `evalStatement`, `EvalContext`, `Verdict3`; 기존 `APP_TRAFFIC_PATHS` (config.ts)
- Produces:
  - `RULE_JSON_MAX = 20480`, `MAX_REQUESTS = 50`, `FIELD_MAX = 500`
  - `defaultTestRequests(): TestRequest[]`
  - `testRule(params: { ruleJson: string; requests: TestRequest[] }): RuleTestResult`

- [ ] **Step 1: 실패하는 테스트 작성**

`scripts/rulesim.test.mjs`:

```js
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { testRule, defaultTestRequests, RULE_JSON_MAX, MAX_REQUESTS, FIELD_MAX } = await import(
  `${SRC}rulesim.ts`
);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};
const throws = (name, fn, needle) => {
  let msg = null;
  try {
    fn();
  } catch (e) {
    msg = e instanceof Error ? e.message : String(e);
  }
  const ok = msg !== null && msg.includes(needle);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` + (ok ? "" : `\n        expected a message containing ${JSON.stringify(needle)}, got ${JSON.stringify(msg)}`),
  );
};

// --- Default request set tracks APP_TRAFFIC_PATHS ---
const defaults = defaultTestRequests();
check("default set has one row per served path plus loadgen and healthcheck", defaults.length, 6);
check("default ids are unique", new Set(defaults.map((r) => r.id)).size, defaults.length);
check(
  "default set covers the served surface",
  defaults.some((r) => r.path === "/v1/user") &&
    defaults.some((r) => r.path === "/v1/product") &&
    defaults.some((r) => r.path === "/v1/stress") &&
    defaults.some((r) => r.path === "/v1/image"),
  true,
);
check("default set includes the healthcheck", defaults.some((r) => r.path === "/healthcheck"), true);

const rule = (statement, action) =>
  JSON.stringify({ Name: "t", Priority: 100, Statement: statement, ...(action ? { Action: action } : {}) });
const uaContains = (needle) => ({
  ByteMatchStatement: {
    SearchString: needle,
    FieldToMatch: { SingleHeader: { Name: "user-agent" } },
    TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
    PositionalConstraint: "CONTAINS",
  },
});
const pathStarts = (p) => ({
  ByteMatchStatement: {
    SearchString: p,
    FieldToMatch: { UriPath: {} },
    TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
    PositionalConstraint: "STARTS_WITH",
  },
});

// --- A rule aimed off the served surface leaves normal traffic alone ---
const safe = testRule({ ruleJson: rule(pathStarts("/wp-login"), { Block: {} }), requests: defaults });
check("off-surface block rule blocks nothing normal", safe.blocked, 0);
check("off-surface block rule verdict is SAFE", safe.verdict, "SAFE");
check("off-surface block rule passes everything", safe.passed, defaults.length);
check("rule name is read", safe.ruleName, "t");
check("Block action is read", safe.action, "Block");

// --- A rule that catches the load generator's UA is a false positive ---
const fp = testRule({ ruleJson: rule(uaContains("go-http-client"), { Block: {} }), requests: defaults });
check("load-generator UA rule blocks one row", fp.blocked, 1);
check("load-generator UA rule verdict is the risk", fp.verdict, "FALSE_POSITIVE_RISK");
check(
  "the blocked row is the load generator",
  fp.rows.find((r) => r.outcome === "BLOCKED")?.requestId,
  defaults.find((r) => r.userAgent.includes("Go-http-client"))?.id,
);

// --- Count does not block ---
const counted = testRule({ ruleJson: rule(uaContains("go-http-client"), { Count: {} }), requests: defaults });
check("Count action is read", counted.action, "Count");
check("Count blocks nothing", counted.blocked, 0);
check("Count counts the match", counted.counted, 1);
check("Count verdict is SAFE", counted.verdict, "SAFE");

// --- Unsupported statement never reads as a pass ---
const unknown = testRule({
  ruleJson: rule({ RateBasedStatement: { Limit: 2000, AggregateKeyType: "IP" } }, { Block: {} }),
  requests: defaults,
});
check("rate-based rule yields no passes", unknown.passed, 0);
check("rate-based rule marks every row unknown", unknown.unknown, defaults.length);
check("rate-based rule verdict is inconclusive", unknown.verdict, "INCONCLUSIVE");
check("rate-based rule names the unsupported statement", unknown.unsupported, ["RateBasedStatement"]);

// --- A blocked row wins over an unknown row in the verdict ---
const mixed = testRule({
  ruleJson: rule(
    { OrStatement: { Statements: [uaContains("go-http-client"), { LabelMatchStatement: { Scope: "NAMESPACE", Key: "x" } }] } },
    { Block: {} },
  ),
  requests: defaults,
});
check("blocked beats unknown in the verdict", mixed.verdict, "FALSE_POSITIVE_RISK");

// --- Missing Action cannot be judged ---
const noAction = testRule({ ruleJson: rule(uaContains("go-http-client"), null), requests: defaults });
check("missing Action is reported", noAction.action, "(none)");
check("a match with no Action is unknown, not blocked", noAction.blocked, 0);
check("a match with no Action is unknown", noAction.unknown, 1);

// --- OverrideAction Count (managed groups) ---
const override = testRule({
  ruleJson: JSON.stringify({
    Name: "og",
    Priority: 1,
    Statement: uaContains("go-http-client"),
    OverrideAction: { Count: {} },
  }),
  requests: defaults,
});
check("OverrideAction Count is read as Count", override.action, "Count");

// --- Input limits ---
throws("rejects invalid JSON", () => testRule({ ruleJson: "{ nope", requests: defaults }), "JSON");
throws(
  "rejects a rule with no Statement",
  () => testRule({ ruleJson: JSON.stringify({ Name: "x" }), requests: defaults }),
  "Statement",
);
throws(
  "rejects an over-long rule",
  () => testRule({ ruleJson: "x".repeat(RULE_JSON_MAX + 1), requests: defaults }),
  "20",
);
throws(
  "rejects too many requests",
  () =>
    testRule({
      ruleJson: rule(pathStarts("/x"), { Block: {} }),
      requests: Array.from({ length: MAX_REQUESTS + 1 }, (_, i) => ({ ...defaults[0], id: `r${i}` })),
    }),
  String(MAX_REQUESTS),
);
throws(
  "rejects an over-long request field",
  () =>
    testRule({
      ruleJson: rule(pathStarts("/x"), { Block: {} }),
      requests: [{ ...defaults[0], path: "/".repeat(FIELD_MAX + 1) }],
    }),
  String(FIELD_MAX),
);
throws("rejects an empty request list", () => testRule({ ruleJson: rule(pathStarts("/x"), { Block: {} }), requests: [] }), "요청");

// --- Every row is accounted for ---
check(
  "counts always sum to the row count",
  safe.passed + safe.blocked + safe.counted + safe.unknown,
  safe.rows.length,
);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패 확인**

Run: `pnpm test:rulesim`
Expected: FAIL — `rulesim.ts` 모듈 없음

- [ ] **Step 3: 시뮬레이터 구현**

`src/lib/server/rulesim.ts`:

```ts
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
  }));
  rows.push({
    id: "loadgen",
    method: "GET",
    path: APP_TRAFFIC_PATHS[0] ?? "/v1/user",
    query: "",
    userAgent: "Go-http-client/2.0",
    ip: "10.0.2.23",
  });
  rows.push({
    id: "healthcheck",
    method: "GET",
    path: "/healthcheck",
    query: "",
    userAgent: "ELB-HealthChecker/2.0",
    ip: "10.0.2.1",
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
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `pnpm test:rulesim`
Expected: 전부 `PASS`, `ALL PASS`. 특히 `rate-based rule yields no passes`와 `blocked beats unknown in the verdict`가 통과해야 한다.

- [ ] **Step 5: 전체 테스트 회귀**

Run: `pnpm test`
Expected: 네 테스트 파일 모두 `ALL PASS`

- [ ] **Step 6: 타입체크 + 커밋**

Run: `npx tsc --noEmit`
Expected: 출력 없음

```bash
git add src/lib/server/rulesim.ts scripts/rulesim.test.mjs
git commit -m "Add rule parsing, input limits, and verdict for the sandbox"
```

---

## Task 3: 서버 액션

**Files:**
- Modify: `src/app/actions/dashboard.ts`

**Interfaces:**
- Consumes: Task 2의 `testRule`, `defaultTestRequests`
- Produces:
  - `testRuleJsonAction(params: { ruleJson: string; requests: TestRequest[] }): Promise<ActionResult<RuleTestResult>>`
  - `getDefaultTestRequestsAction(): Promise<ActionResult<TestRequest[]>>`

- [ ] **Step 1: 액션 추가**

import 블록에 추가한다:

```ts
import { defaultTestRequests, testRule } from "@/lib/server/rulesim";
```

`RuleTestResult`와 `TestRequest`를 기존 `@/lib/types` 타입 import 목록에 알파벳 순서로 넣는다. 그리고 파일 끝에 추가한다:

```ts
// ---------------------------------------------------------------------------
// Rule sandbox — evaluates a pasted WAFv2 Rule against synthetic requests.
// Pure and local: nothing is sent to AWS and no WebACL is touched.
// ---------------------------------------------------------------------------

export async function getDefaultTestRequestsAction(): Promise<ActionResult<TestRequest[]>> {
  try {
    return ok(defaultTestRequests());
  } catch (e) {
    return fail(e);
  }
}

export async function testRuleJsonAction(params: {
  ruleJson: string;
  requests: TestRequest[];
}): Promise<ActionResult<RuleTestResult>> {
  try {
    return ok(testRule(params));
  } catch (e) {
    return fail(e);
  }
}
```

`defaultTestRequests`와 `testRule`은 동기 함수지만 서버 액션은 async여야 하므로 `async` 선언을 유지한다.

- [ ] **Step 2: 타입체크**

Run: `npx tsc --noEmit`
Expected: 출력 없음

- [ ] **Step 3: 커밋**

```bash
git add src/app/actions/dashboard.ts
git commit -m "Expose the rule sandbox through server actions"
```

---

## Task 4: 시험 탭 UI

**Files:**
- Create: `src/app/dashboard/ui/SandboxTab.tsx`
- Modify: `src/app/dashboard/ui/DashboardClient.tsx` (`TABS` 17-23행, 렌더 분기 293-306행, props)

**Interfaces:**
- Consumes: Task 3의 두 액션; 기존 `Card`, `ErrorNote`, `SectionLoading` (shared.tsx); `WafPanel` PollState (추천 규칙 불러오기용)
- Produces: `<SandboxTab waf={waf} />`

- [ ] **Step 1: 탭 컴포넌트 작성**

`src/app/dashboard/ui/SandboxTab.tsx`:

```tsx
"use client";

import { useEffect, useState } from "react";
import { getDefaultTestRequestsAction, testRuleJsonAction } from "@/app/actions/dashboard";
import type { RuleTestResult, TestRequest, WafPanel } from "@/lib/types";
import { Card, ErrorNote, SectionLoading, type PollState } from "./shared";

const PLACEHOLDER = `{
  "Name": "block-wp-login",
  "Priority": 100,
  "Statement": {
    "ByteMatchStatement": {
      "SearchString": "/wp-login",
      "FieldToMatch": { "UriPath": {} },
      "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
      "PositionalConstraint": "STARTS_WITH"
    }
  },
  "Action": { "Block": {} }
}`;

const VERDICT_STYLE: Record<RuleTestResult["verdict"], { label: string; cls: string }> = {
  SAFE: { label: "안전 — 정상 요청 전부 통과", cls: "border-emerald-800 bg-emerald-950/40 text-emerald-300" },
  FALSE_POSITIVE_RISK: {
    label: "오탐 위험 — 정상 요청이 차단됨",
    cls: "border-red-800 bg-red-950/40 text-red-300",
  },
  INCONCLUSIVE: {
    label: "판정 불가 — 로컬에서 평가할 수 없는 문법 포함",
    cls: "border-amber-700 bg-amber-950/40 text-amber-300",
  },
};

const OUTCOME_STYLE: Record<string, { label: string; cls: string }> = {
  PASS: { label: "통과", cls: "text-emerald-400" },
  BLOCKED: { label: "차단", cls: "text-red-400 font-bold" },
  COUNTED: { label: "카운트만", cls: "text-amber-400" },
  UNKNOWN: { label: "판정 불가", cls: "text-neutral-400" },
};

const FIELDS = [
  { key: "method", label: "메소드", width: "w-16" },
  { key: "path", label: "경로", width: "w-40" },
  { key: "query", label: "쿼리", width: "w-32" },
  { key: "userAgent", label: "User-Agent", width: "w-48" },
  { key: "ip", label: "IP", width: "w-28" },
] as const;

export function SandboxTab({ waf }: { waf: PollState<WafPanel> }) {
  const [ruleJson, setRuleJson] = useState("");
  const [requests, setRequests] = useState<TestRequest[] | null>(null);
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      const res = await getDefaultTestRequestsAction();
      if (res.ok) setRequests(res.data);
      else setError(res.error);
    })();
  }, []);

  const run = async (): Promise<void> => {
    if (!requests) return;
    setBusy(true);
    setResult(null);
    const res = await testRuleJsonAction({ ruleJson, requests });
    if (res.ok) {
      setResult(res.data);
      setError(null);
    } else {
      setError(res.error);
    }
    setBusy(false);
  };

  const editField = (id: string, key: (typeof FIELDS)[number]["key"], value: string): void => {
    setRequests((prev) => (prev ?? []).map((r) => (r.id === id ? { ...r, [key]: value } : r)));
  };

  const addRow = (): void => {
    setRequests((prev) => [
      ...(prev ?? []),
      {
        id: `custom-${Date.now()}`,
        method: "GET",
        path: "/",
        query: "",
        userAgent: "Mozilla/5.0",
        ip: "10.0.2.1",
      },
    ]);
  };

  const removeRow = (id: string): void => {
    setRequests((prev) => (prev ?? []).filter((r) => r.id !== id));
  };

  const recs = waf.data?.recommendations ?? [];
  const rowById = new Map((requests ?? []).map((r) => [r.id, r]));

  return (
    <div className="space-y-3">
      <div className="rounded border border-neutral-800 bg-neutral-900/70 px-3 py-2 text-[11px] text-neutral-400">
        붙여넣은 규칙을 아래 요청들에 대해 <span className="text-neutral-200">로컬에서만</span> 평가합니다.
        AWS로 아무것도 전송하지 않고 WebACL도 건드리지 않습니다. 로컬에서 판정할 수 없는 문법은
        통과가 아니라 <span className="text-neutral-200">판정 불가</span>로 표시됩니다.
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card
          title="규칙 JSON"
          right={
            recs.length > 0 ? (
              <select
                defaultValue=""
                onChange={(e) => {
                  const rec = recs.find((r) => r.id === e.target.value);
                  if (rec) setRuleJson(rec.ruleJson);
                }}
                className="rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-[11px] text-neutral-300"
              >
                <option value="">추천 규칙 불러오기…</option>
                {recs.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} — {r.targetPattern.slice(0, 40)}
                  </option>
                ))}
              </select>
            ) : null
          }
        >
          <textarea
            value={ruleJson}
            onChange={(e) => setRuleJson(e.target.value)}
            placeholder={PLACEHOLDER}
            spellCheck={false}
            rows={16}
            className="w-full resize-y rounded border border-neutral-800 bg-neutral-950 p-2 font-mono text-[10px] text-neutral-200"
          />
          <div className="mt-2 flex items-center gap-2">
            <button
              type="button"
              onClick={() => void run()}
              disabled={busy || !ruleJson.trim() || !requests}
              className="rounded bg-sky-900 px-3 py-1 text-[11px] font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
            >
              {busy ? "평가 중…" : "시험 실행"}
            </button>
            <ErrorNote error={error} />
          </div>
        </Card>

        <Card
          title={`정상 요청 (${requests?.length ?? 0})`}
          right={
            <button
              type="button"
              onClick={addRow}
              className="rounded bg-neutral-800 px-2 py-0.5 text-[11px] text-neutral-300 hover:bg-neutral-700"
            >
              + 행 추가
            </button>
          }
        >
          {requests === null ? (
            <SectionLoading />
          ) : (
            <div className="max-h-80 overflow-auto">
              <table className="w-full text-left font-mono text-[10px]">
                <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
                  <tr>
                    {FIELDS.map((f) => (
                      <th key={f.key} className="px-1 py-1 font-medium">
                        {f.label}
                      </th>
                    ))}
                    <th className="px-1 py-1" />
                  </tr>
                </thead>
                <tbody>
                  {requests.map((r) => (
                    <tr key={r.id} className="border-t border-neutral-800">
                      {FIELDS.map((f) => (
                        <td key={f.key} className="px-1 py-0.5">
                          <input
                            value={r[f.key]}
                            onChange={(e) => editField(r.id, f.key, e.target.value)}
                            className={`${f.width} rounded border border-neutral-800 bg-neutral-950 px-1 py-0.5 text-neutral-200`}
                          />
                        </td>
                      ))}
                      <td className="px-1 py-0.5">
                        <button
                          type="button"
                          onClick={() => removeRow(r.id)}
                          aria-label={`${r.id} 삭제`}
                          className="rounded px-1 text-neutral-500 hover:bg-neutral-800 hover:text-neutral-200"
                        >
                          ✕
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {result && (
        <Card title={`결과 — ${result.ruleName} (Action: ${result.action})`}>
          <div
            className={`mb-2 rounded border px-3 py-2 text-[12px] font-semibold ${VERDICT_STYLE[result.verdict].cls}`}
          >
            {VERDICT_STYLE[result.verdict].label}
          </div>
          <div className="mb-2 flex gap-4 font-mono text-[11px]">
            <span className="text-emerald-400">통과 {result.passed}</span>
            <span className="text-red-400">차단 {result.blocked}</span>
            <span className="text-amber-400">카운트만 {result.counted}</span>
            <span className="text-neutral-400">판정 불가 {result.unknown}</span>
          </div>
          <table className="w-full text-left font-mono text-[10px]">
            <thead className="text-neutral-500">
              <tr>
                {["요청", "경로", "User-Agent", "결과", "이유"].map((h) => (
                  <th key={h} className="px-2 py-1 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((row) => {
                const req = rowById.get(row.requestId);
                const style = OUTCOME_STYLE[row.outcome] ?? OUTCOME_STYLE["UNKNOWN"];
                return (
                  <tr key={row.requestId} className="border-t border-neutral-800 text-neutral-300">
                    <td className="px-2 py-0.5 text-neutral-500">{row.requestId}</td>
                    <td className="max-w-40 truncate px-2 py-0.5" title={req?.path ?? ""}>
                      {req?.path ?? "-"}
                    </td>
                    <td className="max-w-40 truncate px-2 py-0.5 text-neutral-500" title={req?.userAgent ?? ""}>
                      {req?.userAgent ?? "-"}
                    </td>
                    <td className={`px-2 py-0.5 ${style?.cls ?? ""}`}>{style?.label ?? row.outcome}</td>
                    <td className="px-2 py-0.5 text-neutral-500">{row.reason}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {result.notes.length > 0 && (
            <ul className="mt-2 space-y-0.5 text-[11px] text-neutral-500">
              {result.notes.map((n, i) => (
                <li key={i}>· {n}</li>
              ))}
            </ul>
          )}
        </Card>
      )}
    </div>
  );
}
```

- [ ] **Step 2: 탭 등록**

`DashboardClient.tsx`의 `TABS`에 `Incident` 뒤로 추가한다:

```tsx
const TABS = [
  { id: "Overview", ko: "요약" },
  { id: "Investigation", ko: "조사" },
  { id: "WAF", ko: "방화벽" },
  { id: "Action", ko: "조치" },
  { id: "Incident", ko: "보고" },
  { id: "Sandbox", ko: "시험" },
] as const;
```

import를 추가하고:

```tsx
import { SandboxTab } from "./SandboxTab";
```

렌더 분기에 추가한다 (`{tab === "Incident" && <IncidentTab />}` 뒤):

```tsx
{tab === "Sandbox" && <SandboxTab waf={waf} />}
```

`waf` PollState는 `tab === "WAF" || tab === "Overview"`일 때만 활성화돼 있다(159-163행). 샌드박스에서도 추천 규칙을 불러오려면 그 조건에 `Sandbox`를 추가한다:

```tsx
  const waf: PollState<WafPanel> = usePoll(
    getWafPanelAction,
    Math.max(refreshSec, 30) * 1000,
    tab === "WAF" || tab === "Overview" || tab === "Sandbox",
  );
```

- [ ] **Step 3: 타입체크**

Run: `npx tsc --noEmit`
Expected: 출력 없음

- [ ] **Step 4: 전체 테스트 회귀**

Run: `pnpm test`
Expected: 네 테스트 파일 모두 `ALL PASS`

- [ ] **Step 5: 실제 앱에서 확인**

```bash
pnpm dev
```

`http://localhost:3100/dashboard` → 시험 탭. 확인 항목:

- 사이드바에 `SANDBOX 시험` 항목이 보이고 클릭하면 열리는지
- 정상 요청 표가 6행으로 채워져 있는지 (`/v1/user`, `/v1/product`, `/v1/stress`, `/v1/image`, loadgen, healthcheck)
- placeholder에 있는 `/wp-login` 차단 규칙을 붙여넣고 실행 → **안전, 통과 6 / 차단 0**
- `SearchString`을 `go-http-client`로, `FieldToMatch`를 `{"SingleHeader":{"Name":"user-agent"}}`로 바꿔 실행 → **오탐 위험, 차단 1** 이고 차단된 행이 loadgen인지
- 같은 규칙의 `Action`을 `{"Count":{}}`로 바꿔 실행 → **안전, 카운트만 1**, 노트에 COUNT 설명이 붙는지
- `Statement`를 `{"RateBasedStatement":{"Limit":2000,"AggregateKeyType":"IP"}}`로 바꿔 실행 → **판정 불가**, 전 행 `판정 불가`, 노트에 `RateBasedStatement` 언급
- 깨진 JSON(`{ nope`) 실행 → `조회 실패: 규칙 JSON 파싱 실패: …`
- `Statement` 없는 객체 실행 → `규칙에 Statement가 없음 …`
- 행 추가·삭제·필드 편집이 동작하고, 편집 후 재실행 시 결과가 바뀌는지
- WAF 탭에 추천 규칙이 있으면 `추천 규칙 불러오기` 셀렉트로 JSON이 채워지는지
- **AWS 호출이 없는지** — dev 서버 로그에 Insights/WAF 조회 지연이 없어야 한다 (평가는 즉시 응답)

- [ ] **Step 6: 커밋**

```bash
git add src/app/dashboard/ui/SandboxTab.tsx src/app/dashboard/ui/DashboardClient.tsx
git commit -m "Add the rule sandbox tab"
```

---

## Task 5: 마무리

- [ ] **Step 1: 전체 검증**

```bash
npx tsc --noEmit && pnpm test
```
Expected: 타입체크 무출력, 네 테스트 파일 `ALL PASS`

- [ ] **Step 2: 스펙 상태 갱신 + 푸시**

`docs/superpowers/specs/2026-08-10-waf-log-query-and-rule-sandbox-design.md`의 상태 줄을 바꾼다:

```markdown
상태: 파트 A · 파트 B 구현 완료
```

`SearchString` 평문 전용 결정을 스펙 B2에 한 문단으로 기록한다 (구현이 스펙과 다르면 스펙이 거짓말이 된다):

```markdown
**구현 시 결정 — `SearchString`은 평문만 해석한다.** 자동 판별이 불가능하다.
`"/v1/user"`는 유효한 base64로도 평문으로도 읽히므로, 추측하면 조용히 틀린
답을 낸다. base64가 필요하면 UI 토글을 추가하는 것이 옳다. 값이 base64로도
해석 가능할 때는 결과에 경고 노트를 붙인다.
```

```bash
git add docs/superpowers/specs/2026-08-10-waf-log-query-and-rule-sandbox-design.md
git commit -m "Record the SearchString decision and mark part B complete"
git push
```

---

## Self-Review

**스펙 커버리지**

| 스펙 요구 | 태스크 |
|---|---|
| B1 규칙 = Rule JSON 붙여넣기 | Task 4 Step 1 (textarea) |
| B1 추천 규칙 불러오기 셀렉트 | Task 4 Step 1 · Step 2(`waf` 활성 조건) |
| B1 요청 = APP_TRAFFIC_PATHS 파생 기본 집합 | Task 2 Step 3 `defaultTestRequests` |
| B1 요청 편집·행 추가·삭제 | Task 4 Step 1 |
| B2 3값 논리 And/Or/Not | Task 1 Step 4, 테스트 11건 |
| B2 ByteMatch 5종 constraint | Task 1 Step 4, 테스트 10건 |
| B2 RegexMatch + 컴파일 실패 UNKNOWN | Task 1 Step 4, 테스트 4건 |
| B2 SizeConstraint 6종 | Task 1 Step 4, 테스트 6건 |
| B2 FieldToMatch 5종 | Task 1 Step 4, 테스트 6건 |
| B2 TextTransformations 6종 + Priority 순서 | Task 1 Step 4, 테스트 6건 |
| B2 SearchString 평문·base64 | **의도적 차이** — 평문 전용 + 경고 노트. 상단 절에 근거 기술, Task 5에서 스펙에 반영 |
| B2 미지원 문법 UNKNOWN + 종류 나열 | Task 1 Step 4, 테스트 14건; Task 2의 `unsupported` |
| B3 판정 표 (통과/차단/카운트만/판정불가) | Task 2 `outcomeFor` |
| B3 verdict 우선순위 (차단 > UNKNOWN) | Task 2 Step 3, 테스트 `blocked beats unknown` |
| B4 두 서버 액션 | Task 3 |
| B4 TABS + SandboxTab | Task 4 Step 1-2 |
| B5 입력 상한 4종 | Task 2 Step 3, 테스트 5건 |
| B6 파싱 실패·Statement 누락·빈 요청 목록 | Task 2 Step 3, 테스트 4건 |

**플레이스홀더 스캔:** TBD/TODO 없음. 모든 코드 단계에 실제 코드가 들어 있다. Task 4 Step 5의 실앱 확인은 절차 목록이며 각 항목에 기대 결과가 명시돼 있다.

**타입 일관성:**
- `Verdict3`는 `rulestatement.ts`에서만 정의되고 `rulesim.ts`가 임포트한다. `RuleTestRow.matched`는 `boolean | null`이며 `"UNKNOWN"`이 아니다 — 변환은 `testRule`의 `v === "UNKNOWN" ? null : v` 한 곳에서만 일어난다
- `EvalContext`는 `rulestatement.ts` 정의를 `rulesim.ts`가 그대로 쓴다
- `RuleTestResult["action"]`을 `rulesim.ts`가 로컬 별칭 `Action`으로 참조한다. 멤버는 `"Block" | "Count" | "Allow" | "(none)"`이며 Task 1 Step 1의 타입 정의와 일치
- `OUTCOME_STYLE`은 `Record<string, …>`이라 `noUncheckedIndexedAccess` 하에서 조회 결과가 `| undefined`다. Task 4 Step 1은 `?? OUTCOME_STYLE["UNKNOWN"]`과 `style?.cls`로 처리한다
- `defaultTestRequests`의 `APP_TRAFFIC_PATHS[0]`도 `noUncheckedIndexedAccess` 대상이므로 `?? "/v1/user"` 폴백을 둔다
- 테스트의 `defaults[0]` 전개도 같은 이유로 런타임에는 안전하지만 `.mjs`라 타입체크 대상이 아니다

**의존 방향:** `rulestatement.ts` → types만. `rulesim.ts` → `rulestatement.ts` + `config.ts` + types. 어느 쪽도 AWS SDK를 임포트하지 않으므로 단위 테스트가 가볍다.
