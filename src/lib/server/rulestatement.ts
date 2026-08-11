import "server-only";
import { looksLikeSqli, looksLikeXss, readSensitivity } from "./ruleinjection";
import { evaluateManagedGroup } from "./rulemanaged";
import { ipInCidr, normalizeRequest, type NormalizedRequest } from "./rulerequest";
import { applyTransforms } from "./ruletransform";
import type { TestRequest } from "@/lib/types";

// Three-valued: UNKNOWN means "this cannot be decided locally". It is never
// collapsed into false or true — a rule tester that guesses is worse than none.
// The point of this module is to keep UNKNOWN rare: everything that *can* be
// decided from a synthetic request is decided, and what is left is named.
export type Verdict3 = boolean | "UNKNOWN";

export interface EvalContext {
  // statement types encountered that cannot be evaluated locally
  unsupported: Set<string>;
  // operator-facing explanations
  notes: Set<string>;
  // statement types answered by a local approximation rather than by AWS's own
  // implementation — the verdict is usable but not authoritative
  approximated: Set<string>;
  // referenced sets resolved from the pasted JSON, keyed by ARN, by ARN tail
  // and by bare name (all lower-cased)
  ipSets: Map<string, string[]>;
  regexSets: Map<string, string[]>;
  // labels a matching rule would add, collected for later LabelMatchStatements
  emitted: Set<string>;
}

export const REGEX_MAX = 200;

export function newEvalContext(init?: Partial<EvalContext>): EvalContext {
  return {
    unsupported: init?.unsupported ?? new Set(),
    notes: init?.notes ?? new Set(),
    approximated: init?.approximated ?? new Set(),
    ipSets: init?.ipSets ?? new Map(),
    regexSets: init?.regexSets ?? new Map(),
    emitted: init?.emitted ?? new Set(),
  };
}

// Statement types that still cannot be decided from a synthetic request: they
// depend on TLS-handshake fingerprints or on AWS-side ASN data.
const UNSUPPORTED_STATEMENTS = ["ASNMatchStatement"] as const;

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.map((x) => str(x)).filter((x): x is string => x !== null) : [];
}

// --- FieldToMatch ------------------------------------------------------------

// MatchScope on a multi-value field (Headers / Cookies / JsonBody) selects
// whether keys, values, or both are inspected.
function scoped(
  entries: Array<[string, string]>,
  scope: string | null,
): string[] {
  switch ((scope ?? "VALUE").toUpperCase()) {
    case "KEY":
      return entries.map(([k]) => k);
    case "ALL":
      return entries.flatMap(([k, v]) => [k, v]);
    default:
      return entries.map(([, v]) => v);
  }
}

// MatchPattern narrows which keys of a multi-value field are inspected.
function patternFilter(
  entries: Array<[string, string]>,
  pattern: unknown,
): Array<[string, string]> {
  const p = asRecord(pattern);
  if (!p || "All" in p) return entries;
  const included = strList(p["IncludedHeaders"] ?? p["IncludedCookies"]).map((s) => s.toLowerCase());
  if (included.length > 0) return entries.filter(([k]) => included.includes(k.toLowerCase()));
  const excluded = strList(p["ExcludedHeaders"] ?? p["ExcludedCookies"]).map((s) => s.toLowerCase());
  if (excluded.length > 0) return entries.filter(([k]) => !excluded.includes(k.toLowerCase()));
  return entries;
}

// Flattens a parsed JSON body into "path -> value" pairs so JsonBody's
// MatchScope (KEY / VALUE / ALL) has something to select from.
function flattenJson(value: unknown, prefix: string, out: Array<[string, string]>): void {
  if (Array.isArray(value)) {
    value.forEach((v, i) => flattenJson(v, `${prefix}/${i}`, out));
    return;
  }
  const rec = asRecord(value);
  if (rec) {
    for (const [k, v] of Object.entries(rec)) flattenJson(v, `${prefix}/${k}`, out);
    return;
  }
  out.push([prefix.split("/").pop() ?? prefix, value === null ? "null" : String(value)]);
}

// Returns the strings a matcher should be run against — a match on any of them
// is a match — or null when the field is one the synthetic request cannot
// model at all. An empty array is a definite "no match", not an unknown: it
// means the request simply does not carry that field.
function fieldValues(
  req: NormalizedRequest,
  field: unknown,
  ctx: EvalContext,
): string[] | null {
  const f = asRecord(field);
  if (!f) return null;

  if ("UriPath" in f) return [req.path];
  if ("QueryString" in f) return [req.query];
  if ("Method" in f) return [req.method];
  if ("Body" in f) return [req.body];
  if ("UriFragment" in f) {
    // The fragment never leaves the browser, so it is empty for every request
    // that reaches a WAF.
    ctx.notes.add("UriFragment는 서버로 전송되지 않는 필드 — 항상 빈 값으로 평가함");
    return [""];
  }
  if ("HeaderOrder" in f) return [[...req.headers.keys()].join(",")];

  if ("AllQueryArguments" in f) return req.args.map((a) => a.value);

  if ("SingleQueryArgument" in f) {
    const name = str(asRecord(f["SingleQueryArgument"])?.["Name"])?.toLowerCase() ?? "";
    return req.args.filter((a) => a.name === name).map((a) => a.value);
  }

  if ("SingleHeader" in f) {
    const name = str(asRecord(f["SingleHeader"])?.["Name"])?.toLowerCase() ?? "";
    const value = req.headers.get(name);
    if (value === undefined) {
      ctx.notes.add(
        `요청에 "${name}" 헤더가 없어 미매칭으로 평가함 — 필요하면 요청 행의 헤더란에 추가`,
      );
      return [];
    }
    return [value];
  }

  if ("Headers" in f) {
    const h = asRecord(f["Headers"]) ?? {};
    const entries = patternFilter([...req.headers.entries()], h["MatchPattern"]);
    return scoped(entries, str(h["MatchScope"]));
  }

  if ("Cookies" in f) {
    const c = asRecord(f["Cookies"]) ?? {};
    const entries = patternFilter([...req.cookies.entries()], c["MatchPattern"]);
    return scoped(entries, str(c["MatchScope"]));
  }

  if ("JsonBody" in f) {
    const j = asRecord(f["JsonBody"]) ?? {};
    if (req.body.length === 0) return [];
    let parsed: unknown;
    try {
      parsed = JSON.parse(req.body);
    } catch {
      // InvalidFallbackBehavior: EVALUATE_AS_STRING inspects the raw body,
      // MATCH / NO_MATCH short-circuit the whole statement upstream.
      const fallback = (str(j["InvalidFallbackBehavior"]) ?? "EVALUATE_AS_STRING").toUpperCase();
      if (fallback === "EVALUATE_AS_STRING") return [req.body];
      ctx.notes.add(`바디가 JSON이 아니어서 JsonBody의 InvalidFallbackBehavior=${fallback} 적용`);
      return fallback === "MATCH" ? null : [];
    }
    const flat: Array<[string, string]> = [];
    flattenJson(parsed, "", flat);
    return scoped(patternFilter(flat, j["MatchPattern"]), str(j["MatchScope"]));
  }

  const key = Object.keys(f)[0] ?? "(empty)";
  ctx.unsupported.add(`FieldToMatch:${key}`);
  return null;
}

// Runs FieldToMatch + TextTransformations. Returns null when either is
// unsupported, after naming the culprit in the context.
function preparedValues(
  req: NormalizedRequest,
  body: Record<string, unknown>,
  ctx: EvalContext,
  what: string,
): string[] | null {
  const raw = fieldValues(req, body["FieldToMatch"], ctx);
  if (raw === null) return null;
  const out: string[] = [];
  for (const v of raw) {
    const t = applyTransforms(v, body["TextTransformations"]);
    if (!t.ok) {
      ctx.unsupported.add(`TextTransformation:${t.type}`);
      ctx.notes.add(`${what}의 TextTransformation "${t.type}"은 로컬에서 재현할 수 없음 — 평가 불가`);
      return null;
    }
    out.push(t.value);
  }
  return out;
}

function decodeBase64(s: string): string {
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return "";
  }
}

// Distinguishes an actual base64 blob from an ordinary word that happens to fit
// the alphabet. Plain search strings like "gobuster", "nmap" or "/admin/login"
// are all valid base64 by charset alone, so warning on those buries the one
// case that matters under noise. A real encoding of ASCII text mixes case (or
// carries digits / padding), never starts as a URI path, and decodes to
// printable text.
function looksBase64Encoded(s: string): boolean {
  if (s.length < 8 || s.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return false;
  if (s.startsWith("/")) return false;
  const mixedCase = /[a-z]/.test(s) && /[A-Z]/.test(s);
  if (!mixedCase && !/[0-9+/=]/.test(s)) return false;
  const decoded = decodeBase64(s);
  return decoded.length >= 3 && /^[\x20-\x7e]+$/.test(decoded);
}

// --- matchers ----------------------------------------------------------------

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

// Any-of over a multi-valued field, keeping the three-valued semantics.
function anyOf(values: string[], test: (v: string) => Verdict3): Verdict3 {
  let sawUnknown = false;
  for (const v of values) {
    const r = test(v);
    if (r === true) return true;
    if (r === "UNKNOWN") sawUnknown = true;
  }
  return sawUnknown ? "UNKNOWN" : false;
}

// A compiled user regex is bounded in length; the compile itself is guarded.
function safeRegex(pattern: string, ctx: EvalContext): RegExp | null {
  if (pattern.length > REGEX_MAX) {
    ctx.notes.add(`RegexString이 상한 ${REGEX_MAX}자를 초과 — 평가 불가`);
    return null;
  }
  try {
    return new RegExp(pattern);
  } catch {
    ctx.notes.add(`RegexString을 컴파일할 수 없음: ${pattern}`);
    return null;
  }
}

// --- referenced sets ---------------------------------------------------------

// A reference can be resolved from an inline list on the statement itself (a
// sandbox convenience) or from the top-level "IPSets" / "RegexPatternSets"
// block of the pasted JSON, matched by full ARN, by ARN tail, or by bare name.
function resolveSet(
  store: Map<string, string[]>,
  arn: string | null,
  inline: string[],
): string[] | null {
  if (inline.length > 0) return inline;
  if (arn === null) return null;
  const key = arn.toLowerCase();
  const direct = store.get(key);
  if (direct) return direct;
  // "arn:aws:wafv2:us-east-1:1234:global/ipset/office-ips/abcd-efgh"
  for (const part of key.split("/").reverse()) {
    const hit = store.get(part);
    if (hit) return hit;
  }
  return null;
}

// The console exports a regex pattern set three different ways depending on the
// command used; accept all of them as an inline definition.
function inlineRegexStrings(stmt: Record<string, unknown>): string[] {
  const direct = strList(stmt["RegexStrings"]);
  if (direct.length > 0) return direct;
  const nested = strList(asRecord(stmt["RegexPatternSet"])?.["RegularExpressionList"]);
  if (nested.length > 0) return nested;
  const objects = [
    ...(Array.isArray(stmt["RegularExpressionList"]) ? stmt["RegularExpressionList"] : []),
    ...(Array.isArray(asRecord(stmt["RegexPatternSet"])?.["RegularExpressionList"])
      ? (asRecord(stmt["RegexPatternSet"])?.["RegularExpressionList"] as unknown[])
      : []),
  ];
  return objects.map((e) => str(asRecord(e)?.["RegexString"])).filter((x): x is string => x !== null);
}

// Forwarded-IP handling for IPSetReferenceStatement / RateBasedStatement.
function forwardedIp(
  req: NormalizedRequest,
  config: unknown,
): { ips: string[]; fallback: "MATCH" | "NO_MATCH" } | null {
  const c = asRecord(config);
  if (!c) return null;
  const header = (str(c["HeaderName"]) ?? "x-forwarded-for").toLowerCase();
  const fallback = (str(c["FallbackBehavior"]) ?? "NO_MATCH").toUpperCase() === "MATCH" ? "MATCH" : "NO_MATCH";
  const raw = req.headers.get(header);
  if (raw === undefined || raw.trim().length === 0) return { ips: [], fallback };
  const list = raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  const position = (str(c["Position"]) ?? "FIRST").toUpperCase();
  if (position === "FIRST") return { ips: list.slice(0, 1), fallback };
  if (position === "LAST") return { ips: list.slice(-1), fallback };
  return { ips: list, fallback };
}

// --- evaluator ---------------------------------------------------------------

function isNormalized(r: TestRequest | NormalizedRequest): r is NormalizedRequest {
  return (r as NormalizedRequest).cookies instanceof Map;
}

// Accepts either a raw TestRequest (normalizing it on the spot) or a request
// already normalized by the caller, so a multi-rule run normalizes only once.
export function evalStatement(
  stmt: unknown,
  request: TestRequest | NormalizedRequest,
  ctx: EvalContext,
): Verdict3 {
  return evalNormalized(stmt, isNormalized(request) ? request : normalizeRequest(request), ctx);
}

function evalNormalized(stmt: unknown, req: NormalizedRequest, ctx: EvalContext): Verdict3 {
  const s = asRecord(stmt);
  if (!s) return "UNKNOWN";

  const and = asRecord(s["AndStatement"]);
  if (and) {
    const parts = Array.isArray(and["Statements"]) ? and["Statements"] : [];
    const results = parts.map((p) => evalNormalized(p, req, ctx));
    if (results.some((r) => r === false)) return false;
    if (results.some((r) => r === "UNKNOWN")) return "UNKNOWN";
    return results.length > 0;
  }

  const or = asRecord(s["OrStatement"]);
  if (or) {
    const parts = Array.isArray(or["Statements"]) ? or["Statements"] : [];
    const results = parts.map((p) => evalNormalized(p, req, ctx));
    if (results.some((r) => r === true)) return true;
    if (results.some((r) => r === "UNKNOWN")) return "UNKNOWN";
    return false;
  }

  const not = asRecord(s["NotStatement"]);
  if (not) {
    const inner = evalNormalized(not["Statement"], req, ctx);
    return inner === "UNKNOWN" ? "UNKNOWN" : !inner;
  }

  const byte = asRecord(s["ByteMatchStatement"]);
  if (byte) {
    const search = str(byte["SearchString"]);
    if (search === null) {
      ctx.notes.add("ByteMatchStatement의 SearchString이 문자열이 아님 — 평가 불가");
      return "UNKNOWN";
    }
    // `aws wafv2 get-web-acl` emits SearchString base64-encoded, so a pasted
    // rule may carry a blob where the author expects plain text. Warn only when
    // the value really reads as an encoded blob — see looksBase64Encoded.
    if (looksBase64Encoded(search)) {
      ctx.notes.add(
        `SearchString "${search}"은 base64로 인코딩된 값으로 보임 (디코딩하면 "${decodeBase64(search)}") — 평문으로 간주해 평가했으므로 의도한 값인지 확인 필요`,
      );
    }
    const values = preparedValues(req, byte, ctx, "ByteMatchStatement");
    if (values === null) return "UNKNOWN";
    // WAF applies TextTransformations to the inspected field only — the
    // SearchString you author is compared as-is.
    const constraint = str(byte["PositionalConstraint"]);
    return anyOf(values, (v) => positional(v, search, constraint));
  }

  const re = asRecord(s["RegexMatchStatement"]);
  if (re) {
    const pattern = str(re["RegexString"]);
    if (pattern === null) return "UNKNOWN";
    const compiled = safeRegex(pattern, ctx);
    if (compiled === null) return "UNKNOWN";
    const values = preparedValues(req, re, ctx, "RegexMatchStatement");
    if (values === null) return "UNKNOWN";
    return values.some((v) => compiled.test(v));
  }

  const regexSet = asRecord(s["RegexPatternSetReferenceStatement"]);
  if (regexSet) {
    const patterns = resolveSet(ctx.regexSets, str(regexSet["ARN"]), inlineRegexStrings(regexSet));
    if (patterns === null) {
      ctx.unsupported.add("RegexPatternSetReferenceStatement");
      ctx.notes.add(
        '정규식 패턴 세트를 로컬에서 알 수 없음 — 붙여넣은 JSON 최상위에 "RegexPatternSets": { "<세트이름 또는 ARN>": ["정규식", …] } 을 추가하면 평가함',
      );
      return "UNKNOWN";
    }
    const compiled = patterns.map((p) => safeRegex(p, ctx));
    if (compiled.some((c) => c === null)) return "UNKNOWN";
    const values = preparedValues(req, regexSet, ctx, "RegexPatternSetReferenceStatement");
    if (values === null) return "UNKNOWN";
    return values.some((v) => compiled.some((c) => c?.test(v) === true));
  }

  const ipSet = asRecord(s["IPSetReferenceStatement"]);
  if (ipSet) {
    const cidrs = resolveSet(
      ctx.ipSets,
      str(ipSet["ARN"]),
      strList(ipSet["Addresses"]).length > 0
        ? strList(ipSet["Addresses"])
        : strList(asRecord(ipSet["IPSet"])?.["Addresses"]),
    );
    if (cidrs === null) {
      ctx.unsupported.add("IPSetReferenceStatement");
      ctx.notes.add(
        'IP 세트 내용을 로컬에서 알 수 없음 — 붙여넣은 JSON 최상위에 "IPSets": { "<세트이름 또는 ARN>": ["10.0.0.0/8", …] } 을 추가하면 평가함',
      );
      return "UNKNOWN";
    }
    const fwd = forwardedIp(req, ipSet["IPSetForwardedIPConfig"]);
    if (fwd) {
      if (fwd.ips.length === 0) return fwd.fallback === "MATCH";
      return fwd.ips.some((ip) => cidrs.some((c) => ipInCidr(ip, c)));
    }
    return cidrs.some((c) => ipInCidr(req.ip, c));
  }

  const size = asRecord(s["SizeConstraintStatement"]);
  if (size) {
    const values = preparedValues(req, size, ctx, "SizeConstraintStatement");
    if (values === null) return "UNKNOWN";
    const op = str(size["ComparisonOperator"]);
    const limit = Number(size["Size"] ?? 0);
    return anyOf(values, (v) => compare(byteLength(v), op, limit));
  }

  const geo = asRecord(s["GeoMatchStatement"]);
  if (geo) {
    const codes = strList(geo["CountryCodes"]);
    if (codes.length === 0) {
      ctx.notes.add("GeoMatchStatement에 CountryCodes가 없음 — 평가 불가");
      return "UNKNOWN";
    }
    return codes.map((c) => c.toUpperCase()).includes(req.country.toUpperCase());
  }

  const sqli = asRecord(s["SqliMatchStatement"]);
  if (sqli) {
    const values = preparedValues(req, sqli, ctx, "SqliMatchStatement");
    if (values === null) return "UNKNOWN";
    ctx.approximated.add("SqliMatchStatement");
    ctx.notes.add(
      "SqliMatchStatement는 AWS 내부 토크나이저 대신 로컬 시그니처로 근사 평가 — 실제 WAF 판정과 다를 수 있음",
    );
    const level = readSensitivity(sqli["SensitivityLevel"]);
    return values.some((v) => looksLikeSqli(v, level));
  }

  const xss = asRecord(s["XssMatchStatement"]);
  if (xss) {
    const values = preparedValues(req, xss, ctx, "XssMatchStatement");
    if (values === null) return "UNKNOWN";
    ctx.approximated.add("XssMatchStatement");
    ctx.notes.add(
      "XssMatchStatement는 AWS 내부 토크나이저 대신 로컬 시그니처로 근사 평가 — 실제 WAF 판정과 다를 수 있음",
    );
    return values.some((v) => looksLikeXss(v, "HIGH"));
  }

  const label = asRecord(s["LabelMatchStatement"]);
  if (label) {
    const key = str(label["Key"]);
    if (key === null) return "UNKNOWN";
    const scope = (str(label["Scope"]) ?? "LABEL").toUpperCase();
    const all = new Set([...req.labels, ...ctx.emitted]);
    if (all.size === 0) {
      ctx.notes.add(
        `라벨 "${key}"를 붙이는 선행 규칙이 없음 — 미매칭으로 평가함(요청 행의 라벨란에 직접 넣으면 매칭 검증 가능)`,
      );
      return false;
    }
    const needle = key.toLowerCase();
    return [...all].some((l) => {
      const have = l.toLowerCase();
      return scope === "NAMESPACE" ? have.startsWith(needle) : have === needle;
    });
  }

  const rate = asRecord(s["RateBasedStatement"]);
  if (rate) {
    ctx.approximated.add("RateBasedStatement");
    const limit = Number(rate["Limit"] ?? 0);
    const window = Number(rate["EvaluationWindowSec"] ?? 300);
    ctx.notes.add(
      `RateBasedStatement는 요청량(${limit || "?"}건/${window}초)이 조건 — 합성 요청 한 건으로는 재현할 수 없어 스코프다운 조건만 평가함. 매칭으로 표시된 행은 "해당 키가 임계치를 넘겼을 때 걸린다"는 뜻.`,
    );
    if (!("ScopeDownStatement" in rate)) return true;
    return evalNormalized(rate["ScopeDownStatement"], req, ctx);
  }

  const managed = asRecord(s["ManagedRuleGroupStatement"]);
  if (managed) {
    const vendor = str(managed["VendorName"]) ?? "";
    const name = str(managed["Name"]) ?? "";
    if ("ScopeDownStatement" in managed) {
      const scope = evalNormalized(managed["ScopeDownStatement"], req, ctx);
      if (scope !== true) return scope;
    }
    const excluded = new Set<string>([
      ...strList(
        Array.isArray(managed["ExcludedRules"])
          ? managed["ExcludedRules"].map((e) => str(asRecord(e)?.["Name"]))
          : [],
      ),
      // A rule overridden to Count still matches; only Allow removes it from
      // the group's blocking behaviour.
      ...(Array.isArray(managed["RuleActionOverrides"])
        ? managed["RuleActionOverrides"]
            .map((o) => asRecord(o))
            .filter((o): o is Record<string, unknown> => o !== null)
            .filter((o) => "Allow" in (asRecord(o["ActionToUse"]) ?? {}))
            .map((o) => str(o["Name"]) ?? "")
        : []),
    ]);
    const verdict = evaluateManagedGroup(vendor, name, req, excluded);
    if (verdict.matched === "UNKNOWN") {
      ctx.unsupported.add(`ManagedRuleGroupStatement(${name})`);
      if (verdict.note) ctx.notes.add(verdict.note);
      return "UNKNOWN";
    }
    ctx.approximated.add(`ManagedRuleGroupStatement(${name})`);
    ctx.notes.add(
      `관리형 규칙 그룹 "${name}"은 공개된 규칙 의도를 로컬 근사로 평가 — 실제 매칭 여부는 COUNT로 확인 필요`,
    );
    if (verdict.matched) {
      for (const l of verdict.labels) ctx.emitted.add(l);
      ctx.notes.add(`"${name}" 근사 매칭: ${verdict.rules.join(", ")}`);
    }
    return verdict.matched;
  }

  const groupRef = asRecord(s["RuleGroupReferenceStatement"]);
  if (groupRef) {
    const rules = Array.isArray(groupRef["Rules"]) ? groupRef["Rules"] : null;
    if (rules === null) {
      ctx.unsupported.add("RuleGroupReferenceStatement");
      ctx.notes.add(
        '사용자 규칙 그룹의 내용을 로컬에서 알 수 없음 — 문장 안에 "Rules": [ … ] 로 규칙 배열을 넣으면 평가함',
      );
      return "UNKNOWN";
    }
    if ("ScopeDownStatement" in groupRef) {
      const scope = evalNormalized(groupRef["ScopeDownStatement"], req, ctx);
      if (scope !== true) return scope;
    }
    ctx.approximated.add("RuleGroupReferenceStatement");
    const results = rules.map((r) => evalNormalized(asRecord(r)?.["Statement"], req, ctx));
    if (results.some((r) => r === true)) return true;
    if (results.some((r) => r === "UNKNOWN")) return "UNKNOWN";
    return false;
  }

  for (const name of UNSUPPORTED_STATEMENTS) {
    if (name in s) {
      ctx.unsupported.add(name);
      ctx.notes.add(`${name}은 AWS 측 데이터가 있어야 판정 가능 — 로컬 평가 불가`);
      return "UNKNOWN";
    }
  }

  const keys = Object.keys(s);
  ctx.unsupported.add(keys[0] ?? "(empty)");
  return "UNKNOWN";
}
