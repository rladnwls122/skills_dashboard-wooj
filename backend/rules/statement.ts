// The WAFv2 statement evaluator. Three-valued: UNKNOWN means "this cannot be
// decided locally" and is never collapsed into a yes or no.
//
// One honest difference from AWS: WAF runs RE2, JavaScript runs a backtracking
// engine. RegexString length is capped (REGEX_MAX) to bound the damage, and a
// pattern RE2 accepts but JavaScript rejects is reported as uncompilable rather
// than guessed at.

import { looksLikeSqli, looksLikeXss, readSensitivity, SENSITIVITY_HIGH } from "./injection.ts";
import { argValues, evaluateManagedGroup } from "./managed.ts";
import { ipInCidr, type NormalizedRequest } from "./request.ts";
import { applyTransforms } from "./transform.ts";
import { fromBool, VERDICT_FALSE, VERDICT_TRUE, VERDICT_UNKNOWN, type Verdict3 } from "./verdict.ts";

export class EvalContext {
  /** Statement types encountered that cannot be evaluated locally. */
  readonly unsupported = new Set<string>();
  /** Operator-facing explanations. */
  readonly notes = new Set<string>();
  /** Statement types answered by a local approximation — usable, not authoritative. */
  readonly approximated = new Set<string>();
  /**
   * Referenced sets resolved from the pasted JSON, keyed by ARN, ARN tail and
   * bare name (all lower-cased).
   */
  readonly ipSets = new Map<string, string[]>();
  readonly regexSets = new Map<string, string[]>();
  /** Labels a matching rule would add, collected for later LabelMatchStatements. */
  readonly emitted = new Set<string>();

  note(s: string): void {
    this.notes.add(s);
  }
  unsup(s: string): void {
    this.unsupported.add(s);
  }
  approx(s: string): void {
    this.approximated.add(s);
  }
}

export const REGEX_MAX = 200;

type Rec = Record<string, unknown>;

function asRecord(v: unknown): Rec | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function num(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "string") {
    const n = Number.parseFloat(v);
    return Number.isFinite(n) ? n : 0;
  }
  return 0;
}

type Entry = [string, string];

/** Unknown values are carried out of band, so a caller cannot mistake [] for it. */
const UNKNOWN_VALUES = null;

// --- FieldToMatch ------------------------------------------------------------

/** MatchScope on a multi-value field selects keys, values, or both. */
function scoped(entries: Entry[], scope: string): string[] {
  switch (scope.toUpperCase()) {
    case "KEY":
      return entries.map((e) => e[0]);
    case "ALL":
      return entries.flatMap((e) => [e[0], e[1]]);
    default:
      return entries.map((e) => e[1]);
  }
}

/** MatchPattern narrows which keys of a multi-value field are inspected. */
function patternFilter(entries: Entry[], pattern: unknown): Entry[] {
  const p = asRecord(pattern);
  if (!p) return entries;
  if ("All" in p) return entries;

  const lower = (list: string[]): Set<string> => new Set(list.map((s) => s.toLowerCase()));

  let included = strList(p.IncludedHeaders);
  if (included.length === 0) included = strList(p.IncludedCookies);
  if (included.length > 0) {
    const set = lower(included);
    return entries.filter((e) => set.has(e[0].toLowerCase()));
  }

  let excluded = strList(p.ExcludedHeaders);
  if (excluded.length === 0) excluded = strList(p.ExcludedCookies);
  if (excluded.length > 0) {
    const set = lower(excluded);
    return entries.filter((e) => !set.has(e[0].toLowerCase()));
  }
  return entries;
}

/**
 * Flattens a parsed JSON body into "leaf key -> value" pairs so JsonBody's
 * MatchScope has something to select from.
 */
function flattenJson(value: unknown, prefix: string, out: Entry[]): void {
  if (Array.isArray(value)) {
    value.forEach((item, i) => flattenJson(item, `${prefix}/${i}`, out));
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [k, item] of Object.entries(value as Rec)) {
      flattenJson(item, `${prefix}/${k}`, out);
    }
    return;
  }
  const slash = prefix.lastIndexOf("/");
  const key = slash >= 0 ? prefix.slice(slash + 1) : prefix;
  let s: string;
  if (value === null) s = "null";
  else if (typeof value === "string") s = value;
  else s = String(value);
  out.push([key, s]);
}

/**
 * The strings a matcher should be run against — a match on any of them is a
 * match — or null when the field cannot be modelled. An empty array is a
 * definite "no match".
 */
function fieldValues(
  req: NormalizedRequest,
  field: unknown,
  ctx: EvalContext,
): string[] | null {
  const f = asRecord(field);
  if (!f) return UNKNOWN_VALUES;

  if ("UriPath" in f) return [req.path];
  if ("QueryString" in f) return [req.query];
  if ("Method" in f) return [req.method];
  if ("Body" in f) return [req.body];
  if ("UriFragment" in f) {
    // The fragment never leaves the browser, so it is empty for every request
    // that reaches a WAF.
    ctx.note("UriFragment는 서버로 전송되지 않는 필드 — 항상 빈 값으로 평가함");
    return [""];
  }
  if ("HeaderOrder" in f) return [[...req.headers.keys()].join(",")];
  if ("AllQueryArguments" in f) return argValues(req);

  if (f.SingleQueryArgument !== undefined) {
    const name = (str(asRecord(f.SingleQueryArgument)?.Name) ?? "").toLowerCase();
    return req.args.filter((a) => a.name === name).map((a) => a.value);
  }

  if (f.SingleHeader !== undefined) {
    const name = (str(asRecord(f.SingleHeader)?.Name) ?? "").toLowerCase();
    const value = req.headers.get(name);
    if (value === undefined) {
      ctx.note(`요청에 "${name}" 헤더가 없어 미매칭으로 평가함 — 필요하면 요청 행의 헤더란에 추가`);
      return [];
    }
    return [value];
  }

  if (f.Headers !== undefined) {
    const h = asRecord(f.Headers) ?? {};
    const entries = patternFilter([...req.headers.entries()], h.MatchPattern);
    return scoped(entries, str(h.MatchScope) || "VALUE");
  }

  if (f.Cookies !== undefined) {
    const c = asRecord(f.Cookies) ?? {};
    const entries = patternFilter([...req.cookies.entries()], c.MatchPattern);
    return scoped(entries, str(c.MatchScope) || "VALUE");
  }

  if (f.JsonBody !== undefined) {
    const j = asRecord(f.JsonBody) ?? {};
    if (req.body === "") return [];
    let parsed: unknown;
    try {
      parsed = JSON.parse(req.body);
    } catch {
      // InvalidFallbackBehavior: EVALUATE_AS_STRING inspects the raw body,
      // MATCH / NO_MATCH short-circuit the whole statement upstream.
      const fallback = (str(j.InvalidFallbackBehavior) ?? "").toUpperCase();
      if (fallback === "" || fallback === "EVALUATE_AS_STRING") return [req.body];
      ctx.note(`바디가 JSON이 아니어서 JsonBody의 InvalidFallbackBehavior=${fallback} 적용`);
      return fallback === "MATCH" ? UNKNOWN_VALUES : [];
    }
    const flat: Entry[] = [];
    flattenJson(parsed, "", flat);
    return scoped(patternFilter(flat, j.MatchPattern), str(j.MatchScope) || "VALUE");
  }

  ctx.unsup("FieldToMatch:" + (Object.keys(f)[0] ?? "(empty)"));
  return UNKNOWN_VALUES;
}

/**
 * Runs FieldToMatch + TextTransformations. Returns null when either is
 * unsupported, after naming the culprit in the context.
 */
function preparedValues(
  req: NormalizedRequest,
  body: Rec,
  ctx: EvalContext,
  what: string,
): string[] | null {
  const raw = fieldValues(req, body.FieldToMatch, ctx);
  if (raw === null) return null;
  const out: string[] = [];
  for (const v of raw) {
    const t = applyTransforms(v, body.TextTransformations);
    if (!t.ok) {
      ctx.unsup("TextTransformation:" + t.type);
      ctx.note(`${what}의 TextTransformation "${t.type}"은 로컬에서 재현할 수 없음 — 평가 불가`);
      return null;
    }
    out.push(t.value);
  }
  return out;
}

function decodeBase64Str(s: string): string {
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return "";
  }
}

const B64_EXACT_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const PRINTABLE_RE = /^[\x20-\x7e]+$/;

/**
 * Distinguishes an actual base64 blob from an ordinary word that happens to fit
 * the alphabet: length, padding, a mix of cases or digits, and a decode that
 * comes out printable.
 */
function looksBase64Encoded(s: string): boolean {
  if (s.length < 8 || s.length % 4 !== 0) return false;
  if (!B64_EXACT_RE.test(s)) return false;
  if (s.startsWith("/")) return false;
  const mixedCase = /[a-z]/.test(s) && /[A-Z]/.test(s);
  if (!mixedCase && !/[0-9+/=]/.test(s)) return false;
  const decoded = decodeBase64Str(s);
  return decoded.length >= 3 && PRINTABLE_RE.test(decoded);
}

// --- matchers ----------------------------------------------------------------

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function positional(haystack: string, needle: string, constraint: string): Verdict3 {
  switch (constraint) {
    case "EXACTLY":
      return fromBool(haystack === needle);
    case "STARTS_WITH":
      return fromBool(haystack.startsWith(needle));
    case "ENDS_WITH":
      return fromBool(haystack.endsWith(needle));
    case "CONTAINS":
      return fromBool(haystack.includes(needle));
    case "CONTAINS_WORD": {
      // WAF: the search string must appear delimited by characters outside
      // [A-Za-z0-9_].
      if (needle === "") return VERDICT_FALSE;
      try {
        const re = new RegExp(`(^|[^A-Za-z0-9_])${escapeRe(needle)}($|[^A-Za-z0-9_])`);
        return fromBool(re.test(haystack));
      } catch {
        return VERDICT_UNKNOWN;
      }
    }
    default:
      return VERDICT_UNKNOWN;
  }
}

function compare(actual: number, op: string, size: number): Verdict3 {
  switch (op) {
    case "EQ":
      return fromBool(actual === size);
    case "NE":
      return fromBool(actual !== size);
    case "LE":
      return fromBool(actual <= size);
    case "LT":
      return fromBool(actual < size);
    case "GE":
      return fromBool(actual >= size);
    case "GT":
      return fromBool(actual > size);
    default:
      return VERDICT_UNKNOWN;
  }
}

/** Any-of over a multi-valued field, keeping the three-valued semantics. */
function anyOf(values: string[], test: (v: string) => Verdict3): Verdict3 {
  let sawUnknown = false;
  for (const v of values) {
    const r = test(v);
    if (r === VERDICT_TRUE) return VERDICT_TRUE;
    if (r === VERDICT_UNKNOWN) sawUnknown = true;
  }
  return sawUnknown ? VERDICT_UNKNOWN : VERDICT_FALSE;
}

/**
 * Nested unbounded quantifiers — `(a+)+`, `(a*)*`, `(a|a)+` — are the shapes
 * whose backtracking is exponential in the subject length. RE2 runs them in
 * linear time, so AWS accepts patterns that would hang this process; the
 * evaluator is on the only thread the HTTP server has, so a single one of these
 * takes the whole dashboard down mid-exercise with no way to interrupt it.
 *
 * Detected structurally rather than by timing it, because there is no way to
 * abort a running JavaScript regex. Refusing to evaluate is the honest answer:
 * the result is UNKNOWN with a note, which the sandbox already renders.
 */
const NESTED_QUANTIFIER_RE = /\([^()]*[+*][^()]*\)\s*[+*{]|\([^()]*\|[^()]*\)\s*[+*{]/;

/**
 * Longest subject a user-supplied regex is run against. A pattern that survives
 * the screen above can still be slow on a long body; 4KB of body is far more
 * than any of the task's requests carry, and bounding the subject bounds the
 * blow-up along with it.
 */
export const REGEX_SUBJECT_MAX = 4096;

/** A user regex is bounded in length and shape; the compile itself is guarded. */
function safeRegex(pattern: string, ctx: EvalContext): RegExp | null {
  if (pattern.length > REGEX_MAX) {
    ctx.note(`RegexString이 상한 ${REGEX_MAX}자를 초과 — 평가 불가`);
    return null;
  }
  if (NESTED_QUANTIFIER_RE.test(pattern)) {
    ctx.note(
      "RegexString 에 중첩 반복자(예: (a+)+)가 있어 평가하지 않음 — AWS 의 RE2 는 선형 시간에 처리하지만 " +
        "이 평가기(JavaScript)는 지수 시간이 걸려 대시보드가 멈춥니다. AWS 에서는 정상 동작할 수 있습니다: " +
        pattern,
    );
    return null;
  }
  try {
    return new RegExp(pattern);
  } catch {
    ctx.note("RegexString을 컴파일할 수 없음: " + pattern);
    return null;
  }
}

/** Runs a user regex against a subject truncated to REGEX_SUBJECT_MAX. */
function regexHits(compiled: RegExp, values: string[]): boolean {
  return values.some((v) => compiled.test(v.length > REGEX_SUBJECT_MAX ? v.slice(0, REGEX_SUBJECT_MAX) : v));
}

// --- referenced sets ---------------------------------------------------------

/**
 * A reference can be resolved from an inline list on the statement itself or
 * from the top-level "IPSets" / "RegexPatternSets" block, matched by full ARN,
 * by ARN tail, or by bare name.
 */
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
  const parts = key.split("/");
  for (let i = parts.length - 1; i >= 0; i--) {
    const hit = store.get(parts[i]!);
    if (hit) return hit;
  }
  return null;
}

/**
 * The console exports a regex pattern set three different ways depending on the
 * command used; accept all of them.
 */
function inlineRegexStrings(stmt: Rec): string[] {
  const direct = strList(stmt.RegexStrings);
  if (direct.length > 0) return direct;

  const nestedSet = asRecord(stmt.RegexPatternSet);
  if (nestedSet) {
    const nested = strList(nestedSet.RegularExpressionList);
    if (nested.length > 0) return nested;
  }

  const objects: unknown[] = [];
  if (Array.isArray(stmt.RegularExpressionList)) objects.push(...stmt.RegularExpressionList);
  if (nestedSet && Array.isArray(nestedSet.RegularExpressionList)) {
    objects.push(...nestedSet.RegularExpressionList);
  }
  const out: string[] = [];
  for (const e of objects) {
    const s = str(asRecord(e)?.RegexString);
    if (s !== null) out.push(s);
  }
  return out;
}

/** Forwarded-IP handling for IPSetReferenceStatement. */
function forwardedIp(
  req: NormalizedRequest,
  config: unknown,
): { ips: string[]; fallbackMatch: boolean } | null {
  const c = asRecord(config);
  if (!c) return null;
  const header = (str(c.HeaderName) || "x-forwarded-for").toLowerCase();
  const fallbackMatch = (str(c.FallbackBehavior) ?? "").toUpperCase() === "MATCH";
  const raw = req.headers.get(header);
  if (raw === undefined || raw.trim() === "") return { ips: [], fallbackMatch };

  let list = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
  switch ((str(c.Position) ?? "").toUpperCase()) {
    case "":
    case "FIRST":
      list = list.slice(0, 1);
      break;
    case "LAST":
      list = list.slice(-1);
      break;
  }
  return { ips: list, fallbackMatch };
}

// --- evaluator ---------------------------------------------------------------

const UNSUPPORTED_STATEMENTS = ["ASNMatchStatement"];

export function evalStatement(
  stmt: unknown,
  req: NormalizedRequest,
  ctx: EvalContext,
): Verdict3 {
  const s = asRecord(stmt);
  if (!s) return VERDICT_UNKNOWN;

  const and = asRecord(s.AndStatement);
  if (and) {
    const parts = Array.isArray(and.Statements) ? and.Statements : [];
    let sawUnknown = false;
    for (const p of parts) {
      const r = evalStatement(p, req, ctx);
      if (r === VERDICT_FALSE) return VERDICT_FALSE;
      if (r === VERDICT_UNKNOWN) sawUnknown = true;
    }
    if (sawUnknown) return VERDICT_UNKNOWN;
    return fromBool(parts.length > 0);
  }

  const or = asRecord(s.OrStatement);
  if (or) {
    const parts = Array.isArray(or.Statements) ? or.Statements : [];
    let sawUnknown = false;
    for (const p of parts) {
      const r = evalStatement(p, req, ctx);
      if (r === VERDICT_TRUE) return VERDICT_TRUE;
      if (r === VERDICT_UNKNOWN) sawUnknown = true;
    }
    return sawUnknown ? VERDICT_UNKNOWN : VERDICT_FALSE;
  }

  const not = asRecord(s.NotStatement);
  if (not) {
    const r = evalStatement(not.Statement, req, ctx);
    if (r === VERDICT_UNKNOWN) return VERDICT_UNKNOWN;
    return r === VERDICT_TRUE ? VERDICT_FALSE : VERDICT_TRUE;
  }

  const byteMatch = asRecord(s.ByteMatchStatement);
  if (byteMatch) {
    const search = str(byteMatch.SearchString);
    if (search === null) {
      ctx.note("ByteMatchStatement의 SearchString이 문자열이 아님 — 평가 불가");
      return VERDICT_UNKNOWN;
    }
    // `aws wafv2 get-web-acl` emits SearchString base64-encoded, so a pasted
    // rule may carry a blob where the author expects plain text.
    if (looksBase64Encoded(search)) {
      ctx.note(
        `SearchString "${search}"은 base64로 인코딩된 값으로 보임 (디코딩하면 "${decodeBase64Str(search)}") — 평문으로 간주해 평가했으므로 의도한 값인지 확인 필요`,
      );
    }
    const values = preparedValues(req, byteMatch, ctx, "ByteMatchStatement");
    if (values === null) return VERDICT_UNKNOWN;
    // WAF applies TextTransformations to the inspected field only — the
    // SearchString you author is compared as-is.
    const constraint = str(byteMatch.PositionalConstraint) ?? "";
    return anyOf(values, (v) => positional(v, search, constraint));
  }

  const regexMatch = asRecord(s.RegexMatchStatement);
  if (regexMatch) {
    const pattern = str(regexMatch.RegexString);
    if (pattern === null) return VERDICT_UNKNOWN;
    const compiled = safeRegex(pattern, ctx);
    if (!compiled) return VERDICT_UNKNOWN;
    const values = preparedValues(req, regexMatch, ctx, "RegexMatchStatement");
    if (values === null) return VERDICT_UNKNOWN;
    return fromBool(regexHits(compiled, values));
  }

  const regexSet = asRecord(s.RegexPatternSetReferenceStatement);
  if (regexSet) {
    const patterns = resolveSet(ctx.regexSets, str(regexSet.ARN), inlineRegexStrings(regexSet));
    if (!patterns) {
      ctx.unsup("RegexPatternSetReferenceStatement");
      ctx.note(
        '정규식 패턴 세트를 로컬에서 알 수 없음 — 붙여넣은 JSON 최상위에 "RegexPatternSets": { "<세트이름 또는 ARN>": ["정규식", …] } 을 추가하면 평가함',
      );
      return VERDICT_UNKNOWN;
    }
    const compiled: RegExp[] = [];
    for (const p of patterns) {
      const c = safeRegex(p, ctx);
      if (!c) return VERDICT_UNKNOWN;
      compiled.push(c);
    }
    const values = preparedValues(req, regexSet, ctx, "RegexPatternSetReferenceStatement");
    if (values === null) return VERDICT_UNKNOWN;
    return fromBool(compiled.some((c) => regexHits(c, values)));
  }

  const ipSet = asRecord(s.IPSetReferenceStatement);
  if (ipSet) {
    let inline = strList(ipSet.Addresses);
    if (inline.length === 0) inline = strList(asRecord(ipSet.IPSet)?.Addresses);
    const cidrs = resolveSet(ctx.ipSets, str(ipSet.ARN), inline);
    if (!cidrs) {
      ctx.unsup("IPSetReferenceStatement");
      ctx.note(
        'IP 세트 내용을 로컬에서 알 수 없음 — 붙여넣은 JSON 최상위에 "IPSets": { "<세트이름 또는 ARN>": ["10.0.0.0/8", …] } 을 추가하면 평가함',
      );
      return VERDICT_UNKNOWN;
    }
    const forwarded = forwardedIp(req, ipSet.IPSetForwardedIPConfig);
    if (forwarded) {
      if (forwarded.ips.length === 0) return fromBool(forwarded.fallbackMatch);
      return fromBool(forwarded.ips.some((ip) => cidrs.some((c) => ipInCidr(ip, c))));
    }
    return fromBool(cidrs.some((c) => ipInCidr(req.ip, c)));
  }

  const size = asRecord(s.SizeConstraintStatement);
  if (size) {
    const values = preparedValues(req, size, ctx, "SizeConstraintStatement");
    if (values === null) return VERDICT_UNKNOWN;
    const op = str(size.ComparisonOperator) ?? "";
    const limit = num(size.Size);
    // WAF measures the field in bytes, not characters.
    return anyOf(values, (v) => compare(Buffer.byteLength(v, "utf8"), op, limit));
  }

  const geo = asRecord(s.GeoMatchStatement);
  if (geo) {
    const codes = strList(geo.CountryCodes);
    if (codes.length === 0) {
      ctx.note("GeoMatchStatement에 CountryCodes가 없음 — 평가 불가");
      return VERDICT_UNKNOWN;
    }
    const country = req.country.toUpperCase();
    return fromBool(codes.some((c) => c.toUpperCase() === country));
  }

  const sqli = asRecord(s.SqliMatchStatement);
  if (sqli) {
    const values = preparedValues(req, sqli, ctx, "SqliMatchStatement");
    if (values === null) return VERDICT_UNKNOWN;
    ctx.approx("SqliMatchStatement");
    ctx.note("SqliMatchStatement는 AWS 내부 토크나이저 대신 로컬 시그니처로 근사 평가 — 실제 WAF 판정과 다를 수 있음");
    const level = readSensitivity(sqli.SensitivityLevel);
    return fromBool(values.some((v) => looksLikeSqli(v, level)));
  }

  const xss = asRecord(s.XssMatchStatement);
  if (xss) {
    const values = preparedValues(req, xss, ctx, "XssMatchStatement");
    if (values === null) return VERDICT_UNKNOWN;
    ctx.approx("XssMatchStatement");
    ctx.note("XssMatchStatement는 AWS 내부 토크나이저 대신 로컬 시그니처로 근사 평가 — 실제 WAF 판정과 다를 수 있음");
    return fromBool(values.some((v) => looksLikeXss(v, SENSITIVITY_HIGH)));
  }

  const label = asRecord(s.LabelMatchStatement);
  if (label) {
    const key = str(label.Key);
    if (key === null) return VERDICT_UNKNOWN;
    const scope = (str(label.Scope) ?? "").toUpperCase() || "LABEL";
    const all = new Set([...req.labels, ...ctx.emitted]);
    if (all.size === 0) {
      ctx.note(
        `라벨 "${key}"를 붙이는 선행 규칙이 없음 — 미매칭으로 평가함(요청 행의 라벨란에 직접 넣으면 매칭 검증 가능)`,
      );
      return VERDICT_FALSE;
    }
    const needle = key.toLowerCase();
    for (const l of all) {
      const have = l.toLowerCase();
      if (scope === "NAMESPACE" ? have.startsWith(needle) : have === needle) return VERDICT_TRUE;
    }
    return VERDICT_FALSE;
  }

  const rate = asRecord(s.RateBasedStatement);
  if (rate) {
    ctx.approx("RateBasedStatement");
    const limit = num(rate.Limit);
    const window = num(rate.EvaluationWindowSec) || 300;
    ctx.note(
      `RateBasedStatement는 요청량(${limit > 0 ? limit : "?"}건/${window}초)이 조건 — 합성 요청 한 건으로는 재현할 수 없어 스코프다운 조건만 평가함. 매칭으로 표시된 행은 "해당 키가 임계치를 넘겼을 때 걸린다"는 뜻.`,
    );
    if (!("ScopeDownStatement" in rate)) return VERDICT_TRUE;
    return evalStatement(rate.ScopeDownStatement, req, ctx);
  }

  const managed = asRecord(s.ManagedRuleGroupStatement);
  if (managed) {
    const vendor = str(managed.VendorName) ?? "";
    const name = str(managed.Name) ?? "";
    if ("ScopeDownStatement" in managed) {
      const scope = evalStatement(managed.ScopeDownStatement, req, ctx);
      if (scope !== VERDICT_TRUE) return scope;
    }
    const excluded = new Set<string>();
    if (Array.isArray(managed.ExcludedRules)) {
      for (const e of managed.ExcludedRules) {
        const n = str(asRecord(e)?.Name);
        if (n !== null) excluded.add(n);
      }
    }
    // A rule overridden to Count still matches; only Allow removes it from the
    // group's blocking behaviour.
    if (Array.isArray(managed.RuleActionOverrides)) {
      for (const e of managed.RuleActionOverrides) {
        const o = asRecord(e);
        if (!o) continue;
        const action = asRecord(o.ActionToUse);
        if (action && "Allow" in action) {
          const n = str(o.Name);
          if (n !== null) excluded.add(n);
        }
      }
    }
    const verdict = evaluateManagedGroup(vendor, name, req, excluded);
    if (verdict.matched === VERDICT_UNKNOWN) {
      ctx.unsup(`ManagedRuleGroupStatement(${name})`);
      if (verdict.note !== "") ctx.note(verdict.note);
      return VERDICT_UNKNOWN;
    }
    ctx.approx(`ManagedRuleGroupStatement(${name})`);
    ctx.note(`관리형 규칙 그룹 "${name}"은 공개된 규칙 의도를 로컬 근사로 평가 — 실제 매칭 여부는 COUNT로 확인 필요`);
    if (verdict.matched === VERDICT_TRUE) {
      for (const l of verdict.labels) ctx.emitted.add(l);
      ctx.note(`"${name}" 근사 매칭: ${verdict.rules.join(", ")}`);
    }
    return verdict.matched;
  }

  const groupRef = asRecord(s.RuleGroupReferenceStatement);
  if (groupRef) {
    if (!Array.isArray(groupRef.Rules)) {
      ctx.unsup("RuleGroupReferenceStatement");
      ctx.note('사용자 규칙 그룹의 내용을 로컬에서 알 수 없음 — 문장 안에 "Rules": [ … ] 로 규칙 배열을 넣으면 평가함');
      return VERDICT_UNKNOWN;
    }
    if ("ScopeDownStatement" in groupRef) {
      const scope = evalStatement(groupRef.ScopeDownStatement, req, ctx);
      if (scope !== VERDICT_TRUE) return scope;
    }
    ctx.approx("RuleGroupReferenceStatement");
    let sawUnknown = false;
    for (const r of groupRef.Rules) {
      const v = evalStatement(asRecord(r)?.Statement, req, ctx);
      if (v === VERDICT_TRUE) return VERDICT_TRUE;
      if (v === VERDICT_UNKNOWN) sawUnknown = true;
    }
    return sawUnknown ? VERDICT_UNKNOWN : VERDICT_FALSE;
  }

  for (const name of UNSUPPORTED_STATEMENTS) {
    if (name in s) {
      ctx.unsup(name);
      ctx.note(name + "은 AWS 측 데이터가 있어야 판정 가능 — 로컬 평가 불가");
      return VERDICT_UNKNOWN;
    }
  }

  ctx.unsup(Object.keys(s)[0] ?? "(empty)");
  return VERDICT_UNKNOWN;
}
