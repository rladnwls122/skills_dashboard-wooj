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
      case "BASE64_DECODE":
        try {
          out = Buffer.from(out, "base64").toString("utf8");
        } catch {
          // WAF leaves an undecodable value unchanged.
        }
        break;
      case "REMOVE_NULLS":
        // Strip NUL bytes.
        out = out.replace(/\x00/g, "");
        break;
      case "NORMALIZE_PATH": {
        // Collapse repeated slashes and resolve ./ and ../ segments.
        const segs: string[] = [];
        for (const seg of out.split("/")) {
          if (seg === "" || seg === ".") continue;
          if (seg === "..") segs.pop();
          else segs.push(seg);
        }
        out = `/${segs.join("/")}`;
        break;
      }
      case "CMD_LINE":
        // AWS CMD_LINE: drop \ " ' ^, collapse whitespace to one space, lowercase.
        out = out
          .replace(/[\\"'^]/g, "")
          .replace(/\s+/g, " ")
          .trim()
          .toLowerCase();
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
    // WAF applies TextTransformations to the inspected field only — the
    // SearchString you author is compared as-is.
    return positional(value, search, str(byte["PositionalConstraint"]));
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

  const geo = asRecord(s["GeoMatchStatement"]);
  if (geo) {
    const raw = Array.isArray(geo["CountryCodes"]) ? geo["CountryCodes"] : [];
    const codes = raw.map((c) => str(c)).filter((c): c is string => c !== null);
    if (codes.length === 0) {
      ctx.notes.add("GeoMatchStatement에 CountryCodes가 없음 — 평가 불가");
      return "UNKNOWN";
    }
    return codes.map((c) => c.toUpperCase()).includes(req.country.toUpperCase());
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
