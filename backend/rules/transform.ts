// WAFv2 TextTransformations. Every type AWS accepts is handled except MD5, whose
// output is raw binary no pasted SearchString can express — that one is reported
// by name.

// NORMALIZE_PATH is not implemented here. The assembler builds its path patterns
// with config/paths.ts and this simulator evaluates them, so a second copy of
// that normalisation is a copy that can drift — and it had: this file kept the
// trailing slash while config/paths.ts dropped it, meaning the two halves of the
// same screen could describe different strings. One definition, imported.
import { normalizePathSegments } from "../config/paths.ts";

export interface TransformResult {
  ok: boolean;
  value: string;
  /** The transform that stopped evaluation, when !ok. */
  type: string;
}

const HTML_ENTITIES: Record<string, string> = {
  "&lt;": "<",
  "&gt;": ">",
  "&amp;": "&",
  "&quot;": '"',
  "&apos;": "'",
  "&nbsp;": " ",
};

function codePoint(n: number): string | null {
  if (!Number.isFinite(n) || n < 0 || n > 0x10ffff) return null;
  try {
    return String.fromCodePoint(n);
  } catch {
    return null;
  }
}

function htmlEntityDecode(s: string): string {
  return s
    .replace(/&(?:lt|gt|amp|quot|apos|nbsp);/gi, (m) => HTML_ENTITIES[m.toLowerCase()] ?? m)
    .replace(/&#([0-9]+);?/g, (m, d: string) => codePoint(Number.parseInt(d, 10)) ?? m)
    .replace(/&#x([0-9a-f]+);?/gi, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m);
}

function urlDecode(s: string): string {
  // A malformed percent-escape decodes to itself in WAF; keep the raw value.
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

function urlDecodeUni(s: string): string {
  return urlDecode(s).replace(
    /%u([0-9a-f]{4})/gi,
    (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m,
  );
}

const B64_STRICT_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function base64DecodeTransform(s: string, lenient: boolean): string {
  let t: string;
  if (lenient) {
    t = s.replace(/[^A-Za-z0-9+/=]/g, "");
    if (t === "") return s;
  } else {
    t = s.replace(/[\r\n]/g, "");
    // WAF leaves an undecodable value alone.
    if (t === "" || t.length % 4 !== 0 || !B64_STRICT_RE.test(t)) return s;
  }
  try {
    return Buffer.from(t.replace(/=+$/, ""), "base64").toString("utf8");
  } catch {
    return s;
  }
}

function hexDecodeTransform(s: string): string {
  const t = s.trim();
  if (t === "" || t.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(t)) return s;
  return Buffer.from(t, "hex").toString("utf8");
}

/** SQL hex literals: 0x646f67 -> dog */
function sqlHexDecode(s: string): string {
  return s.replace(/\b0x((?:[0-9a-fA-F]{2})+)\b/g, (m, h: string) =>
    Buffer.from(h, "hex").toString("utf8") || m,
  );
}

const ESCAPE_CHARS: Record<string, string> = {
  a: "\x07",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
  "\\": "\\",
  "?": "?",
  "'": "'",
  '"': '"',
};

function escapeSeqDecode(s: string): string {
  return s
    .replace(/\\u([0-9a-fA-F]{4})/g, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m)
    .replace(/\\x([0-9a-fA-F]{2})/g, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m)
    .replace(/\\([0-7]{1,3})/g, (m, o: string) => codePoint(Number.parseInt(o, 8)) ?? m)
    .replace(/\\([abfnrtv\\?'"])/g, (m, c: string) => ESCAPE_CHARS[c] ?? m);
}

/** CSS escapes: \3c -> "<", "\<newline>" is a line continuation, "\x" -> "x". */
function cssDecode(s: string): string {
  return s
    .replace(/\\\r?\n/g, "")
    .replace(/\\([0-9a-fA-F]{1,6})[ \t]?/g, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m)
    .replace(/\\([^\r\n])/g, "$1");
}

function jsDecode(s: string): string {
  return s
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m)
    .replace(/\\u([0-9a-fA-F]{4})/g, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m)
    .replace(/\\x([0-9a-fA-F]{2})/g, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m)
    .replace(/\\([0-7]{1,3})/g, (m, o: string) => codePoint(Number.parseInt(o, 8)) ?? m)
    .replace(/\\([bfnrtv0'"\\/])/g, (_m, c: string) =>
      c === "0" ? "\x00" : (ESCAPE_CHARS[c] ?? c),
    );
}

function utf8ToUnicode(s: string): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp > 0x7f) out += "%u" + cp.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out;
}

/** AWS CMD_LINE: drop \ " ' ^, collapse whitespace to one space, lowercase. */
function cmdLine(s: string): string {
  return s
    .replace(/[\\"'^]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function transformOne(value: string, type: string): string | null {
  switch (type) {
    case "NONE":
      return value;
    case "LOWERCASE":
      return value.toLowerCase();
    case "TRIM":
      return value.trim();
    case "COMPRESS_WHITE_SPACE":
      return value.replace(/\s+/g, " ");
    case "REMOVE_NULLS":
      return value.replaceAll("\x00", "");
    case "REPLACE_NULLS":
      return value.replaceAll("\x00", " ");
    case "URL_DECODE":
      return urlDecode(value);
    case "URL_DECODE_UNI":
      return urlDecodeUni(value);
    case "HTML_ENTITY_DECODE":
      return htmlEntityDecode(value);
    case "BASE64_DECODE":
      return base64DecodeTransform(value, false);
    case "BASE64_DECODE_EXT":
      return base64DecodeTransform(value, true);
    case "HEX_DECODE":
      return hexDecodeTransform(value);
    case "SQL_HEX_DECODE":
      return sqlHexDecode(value);
    case "REPLACE_COMMENTS":
      return value.replace(/\/\*[\s\S]*?(\*\/|$)/g, " ");
    case "ESCAPE_SEQ_DECODE":
      return escapeSeqDecode(value);
    case "CSS_DECODE":
      return cssDecode(value);
    case "JS_DECODE":
      return jsDecode(value);
    case "UTF8_TO_UNICODE":
      return utf8ToUnicode(value);
    case "NORMALIZE_PATH":
      return normalizePathSegments(value);
    case "NORMALIZE_PATH_WIN":
      return normalizePathSegments(value.replaceAll("\\", "/"));
    case "CMD_LINE":
      return cmdLine(value);
    default:
      // MD5 lands here on purpose: its output is binary, so no pasted
      // SearchString could be compared against it honestly.
      return null;
  }
}

export function applyTransforms(value: string, transforms: unknown): TransformResult {
  const list = Array.isArray(transforms) ? transforms : [];
  const ordered = list
    .filter((t): t is Record<string, unknown> => t !== null && typeof t === "object")
    .map((t) => ({
      priority: typeof t.Priority === "number" ? t.Priority : 0,
      type: typeof t.Type === "string" ? t.Type : "",
    }));
  // Array#sort is stable, so equal priorities keep their declared order.
  ordered.sort((a, b) => a.priority - b.priority);

  let out = value;
  for (const t of ordered) {
    const next = transformOne(out, t.type);
    if (next === null) {
      return { ok: false, value: "", type: t.type || "(이름 없는 변환)" };
    }
    out = next;
  }
  return { ok: true, value: out, type: "" };
}
