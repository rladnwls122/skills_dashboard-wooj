import "server-only";

// WAFv2 TextTransformations, implemented locally. Every type AWS accepts is
// handled except MD5, whose output is raw binary that no pasted SearchString
// can express — that one is reported by name so the operator sees *which*
// transform stopped the evaluation instead of a blanket "unsupported".

export type TransformResult = { ok: true; value: string } | { ok: false; type: string };

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
    .replace(/&#(\d+);?/g, (m, d: string) => codePoint(Number(d)) ?? m)
    .replace(/&#x([0-9a-f]+);?/gi, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m);
}

function codePoint(n: number): string | null {
  if (!Number.isFinite(n) || n < 0 || n > 0x10ffff) return null;
  try {
    return String.fromCodePoint(n);
  } catch {
    return null;
  }
}

function urlDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    // A malformed percent-escape decodes to itself in WAF; keep the raw value.
    return s;
  }
}

function urlDecodeUni(s: string): string {
  return urlDecode(s).replace(/%u([0-9a-f]{4})/gi, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m);
}

function normalizePath(s: string): string {
  const segs: string[] = [];
  for (const seg of s.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") segs.pop();
    else segs.push(seg);
  }
  const trailing = s.length > 1 && s.endsWith("/") ? "/" : "";
  return `/${segs.join("/")}${segs.length > 0 ? trailing : ""}`;
}

function looksBase64(s: string): boolean {
  const t = s.replace(/[\r\n]/g, "");
  return t.length > 0 && t.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(t);
}

function base64Decode(s: string, lenient: boolean): string {
  const t = lenient ? s.replace(/[^A-Za-z0-9+/=]/g, "") : s.replace(/[\r\n]/g, "");
  if (!lenient && !looksBase64(t)) return s; // WAF leaves an undecodable value alone
  if (lenient && t.length === 0) return s;
  try {
    return Buffer.from(t, "base64").toString("utf8");
  } catch {
    return s;
  }
}

function hexDecode(s: string): string {
  const t = s.trim();
  if (t.length === 0 || t.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(t)) return s;
  try {
    return Buffer.from(t, "hex").toString("utf8");
  } catch {
    return s;
  }
}

// SQL hex literals: 0x646f67 -> dog
function sqlHexDecode(s: string): string {
  return s.replace(/\b0x((?:[0-9a-fA-F]{2})+)\b/g, (m, h: string) => {
    try {
      return Buffer.from(h, "hex").toString("utf8");
    } catch {
      return m;
    }
  });
}

const ESCAPE_CHARS: Record<string, string> = {
  a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v",
  "\\": "\\", "?": "?", "'": "'", '"': '"',
};

function escapeSeqDecode(s: string): string {
  return s
    .replace(/\\u([0-9a-fA-F]{4})/g, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m)
    .replace(/\\x([0-9a-fA-F]{2})/g, (m, h: string) => codePoint(Number.parseInt(h, 16)) ?? m)
    .replace(/\\([0-7]{1,3})/g, (m, o: string) => codePoint(Number.parseInt(o, 8)) ?? m)
    .replace(/\\([abfnrtv\\?'"])/g, (m, c: string) => ESCAPE_CHARS[c] ?? m);
}

// CSS escapes: \3c -> "<", "\<newline>" is a line continuation, "\x" -> "x".
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
    .replace(/\\([bfnrtv0'"\\/])/g, (m, c: string) => (c === "0" ? "\0" : (ESCAPE_CHARS[c] ?? c)));
}

function utf8ToUnicode(s: string): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    out += cp > 0x7f ? `%u${cp.toString(16).padStart(4, "0")}` : ch;
  }
  return out;
}

function cmdLine(s: string): string {
  // AWS CMD_LINE: drop \ " ' ^, collapse whitespace to one space, lowercase.
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
      return value.replace(/\0/g, "");
    case "REPLACE_NULLS":
      return value.replace(/\0/g, " ");
    case "URL_DECODE":
      return urlDecode(value);
    case "URL_DECODE_UNI":
      return urlDecodeUni(value);
    case "HTML_ENTITY_DECODE":
      return htmlEntityDecode(value);
    case "BASE64_DECODE":
      return base64Decode(value, false);
    case "BASE64_DECODE_EXT":
      return base64Decode(value, true);
    case "HEX_DECODE":
      return hexDecode(value);
    case "SQL_HEX_DECODE":
      return sqlHexDecode(value);
    case "REPLACE_COMMENTS":
      return value.replace(/\/\*[\s\S]*?(?:\*\/|$)/g, " ");
    case "ESCAPE_SEQ_DECODE":
      return escapeSeqDecode(value);
    case "CSS_DECODE":
      return cssDecode(value);
    case "JS_DECODE":
      return jsDecode(value);
    case "UTF8_TO_UNICODE":
      return utf8ToUnicode(value);
    case "NORMALIZE_PATH":
      return normalizePath(value);
    case "NORMALIZE_PATH_WIN":
      return normalizePath(value.replace(/\\/g, "/"));
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
    .map((t) => (typeof t === "object" && t !== null ? (t as Record<string, unknown>) : null))
    .filter((t): t is Record<string, unknown> => t !== null)
    .sort((a, b) => Number(a["Priority"] ?? 0) - Number(b["Priority"] ?? 0));

  let out = value;
  for (const t of ordered) {
    const type = typeof t["Type"] === "string" ? (t["Type"] as string) : "";
    const next = transformOne(out, type);
    if (next === null) return { ok: false, type: type.length > 0 ? type : "(이름 없는 변환)" };
    out = next;
  }
  return { ok: true, value: out };
}
