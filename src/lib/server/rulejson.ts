import "server-only";

// A tolerant reader for what an operator actually has on the clipboard.
// Copying two rules out of the WAF console and pasting them one after the other
// produces "}{" — not valid JSON, but an entirely reasonable thing to paste
// into a rule sandbox. This module accepts that, plus the other shapes that
// show up around hand-edited rule JSON:
//
//   {…}{…}          two top-level values back to back
//   {…}, {…}        the same, separated by a comma
//   // … , /* … */  comments left in by hand
//   {"a": 1,}       a trailing comma
//
// Everything is string-aware: a "//" inside "http://x" or a brace inside a
// SearchString never confuses the scanner.

interface Cursor {
  text: string;
  i: number;
}

// Advances past a JSON string literal that starts at cur.i (on the quote).
// Returns false when the literal never closes.
function skipString(cur: Cursor): boolean {
  cur.i += 1;
  while (cur.i < cur.text.length) {
    const ch = cur.text[cur.i];
    if (ch === "\\") {
      cur.i += 2;
      continue;
    }
    cur.i += 1;
    if (ch === '"') return true;
  }
  return false;
}

// Removes // and /* */ comments and trailing commas. Returns the cleaned text.
function sanitize(text: string): string {
  const out: string[] = [];
  const cur: Cursor = { text, i: 0 };

  const dropTrailingComma = (): void => {
    let j = out.length - 1;
    while (j >= 0 && /\s/.test(out[j] ?? "")) j -= 1;
    if (j >= 0 && out[j] === ",") out.splice(j, 1);
  };

  while (cur.i < text.length) {
    const ch = text[cur.i] ?? "";
    if (ch === '"') {
      const start = cur.i;
      if (!skipString(cur)) {
        // Unterminated: hand the rest to JSON.parse so it reports the error.
        out.push(text.slice(start));
        break;
      }
      out.push(text.slice(start, cur.i));
      continue;
    }
    if (ch === "/" && text[cur.i + 1] === "/") {
      while (cur.i < text.length && text[cur.i] !== "\n") cur.i += 1;
      continue;
    }
    if (ch === "/" && text[cur.i + 1] === "*") {
      const end = text.indexOf("*/", cur.i + 2);
      cur.i = end < 0 ? text.length : end + 2;
      continue;
    }
    if (ch === "}" || ch === "]") dropTrailingComma();
    out.push(ch);
    cur.i += 1;
  }
  return out.join("");
}

// Splits sanitized text into the source of each top-level object/array.
function splitTopLevelValues(text: string): string[] {
  const values: string[] = [];
  const cur: Cursor = { text, i: 0 };

  while (cur.i < text.length) {
    const ch = text[cur.i] ?? "";
    // Between values only whitespace and separating commas are allowed.
    if (/\s/.test(ch) || ch === ",") {
      cur.i += 1;
      continue;
    }
    if (ch !== "{" && ch !== "[") {
      throw new Error(
        `규칙 JSON을 읽을 수 없음 — ${cur.i + 1}번째 문자에서 "{" 또는 "["를 기대했는데 "${ch}"가 나옴`,
      );
    }

    const start = cur.i;
    let depth = 0;
    let closed = false;
    while (cur.i < text.length) {
      const c = text[cur.i] ?? "";
      if (c === '"') {
        if (!skipString(cur)) {
          throw new Error("규칙 JSON을 읽을 수 없음 — 닫히지 않은 문자열이 있음");
        }
        continue;
      }
      if (c === "{" || c === "[") depth += 1;
      if (c === "}" || c === "]") depth -= 1;
      cur.i += 1;
      if (depth === 0) {
        closed = true;
        break;
      }
    }
    if (!closed) {
      throw new Error("규칙 JSON을 읽을 수 없음 — 괄호가 닫히지 않음");
    }
    values.push(text.slice(start, cur.i));
  }
  return values;
}

// Parses one or more JSON documents out of a single pasted blob.
export function parseJsonDocuments(text: string): unknown[] {
  const trimmed = text.trim();
  if (trimmed.length === 0) throw new Error("규칙 JSON이 비어 있음");

  // The common case — one well-formed document — never goes near the scanner.
  try {
    return [JSON.parse(trimmed)];
  } catch {
    // fall through to the tolerant path
  }

  const sources = splitTopLevelValues(sanitize(trimmed));
  if (sources.length === 0) throw new Error("규칙 JSON에서 읽을 수 있는 값을 찾지 못함");

  return sources.map((src, i) => {
    try {
      return JSON.parse(src);
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e);
      throw new Error(
        sources.length === 1
          ? `규칙 JSON 파싱 실패: ${detail}`
          : `${i + 1}번째 JSON 블록 파싱 실패: ${detail}`,
      );
    }
  });
}
