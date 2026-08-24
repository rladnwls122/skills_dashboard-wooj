// A tolerant reader for what an operator actually has on the clipboard. Accepts
// "}{" back-to-back documents, // and /* */ comments, and trailing commas —
// everything string-aware.

interface Cursor {
  text: string;
  i: number;
}

/**
 * Advances past a JSON string literal starting at cur.i (on the quote). Returns
 * false when the literal never closes.
 */
function skipString(cur: Cursor): boolean {
  cur.i++;
  while (cur.i < cur.text.length) {
    const ch = cur.text[cur.i]!;
    if (ch === "\\") {
      cur.i += 2;
      continue;
    }
    cur.i++;
    if (ch === '"') return true;
  }
  return false;
}

const isSpace = (ch: string): boolean => /^\s$/.test(ch);

/** Removes // and /* *\/ comments and trailing commas. */
function sanitize(text: string): string {
  const out: string[] = [];
  const cur: Cursor = { text, i: 0 };

  const dropTrailingComma = (): void => {
    let j = out.length - 1;
    while (j >= 0 && isSpace(out[j]!)) j--;
    if (j >= 0 && out[j] === ",") out.splice(j, 1);
  };

  while (cur.i < cur.text.length) {
    const ch = cur.text[cur.i]!;
    if (ch === '"') {
      const start = cur.i;
      if (!skipString(cur)) {
        // Unterminated: hand the rest to JSON.parse so it reports it.
        out.push(cur.text.slice(start));
        break;
      }
      out.push(cur.text.slice(start, cur.i));
      continue;
    }
    if (ch === "/" && cur.text[cur.i + 1] === "/") {
      while (cur.i < cur.text.length && cur.text[cur.i] !== "\n") cur.i++;
      continue;
    }
    if (ch === "/" && cur.text[cur.i + 1] === "*") {
      const end = cur.text.indexOf("*/", cur.i + 2);
      cur.i = end < 0 ? cur.text.length : end + 2;
      continue;
    }
    if (ch === "}" || ch === "]") dropTrailingComma();
    out.push(ch);
    cur.i++;
  }
  return out.join("");
}

/** Splits sanitized text into the source of each top-level object/array. */
function splitTopLevelValues(text: string): string[] {
  const values: string[] = [];
  const cur: Cursor = { text, i: 0 };

  while (cur.i < cur.text.length) {
    const ch = cur.text[cur.i]!;
    // Between values only whitespace and separating commas are allowed.
    if (isSpace(ch) || ch === ",") {
      cur.i++;
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
    while (cur.i < cur.text.length) {
      const c = cur.text[cur.i]!;
      if (c === '"') {
        if (!skipString(cur)) throw new Error("규칙 JSON을 읽을 수 없음 — 닫히지 않은 문자열이 있음");
        continue;
      }
      if (c === "{" || c === "[") depth++;
      if (c === "}" || c === "]") depth--;
      cur.i++;
      if (depth === 0) {
        closed = true;
        break;
      }
    }
    if (!closed) throw new Error("규칙 JSON을 읽을 수 없음 — 괄호가 닫히지 않음");
    values.push(cur.text.slice(start, cur.i));
  }
  return values;
}

/** Parses one or more JSON documents out of a single pasted blob. */
export function parseJsonDocuments(text: string): unknown[] {
  const trimmed = text.trim();
  if (trimmed === "") throw new Error("규칙 JSON이 비어 있음");

  // The common case — one well-formed document — never goes near the scanner.
  try {
    return [JSON.parse(trimmed)];
  } catch {
    // Fall through to the tolerant path.
  }

  const sources = splitTopLevelValues(sanitize(trimmed));
  if (sources.length === 0) throw new Error("규칙 JSON에서 읽을 수 있는 값을 찾지 못함");

  return sources.map((src, i) => {
    try {
      return JSON.parse(src) as unknown;
    } catch (e) {
      const detail = (e as Error).message;
      if (sources.length === 1) throw new Error(`규칙 JSON 파싱 실패: ${detail}`);
      throw new Error(`${i + 1}번째 JSON 블록 파싱 실패: ${detail}`);
    }
  });
}
