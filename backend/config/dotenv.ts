// Reads a .env file into the process environment.
//
// The dashboard is started by hand on a venue machine, often by double-clicking
// or by a one-line `npm start` — there is no launcher (mise, direnv, dotenv-cli)
// to populate the environment first, and a missing AWS_REGION shows up much
// later as an empty panel. So the process loads its own .env.
//
// Two rules keep this predictable:
//   * A variable already present in the real environment always wins. Exporting
//     a value, or `API_ADDR=… npm start`, overrides the file without editing it.
//   * A missing file is not an error. Every value here has a default or lives
//     in the settings table.
//
// Go's backend/internal/config/dotenv.go parses the same grammar; keep the two
// in step.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** One key/value pair as written in the file. */
export type EnvPairs = Record<string, string>;

/** Where a .env was found, and what it contributed. */
export interface DotenvResult {
  /** Absolute path of the file that was read, or null if none existed. */
  path: string | null;
  /** Keys taken from the file (those not already set in the environment). */
  applied: string[];
  /** Keys present in the file but skipped because the environment had them. */
  skipped: string[];
}

/**
 * Candidate paths, in order. The first that exists wins.
 *
 * ENV_FILE is the explicit escape hatch (two instances, two configs). The
 * working directory is the normal case. The directory holding this source tree
 * covers `npm start` run from somewhere else — a shortcut's "start in" field on
 * Windows is a common way to get a surprising cwd.
 */
function candidates(explicit?: string): string[] {
  const list: string[] = [];
  const fromEnv = (explicit ?? process.env.ENV_FILE ?? "").trim();
  if (fromEnv !== "") list.push(resolve(fromEnv));
  list.push(resolve(process.cwd(), ".env"));
  // backend/config/dotenv.ts -> repository root.
  list.push(resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", ".env"));
  return [...new Set(list)];
}

/**
 * Parses .env text. Supports `KEY=value`, an optional `export ` prefix, `#`
 * comments, single-quoted (literal) and double-quoted (escapes) values, and
 * trailing comments after an unquoted value. Malformed lines are skipped rather
 * than thrown: a stray line in a config file must not stop the dashboard from
 * booting mid-exercise.
 */
export function parseEnv(text: string): EnvPairs {
  const out: EnvPairs = {};
  // A leading BOM would otherwise become part of the first key — Windows
  // editors add one, and the resulting "﻿AWS_REGION" silently reads empty.
  for (const raw of text.replace(/^﻿/, "").split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;

    const body = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const eq = body.indexOf("=");
    if (eq <= 0) continue;

    const key = body.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;

    out[key] = parseValue(body.slice(eq + 1).trim());
  }
  return out;
}

function parseValue(raw: string): string {
  if (raw.startsWith("'") && raw.length > 1) {
    const end = raw.indexOf("'", 1);
    // Single quotes are literal: no escapes, no interpolation.
    return end < 0 ? raw.slice(1) : raw.slice(1, end);
  }
  if (raw.startsWith('"') && raw.length > 1) {
    const end = findClosingDouble(raw);
    const inner = end < 0 ? raw.slice(1) : raw.slice(1, end);
    return inner.replace(/\\(.)/g, (_, c: string) =>
      c === "n" ? "\n" : c === "r" ? "\r" : c === "t" ? "\t" : c,
    );
  }
  // Unquoted: a ` #` starts a trailing comment. A bare `#` inside a token (a
  // URL fragment, a password) is kept. A value that starts where a comment
  // would is an empty value with a note after it: `KEY=  # note`.
  if (raw.startsWith("#")) return "";
  const comment = raw.search(/\s#/);
  return (comment < 0 ? raw : raw.slice(0, comment)).trim();
}

/** Index of the closing double quote, skipping escaped ones. */
function findClosingDouble(raw: string): number {
  for (let i = 1; i < raw.length; i++) {
    if (raw[i] === "\\") {
      i++;
      continue;
    }
    if (raw[i] === '"') return i;
  }
  return -1;
}

/**
 * Loads the first .env found into process.env without overwriting anything the
 * environment already provides. Safe to call more than once (the launcher and
 * the backend both do, in different processes).
 */
export function loadDotenv(explicitPath?: string): DotenvResult {
  for (const path of candidates(explicitPath)) {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      continue; // Absent, or unreadable — try the next candidate.
    }

    const applied: string[] = [];
    const skipped: string[] = [];
    for (const [key, value] of Object.entries(parseEnv(text))) {
      // An empty value in .env means "unset" — the file ships with blank AWS
      // keys as documentation, and turning those into empty strings would
      // shadow the credentials the settings screen injects later.
      if (value === "") continue;
      if (process.env[key] !== undefined && process.env[key] !== "") {
        skipped.push(key);
        continue;
      }
      process.env[key] = value;
      applied.push(key);
    }
    return { path, applied, skipped };
  }
  return { path: null, applied: [], skipped: [] };
}
