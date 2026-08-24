// Error-line fingerprinting (spec §14).

import type { FingerprintEntry } from "../../src/lib/types.ts";

// "malicious" is the product binary's trap line for User-Agent Attacker-Bot;
// "[Recovery]" is gin's panic handler; "5xx |" is the access line of a failed
// request. See docs/binaries.md for every message the binaries can print.
const ERROR_LINE_RE =
  /(error|fatal|exception|panic|fail(ed|ure)?|timeout|timed out|refused|oom|out of memory|too many connections|deadlock|malicious|\[recovery\]|\|\s*5\d{2}\s*\||5\d{2}\s)/i;

const NORMALIZERS: { re: RegExp; sub: string }[] = [
  // ISO / RFC3339 timestamps (incl. log-prefix timestamps)
  {
    re: /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/g,
    sub: "<TS>",
  },
  { re: /\d{2}:\d{2}:\d{2}(\.\d+)?/g, sub: "<TS>" },
  // UUID
  { re: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, sub: "<UUID>" },
  // Request/trace ids and long hex
  { re: /\b[0-9a-f]{16,}\b/gi, sub: "<HEX>" },
  // IPv4
  { re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b/g, sub: "<IP>" },
  // Remaining numbers
  { re: /\b\d+\b/g, sub: "<*>" },
];

const LEADING_TOKEN_RE = /^\S+\s/;
const ISO_PREFIX_RE = /\d{4}-\d{2}-\d{2}T/;
const TS_EXTRACT_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)/;

export function normalizeLine(line: string): string {
  // Strip a kubectl-style leading timestamp before normalizing.
  let out = line.replace(LEADING_TOKEN_RE, (m) => (ISO_PREFIX_RE.test(m) ? "" : m));
  for (const n of NORMALIZERS) out = out.replace(n.re, n.sub);
  return out.trim().slice(0, 300);
}

export function extractTimestamp(line: string): string {
  return TS_EXTRACT_RE.exec(line)?.[1] ?? "";
}

export interface PodLines {
  pod: string;
  lines: string[];
}

interface Acc {
  count: number;
  pods: string[];
  podSet: Set<string>;
  firstSeen: string;
  lastSeen: string;
  sample: string;
}

/** Groups equivalent error lines into fingerprints. */
export function aggregateFingerprints(podLines: PodLines[]): FingerprintEntry[] {
  // Insertion-ordered, which is what keeps the stable sort below deterministic.
  const m = new Map<string, Acc>();

  for (const pl of podLines) {
    for (const line of pl.lines) {
      if (!ERROR_LINE_RE.test(line)) continue;
      const fp = normalizeLine(line);
      if (fp.length < 5) continue;
      const ts = extractTimestamp(line);
      const entry = m.get(fp);
      if (entry) {
        entry.count++;
        if (!entry.podSet.has(pl.pod)) {
          entry.podSet.add(pl.pod);
          entry.pods.push(pl.pod);
        }
        if (ts !== "" && (entry.lastSeen === "" || ts > entry.lastSeen)) entry.lastSeen = ts;
        if (ts !== "" && (entry.firstSeen === "" || ts < entry.firstSeen)) entry.firstSeen = ts;
      } else {
        m.set(fp, {
          count: 1,
          pods: [pl.pod],
          podSet: new Set([pl.pod]),
          firstSeen: ts,
          lastSeen: ts,
          sample: line.slice(0, 300),
        });
      }
    }
  }

  const out: FingerprintEntry[] = [];
  for (const [fingerprint, v] of m) {
    out.push({
      fingerprint,
      count: v.count,
      pods: v.pods,
      firstSeen: v.firstSeen,
      lastSeen: v.lastSeen,
      sample: v.sample,
    });
  }
  // Array.prototype.sort is stable, so equal counts keep first-seen order.
  out.sort((x, y) => y.count - x.count);
  return out.slice(0, 20);
}
