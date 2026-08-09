import "server-only";
import type { FingerprintEntry } from "@/lib/types";

const ERROR_LINE =
  /(error|fatal|exception|panic|fail(ed|ure)?|timeout|timed out|refused|oom|out of memory|too many connections|deadlock|5\d{2}\s)/i;

const NORMALIZERS: { re: RegExp; sub: string }[] = [
  // ISO / RFC3339 timestamps (incl. log-prefix timestamps)
  { re: /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/g, sub: "<TS>" },
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

export function normalizeLine(line: string): string {
  // Strip kubectl-style leading timestamp before normalizing.
  let out = line.replace(/^\S+\s/, (m) => (/\d{4}-\d{2}-\d{2}T/.test(m) ? "" : m));
  for (const n of NORMALIZERS) out = out.replace(n.re, n.sub);
  return out.trim().slice(0, 300);
}

export function extractTimestamp(line: string): string | null {
  const m = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)/);
  return m?.[1] ?? null;
}

// Group equivalent error lines into fingerprints (spec §14).
export function aggregateFingerprints(
  podLines: { pod: string; lines: string[] }[],
): FingerprintEntry[] {
  const map = new Map<
    string,
    { count: number; pods: Set<string>; firstSeen: string; lastSeen: string; sample: string }
  >();
  for (const { pod, lines } of podLines) {
    for (const line of lines) {
      if (!ERROR_LINE.test(line)) continue;
      const fp = normalizeLine(line);
      if (fp.length < 5) continue;
      const ts = extractTimestamp(line) ?? "";
      const entry = map.get(fp);
      if (entry) {
        entry.count += 1;
        entry.pods.add(pod);
        if (ts && (entry.lastSeen === "" || ts > entry.lastSeen)) entry.lastSeen = ts;
        if (ts && (entry.firstSeen === "" || ts < entry.firstSeen)) entry.firstSeen = ts;
      } else {
        map.set(fp, {
          count: 1,
          pods: new Set([pod]),
          firstSeen: ts,
          lastSeen: ts,
          sample: line.slice(0, 300),
        });
      }
    }
  }
  return [...map.entries()]
    .map(([fingerprint, v]) => ({
      fingerprint,
      count: v.count,
      pods: [...v.pods],
      firstSeen: v.firstSeen,
      lastSeen: v.lastSeen,
      sample: v.sample,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);
}
