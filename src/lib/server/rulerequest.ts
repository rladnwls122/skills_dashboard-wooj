import "server-only";
import type { TestRequest } from "@/lib/types";

// The synthetic request in the shape the WAFv2 evaluator inspects it: header
// map, parsed cookies, parsed query arguments, body and labels. Everything a
// FieldToMatch can point at is resolved here once per request so the matchers
// stay simple and every field is *modelled* — an absent header is a real
// "no match", not an "unknown".

export interface NormalizedRequest {
  method: string;
  path: string;
  // query string without the leading "?"
  query: string;
  body: string;
  ip: string;
  country: string;
  // lower-cased header name -> value, in declaration order
  headers: Map<string, string>;
  // cookie name -> value, parsed from the Cookie header
  cookies: Map<string, string>;
  // query arguments in order; names lower-cased, values percent-decoded
  args: Array<{ name: string; value: string }>;
  // labels visible to this rule (set by the operator or by earlier rules)
  labels: Set<string>;
}

function decodeArg(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

function parseCookies(header: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of header.split(";")) {
    const t = part.trim();
    if (t.length === 0) continue;
    const eq = t.indexOf("=");
    if (eq < 0) out.set(t, "");
    else out.set(t.slice(0, eq).trim(), t.slice(eq + 1).trim());
  }
  return out;
}

export function parseQueryArgs(query: string): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  for (const part of query.replace(/^\?/, "").split("&")) {
    if (part.length === 0) continue;
    const eq = part.indexOf("=");
    const name = eq < 0 ? part : part.slice(0, eq);
    const value = eq < 0 ? "" : part.slice(eq + 1);
    out.push({ name: decodeArg(name).toLowerCase(), value: decodeArg(value) });
  }
  return out;
}

// Extra headers are authored as "Name: value" lines in the sandbox UI.
export function parseHeaderLines(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (t.length === 0) continue;
    const colon = t.indexOf(":");
    if (colon <= 0) continue;
    out[t.slice(0, colon).trim()] = t.slice(colon + 1).trim();
  }
  return out;
}

export function normalizeRequest(req: TestRequest, extraLabels?: Iterable<string>): NormalizedRequest {
  const headers = new Map<string, string>();
  // The UA has its own column in the sandbox table, so it is authoritative;
  // an empty value means the request carries no User-Agent header at all,
  // which is exactly what AWS's NoUserAgent_HEADER rule looks for.
  if (req.userAgent.length > 0) headers.set("user-agent", req.userAgent);
  for (const [name, value] of Object.entries(req.headers ?? {})) {
    const key = name.trim().toLowerCase();
    if (key.length === 0) continue;
    if (key === "user-agent" && req.userAgent.length > 0) continue;
    headers.set(key, value);
  }

  const labels = new Set<string>(req.labels ?? []);
  for (const l of extraLabels ?? []) labels.add(l);

  return {
    method: req.method.toUpperCase(),
    path: req.path,
    query: req.query.replace(/^\?/, ""),
    body: req.body ?? "",
    ip: req.ip,
    country: req.country,
    headers,
    cookies: parseCookies(headers.get("cookie") ?? ""),
    args: parseQueryArgs(req.query),
    labels,
  };
}

// --- IP / CIDR ---------------------------------------------------------------

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out = out * 256 + n;
  }
  return out >>> 0;
}

// Returns the 16 address bytes, or null when the literal is not a v6 address.
function ipv6ToBytes(ip: string): Uint8Array | null {
  const zone = ip.indexOf("%");
  const addr = zone < 0 ? ip : ip.slice(0, zone);
  if (!addr.includes(":")) return null;
  const halves = addr.split("::");
  if (halves.length > 2) return null;

  const expand = (chunk: string): number[] | null => {
    if (chunk.length === 0) return [];
    const out: number[] = [];
    const groups = chunk.split(":");
    for (let i = 0; i < groups.length; i += 1) {
      const g = groups[i] ?? "";
      // A trailing IPv4 literal ("::ffff:10.0.0.1") occupies two groups.
      if (g.includes(".")) {
        if (i !== groups.length - 1) return null;
        const v4 = ipv4ToInt(g);
        if (v4 === null) return null;
        out.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  };

  const head = expand(halves[0] ?? "");
  const tail = halves.length === 2 ? expand(halves[1] ?? "") : [];
  if (head === null || tail === null) return null;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 0 : fill !== 0) return null;
  const words = [...head, ...Array.from({ length: halves.length === 2 ? fill : 0 }, () => 0), ...tail];
  if (words.length !== 8) return null;

  const bytes = new Uint8Array(16);
  words.forEach((w, i) => {
    bytes[i * 2] = (w >> 8) & 0xff;
    bytes[i * 2 + 1] = w & 0xff;
  });
  return bytes;
}

// Accepts "10.0.0.0/8", "2001:db8::/32" and bare addresses (treated as /32,/128).
export function ipInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf("/");
  const net = slash < 0 ? cidr.trim() : cidr.slice(0, slash).trim();
  const bitsRaw = slash < 0 ? null : Number(cidr.slice(slash + 1));

  const a4 = ipv4ToInt(ip.trim());
  const n4 = ipv4ToInt(net);
  if (a4 !== null && n4 !== null) {
    const bits = bitsRaw ?? 32;
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
    return ((a4 & mask) >>> 0) === ((n4 & mask) >>> 0);
  }

  const a6 = ipv6ToBytes(ip.trim());
  const n6 = ipv6ToBytes(net);
  if (a6 !== null && n6 !== null) {
    const bits = bitsRaw ?? 128;
    if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
    for (let i = 0; i < 16; i += 1) {
      const remaining = bits - i * 8;
      if (remaining <= 0) break;
      const mask = remaining >= 8 ? 0xff : (0xff << (8 - remaining)) & 0xff;
      if (((a6[i] ?? 0) & mask) !== ((n6[i] ?? 0) & mask)) return false;
    }
    return true;
  }
  return false;
}

const PRIVATE_RANGES = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "100.64.0.0/10",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
];

// Private / link-local / CGNAT space never appears on an AWS reputation list,
// which lets the managed-group approximation answer "no match" instead of
// "cannot tell" for internal traffic.
export function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some((r) => ipInCidr(ip, r));
}
