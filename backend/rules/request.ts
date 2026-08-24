// The local WAFv2 rule engine's request model. Pure and AWS-free: it evaluates a
// pasted rule against synthetic requests. Nothing here makes a network call.

import { isIPv4, isIPv6 } from "node:net";

import type { TestRequest } from "../../src/lib/types.ts";

/**
 * The synthetic request in the shape the WAFv2 evaluator inspects it. Everything
 * a FieldToMatch can point at is resolved here once per request — an absent
 * header is a real "no match", not an "unknown".
 */
export interface NormalizedRequest {
  method: string;
  path: string;
  /** Without the leading "?". */
  query: string;
  body: string;
  ip: string;
  country: string;
  /** Lower-cased header name -> value, in declaration order. */
  headers: Map<string, string>;
  /** Cookie name -> value, parsed from the Cookie header. */
  cookies: Map<string, string>;
  /** Query arguments in order; names lower-cased, values percent-decoded. */
  args: Arg[];
  /** Labels visible to this rule (set by the operator or by earlier rules). */
  labels: Set<string>;
}

export interface Arg {
  name: string;
  value: string;
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
    if (t === "") continue;
    const eq = t.indexOf("=");
    if (eq < 0) out.set(t, "");
    else out.set(t.slice(0, eq).trim(), t.slice(eq + 1).trim());
  }
  return out;
}

export function parseQueryArgs(query: string): Arg[] {
  const out: Arg[] = [];
  for (const part of query.replace(/^\?/, "").split("&")) {
    if (part === "") continue;
    const eq = part.indexOf("=");
    const name = eq >= 0 ? part.slice(0, eq) : part;
    const value = eq >= 0 ? part.slice(eq + 1) : "";
    out.push({ name: decodeArg(name).toLowerCase(), value: decodeArg(value) });
  }
  return out;
}

export function normalizeRequest(req: TestRequest): NormalizedRequest {
  const headers = new Map<string, string>();
  // The UA has its own column in the sandbox table, so it is authoritative; an
  // empty value means the request carries no User-Agent header at all, which is
  // exactly what AWS's NoUserAgent_HEADER rule looks for.
  if (req.userAgent) headers.set("user-agent", req.userAgent);
  for (const [name, value] of Object.entries(req.headers ?? {})) {
    const key = name.trim().toLowerCase();
    if (key === "" || (key === "user-agent" && req.userAgent)) continue;
    headers.set(key, value);
  }

  return {
    method: (req.method ?? "").toUpperCase(),
    path: req.path ?? "",
    query: (req.query ?? "").replace(/^\?/, ""),
    body: req.body ?? "",
    ip: req.ip ?? "",
    country: req.country ?? "",
    headers,
    cookies: parseCookies(headers.get("cookie") ?? ""),
    args: parseQueryArgs(req.query ?? ""),
    labels: new Set(req.labels ?? []),
  };
}

// --- IP / CIDR ---------------------------------------------------------------

function ipv4ToBytes(ip: string): number[] | null {
  if (!isIPv4(ip)) return null;
  return ip.split(".").map(Number);
}

function ipv6ToBytes(ip: string): number[] | null {
  if (!isIPv6(ip)) return null;
  // Expand "::" and any embedded IPv4 tail into 8 groups of 16 bits.
  let text = ip;
  const v4 = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  if (v4) {
    const quad = ipv4ToBytes(v4[1]!);
    if (!quad) return null;
    const hi = ((quad[0]! << 8) | quad[1]!).toString(16);
    const lo = ((quad[2]! << 8) | quad[3]!).toString(16);
    text = text.slice(0, v4.index) + hi + ":" + lo;
  }
  const [head, tail] = text.split("::");
  const headParts = head === "" ? [] : head!.split(":").filter((p) => p !== "");
  const tailParts = tail === undefined || tail === "" ? [] : tail.split(":").filter((p) => p !== "");
  const fill = 8 - headParts.length - tailParts.length;
  if (fill < 0 || (tail === undefined && fill !== 0)) return null;
  const groups = [...headParts, ...Array<string>(fill).fill("0"), ...tailParts];
  const bytes: number[] = [];
  for (const g of groups) {
    const n = Number.parseInt(g, 16);
    if (!Number.isFinite(n)) return null;
    bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  return bytes;
}

function toBytes(ip: string): number[] | null {
  return ipv4ToBytes(ip) ?? ipv6ToBytes(ip);
}

/**
 * Accepts "10.0.0.0/8", "2001:db8::/32" and bare addresses (treated as /32 or
 * /128). A v4 CIDR never contains a v6 address and vice versa.
 */
export function ipInCidr(ip: string, cidr: string): boolean {
  const addr = toBytes(ip.trim());
  if (!addr) return false;

  let c = cidr.trim();
  if (!c.includes("/")) c += c.includes(":") ? "/128" : "/32";
  const slash = c.lastIndexOf("/");
  const network = toBytes(c.slice(0, slash));
  const prefix = Number.parseInt(c.slice(slash + 1), 10);
  if (!network || !Number.isFinite(prefix)) return false;
  if (network.length !== addr.length) return false;
  if (prefix < 0 || prefix > network.length * 8) return false;

  const fullBytes = prefix >> 3;
  for (let i = 0; i < fullBytes; i++) {
    if (network[i] !== addr[i]) return false;
  }
  const rest = prefix & 7;
  if (rest === 0) return true;
  const mask = 0xff << (8 - rest);
  return (network[fullBytes]! & mask) === (addr[fullBytes]! & mask);
}

const PRIVATE_RANGES = [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
  "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
];

/**
 * Private / link-local / CGNAT space never appears on an AWS reputation list,
 * which lets the managed-group approximation answer "no match" instead of
 * "cannot tell" for internal traffic.
 */
export function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some((r) => ipInCidr(ip, r));
}
