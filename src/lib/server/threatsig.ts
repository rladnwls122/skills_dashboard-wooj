import "server-only";

// Threat classification for a synthetic or sampled request's User-Agent and
// query. Pure and AWS-free so it is shared by anomaly detection, the WAF
// recommender, and the rule sandbox, and unit-tested without a cloud call.
export type ThreatCategory = "SCANNER" | "RECON" | "SPOOFED";

// Go's default HTTP client is the competition's load generator and the expected
// AI-agent traffic (REQ-01): always allowed, unless an explicit tool signature
// below fires first.
const GO_ALLOW_RE = /go-http-client\/|go-language/i;

// Named offensive tools. A hit is an unambiguous attack signature.
const SCANNER_TOOLS = [
  "sqlmap", "nikto", "acunetix", "dirbuster", "dirb", "w3af", "netsparker",
  "zaproxy", "gobuster", "wpscan", "arachni", "nessus", "openvas", "commix",
];
const RECON_TOOLS = ["nmap", "masscan", "zgrab", "censysinspect", "zmap"];

// Word-ish boundary: tool names sit next to /, digits, spaces or string edges.
const SCANNER_RE = new RegExp(`(^|[^a-z])(${SCANNER_TOOLS.join("|")})([^a-z]|$)`, "i");
const RECON_RE = new RegExp(`(^|[^a-z])(${RECON_TOOLS.join("|")})([^a-z]|$)`, "i");

// Injection payloads smuggled into the UA field (Log4Shell, SQLi, OS command).
const UA_INJECTION_RE =
  /(\$\{jndi:|\bunion\s+select\b|['"]\s*or\s+1\s*=\s*1|;\s*(cat|wget|curl|nc|bash|sh)\b)/i;

// A standalone base64 blob long enough to hide a payload.
const B64_BLOB_RE = /(^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})($|[^A-Za-z0-9+/=])/;

function hasBase64Blob(s: string): boolean {
  const m = B64_BLOB_RE.exec(s);
  const blob = m?.[2] ?? "";
  return blob.length >= 24 && blob.length % 4 === 0;
}

// Starts like a browser but names no rendering engine and carries a long
// unbroken letter run no real token has — reads as filler.
function isMalformedMozilla(ua: string): boolean {
  if (!/^mozilla\/\d/i.test(ua)) return false;
  const hasEngine =
    /(applewebkit|gecko|trident|khtml|presto|chrome|firefox|safari|edg|opr)\b/i.test(ua);
  return !hasEngine && /[a-z]{20,}/i.test(ua);
}

export function classifyUa(ua: string): { category: ThreatCategory; label: string } | null {
  const scan = SCANNER_RE.exec(ua);
  if (scan) return { category: "SCANNER", label: (scan[2] ?? "scanner").toLowerCase() };
  const recon = RECON_RE.exec(ua);
  if (recon) return { category: "RECON", label: (recon[2] ?? "recon").toLowerCase() };
  // The Go bypass applies only after explicit tool signatures are ruled out.
  if (GO_ALLOW_RE.test(ua)) return null;
  if (UA_INJECTION_RE.test(ua)) return { category: "SPOOFED", label: "injection-in-ua" };
  if (isMalformedMozilla(ua)) return { category: "SPOOFED", label: "malformed-mozilla" };
  if (hasBase64Blob(ua)) return { category: "SPOOFED", label: "base64-ua" };
  return null;
}

export function queryHasBase64Blob(query: string): boolean {
  return hasBase64Blob(query);
}
