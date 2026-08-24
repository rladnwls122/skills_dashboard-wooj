// Threat classification for a synthetic or sampled request's User-Agent and
// query. Pure and AWS-free so it is shared by anomaly detection, the WAF
// recommender, and the rule sandbox. UNKNOWN is not a signature — it is the
// absence of one.

export const CATEGORY_SCANNER = "SCANNER";
export const CATEGORY_RECON = "RECON";
export const CATEGORY_SPOOFED = "SPOOFED";
export const CATEGORY_AUTOMATION = "AUTOMATION";
export const CATEGORY_UNKNOWN = "UNKNOWN";

export type ThreatCategory =
  | typeof CATEGORY_SCANNER
  | typeof CATEGORY_RECON
  | typeof CATEGORY_SPOOFED
  | typeof CATEGORY_AUTOMATION
  | typeof CATEGORY_UNKNOWN;

export interface ThreatHit {
  category: ThreatCategory;
  label: string;
}

// Go's default HTTP client is the competition's load generator and the expected
// AI-agent traffic (REQ-01): always allowed, unless an explicit tool signature
// below fires first.
const GO_ALLOW_RE = /go-http-client\/|go-language/i;

// Named offensive tools. A hit is an unambiguous attack signature.
// "attacker-bot" is the User-Agent the product binary itself treats as an
// attack (it answers 500 "Consumed resources by malicious attacks") — the
// task's abnormal-request probe, which the WAF has to turn into a 403.
const SCANNER_TOOLS = [
  "sqlmap", "nikto", "acunetix", "dirbuster", "dirb", "w3af", "netsparker",
  "zaproxy", "gobuster", "wpscan", "arachni", "nessus", "openvas", "commix",
  "attacker-bot",
];
const RECON_TOOLS = ["nmap", "masscan", "zgrab", "censysinspect", "zmap"];

// HTTP clients and headless browsers. None of these is an attack by itself —
// kept separate from SCANNER so the rule can say "automation, not a named
// weapon".
const AUTOMATION_TOOLS = [
  "curl", "wget", "python-requests", "python-urllib", "urllib", "libwww-perl",
  "okhttp", "apache-httpclient", "java", "axios", "node-fetch", "got", "httpie",
  "postmanruntime", "insomnia", "scrapy", "phantomjs", "headlesschrome",
  "puppeteer", "playwright", "selenium", "httpclient", "restsharp", "guzzle",
  "winhttp", "powershell", "lwp-request", "aiohttp", "httpx", "reqwest",
];

function toolRe(tools: string[]): RegExp {
  return new RegExp(`(^|[^a-z])(${tools.join("|")})([^a-z]|$)`, "i");
}

const SCANNER_RE = toolRe(SCANNER_TOOLS);
const RECON_RE = toolRe(RECON_TOOLS);
const AUTOMATION_RE = toolRe(AUTOMATION_TOOLS);

// Clients this environment is expected to see. Everything else observed is
// suspicious by default — see classifyUa.
const KNOWN_GOOD_UA = [
  // A real browser always names a rendering engine.
  /(applewebkit|gecko|trident|khtml|presto)\b/i,
  // The competition's load generator and expected AI-agent traffic (REQ-01).
  /go-http-client\/|go-language/i,
  // AWS infrastructure probes.
  /^elb-healthchecker\//i,
  /^amazon-route53-health-check-service/i,
  /^amazon cloudfront/i,
  /^kube-probe\//i,
  // This dashboard's own traffic check — deliberately named so it can be told
  // apart, and it must not end up in a rule that blocks the next check.
  /^skills-dashboard\/traffic-check/i,
];

export function isKnownGoodUa(ua: string): boolean {
  return KNOWN_GOOD_UA.some((re) => re.test(ua));
}

// Injection payloads smuggled into the UA field (Log4Shell, SQLi, OS command).
const UA_INJECTION_RE =
  /(\$\{jndi:|\bunion\s+select\b|['"]\s*or\s+1\s*=\s*1|;\s*(cat|wget|curl|nc|bash|sh)\b)/i;

// A standalone base64 blob long enough to hide a payload.
const B64_BLOB_RE = /(^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})($|[^A-Za-z0-9+/=])/;

function hasBase64Blob(s: string): boolean {
  const m = B64_BLOB_RE.exec(s);
  if (!m) return false;
  const blob = m[2]!;
  return blob.length >= 24 && blob.length % 4 === 0;
}

const MOZILLA_START_RE = /^mozilla\/\d/i;
const ENGINE_RE = /(applewebkit|gecko|trident|khtml|presto|chrome|firefox|safari|edg|opr)\b/i;
const LONG_LETTERS_RE = /[a-z]{20,}/i;

/**
 * Starts like a browser but names no rendering engine and carries a long
 * unbroken letter run no real token has — reads as filler.
 */
function isMalformedMozilla(ua: string): boolean {
  return MOZILLA_START_RE.test(ua) && !ENGINE_RE.test(ua) && LONG_LETTERS_RE.test(ua);
}

// What a classification looks like as a WAF regex, for the SPOOFED categories
// whose label is a category name rather than text found in the UA.
// RE2 syntax, lowercase only: the rules that use these apply LOWERCASE (and
// COMPRESS_WHITE_SPACE) before matching.
const SPOOFED_PATTERNS: Record<string, string[]> = {
  "injection-in-ua": [
    `\\$\\{jndi:`,
    `union\\s+select`,
    `['"]\\s*or\\s+1\\s*=\\s*1`,
    `;\\s*(cat|wget|curl|nc|bash|sh)\\b`,
  ],
  // Base64 folds to lowercase under the transform, so the class is a-z0-9+/.
  "base64-ua": [`(^|[^a-z0-9+/])[a-z0-9+/]{24,}={0,2}([^a-z0-9+/=]|$)`],
  // RE2 has no lookahead, so this takes the other half of the signal — the long
  // unbroken letter run right after the mozilla token.
  "malformed-mozilla": [`^mozilla/[0-9.]+\\s*\\(?[a-z]{20,}`],
};

/**
 * The regexes that express a classification; [] when the label is unknown.
 */
export function spoofedUaPatterns(label: string): string[] {
  return SPOOFED_PATTERNS[label] ?? [];
}

const UA_TOKEN_SPLIT_RE = /[\s/(;,]/;

/**
 * The leading product token of a UA — "python-requests" out of
 * "python-requests/2.31.0". The version that follows changes between releases,
 * so a rule written against the whole string stops firing on upgrade.
 */
export function uaToken(ua: string): string {
  return ua.trim().split(UA_TOKEN_SPLIT_RE, 1)[0]!.toLowerCase();
}

export function classifyUa(ua: string): ThreatHit | null {
  const scanner = SCANNER_RE.exec(ua);
  if (scanner) return { category: CATEGORY_SCANNER, label: scanner[2]!.toLowerCase() };

  const recon = RECON_RE.exec(ua);
  if (recon) return { category: CATEGORY_RECON, label: recon[2]!.toLowerCase() };

  // Payload-in-the-UA outranks the allow list: a request carrying ${jndi: is an
  // attack no matter what it claims to be.
  if (UA_INJECTION_RE.test(ua)) return { category: CATEGORY_SPOOFED, label: "injection-in-ua" };

  // The Go bypass applies only after explicit attack signatures are ruled out.
  if (GO_ALLOW_RE.test(ua)) return null;

  if (isMalformedMozilla(ua)) return { category: CATEGORY_SPOOFED, label: "malformed-mozilla" };
  if (hasBase64Blob(ua)) return { category: CATEGORY_SPOOFED, label: "base64-ua" };

  const automation = AUTOMATION_RE.exec(ua);
  if (automation) return { category: CATEGORY_AUTOMATION, label: automation[2]!.toLowerCase() };

  // Nothing recognised it and it is not one of the clients this environment
  // expects, so it is reported rather than passed. An empty UA lands here too.
  if (isKnownGoodUa(ua)) return null;
  return { category: CATEGORY_UNKNOWN, label: uaToken(ua) || "(빈 User-Agent)" };
}

export function queryHasBase64Blob(query: string): boolean {
  return hasBase64Blob(query);
}
