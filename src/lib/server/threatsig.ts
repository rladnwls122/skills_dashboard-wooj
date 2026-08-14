import "server-only";

// Threat classification for a synthetic or sampled request's User-Agent and
// query. Pure and AWS-free so it is shared by anomaly detection, the WAF
// recommender, and the rule sandbox, and unit-tested without a cloud call.
// UNKNOWN is not a signature — it is the absence of one. A named tool, an
// injection payload and "a client nobody recognises" are three different
// findings and the rule text has to say which it is.
export type ThreatCategory = "SCANNER" | "RECON" | "SPOOFED" | "AUTOMATION" | "UNKNOWN";

// Go's default HTTP client is the competition's load generator and the expected
// AI-agent traffic (REQ-01): always allowed, unless an explicit tool signature
// below fires first.
const GO_ALLOW_RE = /go-http-client\/|go-language/i;

// Named offensive tools. A hit is an unambiguous attack signature — this is the
// one category the runbook promotes straight to BLOCK without a COUNT pass, so
// every token here has to be a string no legitimate client sends.
//
// Sourced from the public scanner/offensive-tool UA lists (digininja's
// scanner_user_agents, mthcht's suspicious_http_user_agents_list) plus each
// tool's own default UA, then filtered twice:
//
//   - Web-facing only. Those lists are largely Windows/AD/C2 tooling (rubeus,
//     certipy, evilginx, empire…), which cannot arrive as a User-Agent at an
//     HTTP API behind this WAF. Carrying them would only make the classifier
//     longer to read without changing a single verdict.
//   - No generic bad-bot lists. The 1,200-entry spam-crawler blocklists are a
//     different problem (scraping, ad fraud) and they carry ambiguous strings
//     that a real client can hold — a false block costs availability score,
//     which is the one thing this environment cannot spend.
//
// The emitted rule is built from the UAs actually observed, not from this list
// (see ruleassemble.uaPatternsFor), so length here costs no WCU — what it buys
// is the difference between "SCANNER: nuclei", which the runbook promotes
// straight to BLOCK, and "UNKNOWN: nuclei", which has to go through COUNT.
//
// Anything not listed still surfaces: unrecognised clients classify as UNKNOWN
// by the allow-list check below. Naming a tool changes what the operator can do
// about it, not whether they see it.
const SCANNER_TOOLS = [
  // SQL / injection
  "sqlmap", "ghauri", "sqlninja", "nosqlmap", "commix", "tplmap",
  // XSS
  "xsstrike", "dalfox", "xsser",
  // Web vulnerability scanners
  "nikto", "acunetix", "netsparker", "invicti", "arachni", "w3af", "wapiti",
  "skipfish", "whatweb", "nuclei", "vega", "webinspect", "appscan", "qualys",
  "nessus", "openvas", "greenbone", "detectify", "probely", "burpcollaborator",
  // Content discovery / fuzzing. ffuf's default UA is the phrase, not "ffuf".
  "dirbuster", "dirb", "dirsearch", "gobuster", "feroxbuster", "ffuf",
  "fuzz faster u fool", "wfuzz", "crlfuzz",
  // CMS-specific
  "wpscan", "joomscan", "droopescan", "cmseek",
  // Proxies / frameworks whose UA means someone is testing, not browsing
  "zaproxy", "zap", "burpsuite", "burp", "metasploit", "havij",
  // Credential brute-force
  "hydra", "medusa", "patator",
];

// Internet-wide scanners and OSINT crawlers. Not an attack on their own —
// somebody else's census hitting everything with a public IP — but on a
// competition surface they are still traffic nobody asked for, and they arrive
// before the targeted attempts do.
const RECON_TOOLS = [
  "nmap", "masscan", "zgrab", "zmap", "censysinspect", "shodan",
  "internetmeasurement", "netsystemsresearch", "criminalip", "leakix",
  "l9explore", "l9tcpid", "expanse", "researchscan",
  "projectdiscovery", "interactsh", "katana", "gospider", "hakrawler",
];

// HTTP clients and headless browsers. None of these is an attack by itself —
// they are how scripted traffic identifies itself, which is exactly why an
// attacker who does not bother to forge a UA arrives wearing one. Kept separate
// from SCANNER so the rule can say "automation, not a named weapon".
const AUTOMATION_TOOLS = [
  "curl", "wget", "python-requests", "python-urllib", "urllib", "libwww-perl",
  "okhttp", "apache-httpclient", "java", "axios", "node-fetch", "got", "httpie",
  "postmanruntime", "insomnia", "scrapy", "phantomjs", "headlesschrome",
  "puppeteer", "playwright", "selenium", "httpclient", "restsharp", "guzzle",
  "winhttp", "powershell", "lwp-request", "aiohttp", "httpx", "reqwest",
  // An intercepting proxy in the path means someone is inspecting or replaying
  // traffic. Not an attack signature on its own, which is why it sits here and
  // not in SCANNER_TOOLS.
  "mitmproxy",
];

const AUTOMATION_RE = new RegExp(`(^|[^a-z])(${AUTOMATION_TOOLS.join("|")})([^a-z]|$)`, "i");

// Clients this environment is expected to see. Everything else observed is
// suspicious by default — see classifyUa.
//
// The inversion matters. A deny list only catches attackers who announce
// themselves, and the ones worth catching do not: "Mozilla/5.0 (compatible)"
// costs an attacker nothing and passes every signature above. The traffic here
// is narrow enough to enumerate — the load generator, real browsers, and AWS's
// own probes — so the honest test is "is this one of those", not "is this one
// of the tools I happened to list".
const KNOWN_GOOD_UA = [
  // A real browser always names a rendering engine. isMalformedMozilla exists
  // because "Mozilla/5.0" alone does not.
  /(applewebkit|gecko|trident|khtml|presto)\b/i,
  // The competition's load generator and expected AI-agent traffic (REQ-01).
  /go-http-client\/|go-language/i,
  // AWS infrastructure probes.
  /^elb-healthchecker\//i,
  /^amazon-route53-health-check-service/i,
  /^amazon cloudfront/i,
  /^kube-probe\//i,
  // This dashboard's own traffic check (server/probe.ts) — it is deliberately
  // named so it can be told apart, and it must not end up in a rule that then
  // blocks the next check.
  /^skills-dashboard\/traffic-check/i,
];

export function isKnownGoodUa(ua: string): boolean {
  return KNOWN_GOOD_UA.some((re) => re.test(ua));
}

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

// What a classification looks like as a WAF regex, for the SPOOFED categories
// whose label is a category name rather than text found in the UA. A rule built
// by treating "injection-in-ua" as a literal would match nothing at all, so
// anything turning a classification into a rule must come through here.
//
// RE2 syntax, lowercase only: the rules that use these apply LOWERCASE (and
// COMPRESS_WHITE_SPACE) before matching, so an uppercase letter here could
// never fire and \s+ is already collapsed to single spaces.
const SPOOFED_PATTERNS: Record<string, string[]> = {
  "injection-in-ua": [
    "\\$\\{jndi:",
    "union\\s+select",
    "['\"]\\s*or\\s+1\\s*=\\s*1",
    ";\\s*(cat|wget|curl|nc|bash|sh)\\b",
  ],
  // Base64 folds to lowercase under the transform, so the class is a-z0-9+/.
  "base64-ua": ["(^|[^a-z0-9+/])[a-z0-9+/]{24,}={0,2}([^a-z0-9+/=]|$)"],
  // RE2 has no lookahead, so "starts like a browser but names no engine" can't
  // be written directly. This takes the other half of the signal — the long
  // unbroken letter run right after the mozilla token — which real browser UAs
  // never have (their next token is "windows", "macintosh", "x11"…).
  "malformed-mozilla": ["^mozilla/[0-9.]+\\s*\\(?[a-z]{20,}"],
};

// The regexes that express a classification. SCANNER and RECON labels are the
// tool name as it appears in the UA, so the caller can use the label itself as
// a literal; SPOOFED labels need these instead. Returns [] when the label is
// unknown.
export function spoofedUaPatterns(label: string): string[] {
  return SPOOFED_PATTERNS[label] ?? [];
}

// The leading product token of a UA — "python-requests" out of
// "python-requests/2.31.0", "sqlmap" out of "sqlmap/1.7#stable". It is what an
// unrecognised client can be matched on: the version that follows changes
// between releases, so a rule written against the whole string stops firing the
// day the attacker upgrades.
export function uaToken(ua: string): string {
  const first = ua.trim().split(/[\s/(;,]/)[0] ?? "";
  return first.toLowerCase();
}

export function classifyUa(ua: string): { category: ThreatCategory; label: string } | null {
  const scan = SCANNER_RE.exec(ua);
  if (scan) return { category: "SCANNER", label: (scan[2] ?? "scanner").toLowerCase() };
  const recon = RECON_RE.exec(ua);
  if (recon) return { category: "RECON", label: (recon[2] ?? "recon").toLowerCase() };
  // Payload-in-the-UA outranks the allow list: a request carrying ${jndi: is an
  // attack no matter what it claims to be, and a forged browser token is the
  // usual wrapper for one.
  if (UA_INJECTION_RE.test(ua)) return { category: "SPOOFED", label: "injection-in-ua" };
  // The Go bypass applies only after explicit attack signatures are ruled out.
  if (GO_ALLOW_RE.test(ua)) return null;
  if (isMalformedMozilla(ua)) return { category: "SPOOFED", label: "malformed-mozilla" };
  if (hasBase64Blob(ua)) return { category: "SPOOFED", label: "base64-ua" };

  const auto = AUTOMATION_RE.exec(ua);
  if (auto) return { category: "AUTOMATION", label: (auto[2] ?? "automation").toLowerCase() };

  // Nothing recognised it and it is not one of the clients this environment
  // expects, so it is reported rather than passed. An empty UA lands here too —
  // a request that declines to identify itself is the plainest case of this.
  if (isKnownGoodUa(ua)) return null;
  const token = uaToken(ua);
  return { category: "UNKNOWN", label: token || "(빈 User-Agent)" };
}

export function queryHasBase64Blob(query: string): boolean {
  return hasBase64Blob(query);
}
