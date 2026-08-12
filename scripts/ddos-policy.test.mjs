// Locks in the competition directive: request volume against the served API
// surface is never a finding, traffic aimed outside it still is, and no
// rate-based (volumetric) WAF rule can be recommended.
import { readFile } from "node:fs/promises";

const SRC = new URL("../src/lib/server/", import.meta.url).href;
const {
  isAppTrafficPath,
  APP_TRAFFIC_PATHS,
  isPathSuspicious,
  isIpConcentrated,
  isLowPriorityPath,
} = await import(`${SRC}config.ts`);
const { detectAnomalies } = await import(`${SRC}anomaly.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

console.log("APP_TRAFFIC_PATHS =", APP_TRAFFIC_PATHS.join(", "), "\n");

for (const p of ["/v1/user", "/v1/product", "/v1/stress", "/v1/image", "/v1/user/42", "/v1/image?id=3"]) {
  check(`isAppTrafficPath("${p}")`, isAppTrafficPath(p), true);
}
for (const p of ["/admin.php", "/v1", "/v1/userx", "/.env", "/wp-login.php"]) {
  check(`isAppTrafficPath("${p}")`, isAppTrafficPath(p), false);
}

// A served-path prefix must not launder a traversal into "ordinary app
// traffic" — the path is resolved before the prefix test, the way WAF's
// NORMALIZE_PATH does it.
for (const p of ["/v1/image/../../etc/passwd", "/v1/user/../../../admin", "/v1/./../admin"]) {
  check(`traversal escapes the served surface: ${p}`, isAppTrafficPath(p), false);
}
check("a plain served path still matches", isAppTrafficPath("/v1/image/logo.png"), true);
check("health check with a dot segment is still a health check", isLowPriorityPath("/health/./x"), true);

// The single suspicious-path rule both UI tabs and the anomaly detector share.
check("off-surface + concentrated is suspicious", isPathSuspicious("/wp-login.php", 990, 1000), true);
check("served path is never suspicious", isPathSuspicious("/v1/user", 990, 1000), false);
check("health check is never suspicious", isPathSuspicious("/healthcheck", 990, 1000), false);
check("off-surface below share is not suspicious", isPathSuspicious("/.env", 40, 1000), false);
check("off-surface below count is not suspicious", isPathSuspicious("/x", 20, 30), false);
check("concentrated IP", isIpConcentrated(400, 1000), true);
check("low-share IP is not concentrated", isIpConcentrated(200, 1000), false);
check("low-count IP is not concentrated", isIpConcentrated(19, 20), false);

const summary = (byPath, byUa) => ({
  totalSampled: 1000,
  windowLabel: "15m",
  source: "test",
  byPath,
  byIp: [{ key: "203.0.113.7", count: 990 }],
  byUa,
  byMethod: [],
  queryPatterns: [],
  headerPatterns: [],
  statusDist: null,
  detailedStatus: null,
});
const input = (httpSummary) => ({ metrics: [], httpSummary, pods: [], events: [], fingerprints: [] });
const traffic = (as) => as.filter((a) => a.type === "TRAFFIC_ANOMALY_SUSPECTED");

// A realistic metrics snapshot where every tracked metric is quiet (NORMAL),
// matching the MetricSummary shape detectAnomalies reads (status plus the
// fields the spike messages format). Using this instead of `metrics: []`
// closes a gap where an absent metric (`undefined`) reads as "not NORMAL"
// and inflates spikeSignals, silently corroborating an otherwise-isolated
// finding.
const normalMetric = (key, current) => ({
  key,
  label: key,
  unit: "",
  current,
  previous: current,
  delta: 0,
  percentChange: 0,
  status: "NORMAL",
  points: [],
});
const normalMetrics = [
  normalMetric("targetResponseTime", 0.2),
  normalMetric("http4xx", 5),
  normalMetric("http5xx", 0),
  normalMetric("wafBlocked", 0),
  normalMetric("rdsClientConnections", 5),
];
const inputQuiet = (httpSummary) => ({
  metrics: normalMetrics,
  httpSummary,
  pods: [],
  events: [],
  fingerprints: [],
});

const loadGen = detectAnomalies(
  input(summary(
    [{ path: "/v1/user", count: 990, blocked: 0, lowPriority: false }],
    [{ key: "Go-http-client/2.0", count: 990 }],
  )),
);
check("load generator on /v1/user raises no traffic anomaly", traffic(loadGen).length, 0);

const scan = detectAnomalies(
  input(summary(
    [{ path: "/wp-login.php", count: 990, blocked: 0, lowPriority: false }],
    [{ key: "Go-http-client/2.0", count: 990 }],
  )),
);
check("off-surface scan still raises a traffic anomaly", traffic(scan).length, 1);
check(
  "off-surface finding cites no source IP",
  traffic(scan)[0]?.evidence.some((e) => e.includes("203.0.113.7")) ?? true,
  false,
);

const mixed = detectAnomalies(
  input(summary(
    [
      { path: "/v1/product", count: 960, blocked: 0, lowPriority: false },
      { path: "/.env", count: 40, blocked: 0, lowPriority: false },
    ],
    [{ key: "Mozilla/5.0", count: 800 }],
  )),
);
check("small probe under threshold stays quiet", traffic(mixed).length, 0);

const wafSrc = await readFile(new URL(`${SRC}waf.ts`), "utf8");
const genBody = wafSrc.slice(
  wafSrc.indexOf("export async function generateRecommendations"),
  wafSrc.indexOf("function hash(s: string)"),
);
check("generateRecommendations builds no RateBasedStatement", genBody.includes("RateBasedStatement:"), false);
check("generateRecommendations emits no RATE_BASED kind", genBody.includes('kind: "RATE_BASED"'), false);

const incSrc = await readFile(new URL(`${SRC}incident.ts`), "utf8");
check("buildSnapshot blanks byIp", incSrc.includes("byIp: []"), true);

// New malicious-client detection must not disturb the volumetric policy:
// Go-http-client is bypassed, so the load generator and the off-surface scan
// (both Go UA) keep their existing anomaly counts.
const malicious = (as) => as.filter((a) => a.type === "MALICIOUS_CLIENT_SUSPECTED");
check("Go load generator raises no malicious-client anomaly", malicious(loadGen).length, 0);
check("Go off-surface scan raises no malicious-client anomaly", malicious(scan).length, 0);
check("Mozilla traffic raises no malicious-client anomaly", malicious(mixed).length, 0);

// A named scanner tool in the UA mix does raise one, citing the tool, never an
// IP — and using inputQuiet (realistic all-NORMAL metrics, not the empty-array
// fixture) proves the severity isn't riding on an accidental spikeSignals
// inflation: a lone scanner signature must be CRITICAL even with every other
// metric quiet.
const scanner = detectAnomalies(
  inputQuiet(summary(
    [{ path: "/v1/user", count: 500, blocked: 0, lowPriority: false }],
    [{ key: "sqlmap/1.7", count: 60 }],
  )),
);
check("scanner UA raises a malicious-client anomaly", malicious(scanner).length, 1);
check(
  "malicious-client finding cites no source IP",
  malicious(scanner)[0]?.evidence.some((e) => e.includes("203.0.113.7")) ?? true,
  false,
);
check(
  "malicious-client finding names the tool",
  malicious(scanner)[0]?.evidence.some((e) => e.toLowerCase().includes("sqlmap")) ?? false,
  true,
);
check(
  "scanner signature is guaranteed CRITICAL even with all other metrics NORMAL",
  malicious(scanner)[0]?.severity,
  "CRITICAL",
);

// A spoofed-but-not-scanner UA (malformed Mozilla, no named tool) is a softer
// signal — it stays WARNING even under the same quiet-metrics conditions.
const spoofed = detectAnomalies(
  inputQuiet(summary(
    [{ path: "/v1/user", count: 500, blocked: 0, lowPriority: false }],
    [{ key: "Mozilla/5.0 (asdfghjklqwertyuiopzxcvbnm)", count: 60 }],
  )),
);
check("spoofed-only UA raises a malicious-client anomaly", malicious(spoofed).length, 1);
check(
  "spoofed-only finding cites no source IP",
  malicious(spoofed)[0]?.evidence.some((e) => e.includes("203.0.113.7")) ?? true,
  false,
);
check("spoofed-only (no scanner/recon) severity stays WARNING", malicious(spoofed)[0]?.severity, "WARNING");

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
