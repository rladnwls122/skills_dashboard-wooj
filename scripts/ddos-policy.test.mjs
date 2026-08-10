// Locks in the competition directive: request volume against the served API
// surface is never a finding, traffic aimed outside it still is, and no
// rate-based (volumetric) WAF rule can be recommended.
import { readFile } from "node:fs/promises";

const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { isAppTrafficPath, APP_TRAFFIC_PATHS } = await import(`${SRC}config.ts`);
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

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
