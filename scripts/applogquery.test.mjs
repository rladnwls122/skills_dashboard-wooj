const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { toSampleRow } = await import(`${SRC}waf.ts`);
const {
  buildRequestLogQuery,
  validatePathFilter,
  toRequestLogRow,
  ROW_LIMIT,
  PATH_FILTER_MAX,
} = await import(`${SRC}applogquery.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const blocked = toSampleRow({
  Timestamp: new Date("2026-08-10T03:07:12.000Z"),
  Action: "BLOCK",
  RuleNameWithinRuleGroup: "dash-ua-match",
  ResponseCodeSent: 403,
  Request: {
    ClientIP: "203.0.113.7",
    Country: "KR",
    Method: "GET",
    URI: "/wp-login.php",
    Headers: [{ Name: "User-Agent", Value: "sqlmap/1.7" }],
  },
});
check("blocked sample keeps the WAF response code", blocked.responseCode, 403);
check("blocked sample action", blocked.action, "BLOCK");
check("blocked sample path", blocked.path, "/wp-login.php");

const allowed = toSampleRow({
  Timestamp: new Date("2026-08-10T03:07:13.000Z"),
  Action: "ALLOW",
  Request: { ClientIP: "10.0.2.88", Method: "GET", URI: "/v1/user" },
});
check("allowed sample with no code maps to null", allowed.responseCode, null);
check("missing rule maps to empty string", allowed.rule, "");
check("missing country maps to empty string", allowed.country, "");

const contains = (name, haystack, needle, expected = true) => {
  const ok = haystack.includes(needle) === expected;
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        ${expected ? "missing" : "unexpected"} ${JSON.stringify(needle)} in ${JSON.stringify(haystack)}`),
  );
};

// Status class ranges
const q4xx = buildRequestLogQuery({ statusClass: "4xx", pathContains: "" });
contains("4xx adds the right range", q4xx, "filter status >= 400 and status < 500");
const q5xx = buildRequestLogQuery({ statusClass: "5xx", pathContains: "" });
contains("5xx adds the right range", q5xx, "filter status >= 500 and status < 600");
const q2xx = buildRequestLogQuery({ statusClass: "2xx", pathContains: "" });
contains("2xx adds the right range", q2xx, "filter status >= 200 and status < 300");
const q3xx = buildRequestLogQuery({ statusClass: "3xx", pathContains: "" });
contains("3xx adds the right range", q3xx, "filter status >= 300 and status < 400");

// ALL adds no status range at all
const qAll = buildRequestLogQuery({ statusClass: "ALL", pathContains: "" });
contains("ALL adds no status range", qAll, "filter status >=", false);
contains("ALL still requires a parsed status", qAll, "filter ispresent(status)");

// Path filter
const qPath = buildRequestLogQuery({ statusClass: "ALL", pathContains: "/v1/user" });
contains("path filter is added", qPath, 'filter path like "/v1/user"');
contains("empty path adds no path filter", qAll, "filter path like", false);

// Structure
contains("query parses the JSON fields", qAll, 'parse log /"status":(?<status>[0-9]+)/');
contains("query selects the row fields", qAll, "fields @timestamp, method, path, status, latency_ms");
contains("query sorts newest first", qAll, "sort @timestamp desc");
contains("query caps rows", qAll, `limit ${ROW_LIMIT}`);
check("row cap is 200", ROW_LIMIT, 200);

// Rejected input — these would otherwise break out of the quoted string
const rejects = ['/v1/"', "/v1/\\", "/v1/user or 1=1", "/v1/*", "/v1/(a|b)", "/v1 user", "/v1/user;"];
for (const bad of rejects) {
  let threw = false;
  try {
    validatePathFilter(bad);
  } catch {
    threw = true;
  }
  check(`validatePathFilter rejects ${JSON.stringify(bad)}`, threw, true);
}
let tooLong = false;
try {
  validatePathFilter("/".repeat(PATH_FILTER_MAX + 1));
} catch {
  tooLong = true;
}
check("validatePathFilter rejects over-long input", tooLong, true);

// Accepted input
check("validatePathFilter trims", validatePathFilter("  /v1/user  "), "/v1/user");
check("validatePathFilter allows dots and dashes", validatePathFilter("/v1/a-b.c_d"), "/v1/a-b.c_d");
check("validatePathFilter allows empty", validatePathFilter(""), "");

// Row mapping
check(
  "toRequestLogRow converts types",
  toRequestLogRow({
    "@timestamp": "2026-08-10 03:07:12.727",
    method: "GET",
    path: "/v1/product",
    status: "500",
    latency_ms: "85.5",
  }),
  { ts: "2026-08-10T03:07:12.727Z", method: "GET", path: "/v1/product", status: 500, latencyMs: 85.5 },
);
check(
  "toRequestLogRow tolerates missing fields",
  toRequestLogRow({}),
  { ts: "Z", method: "", path: "", status: 0, latencyMs: 0 },
);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
