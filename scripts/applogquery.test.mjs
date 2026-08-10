const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { toSampleRow } = await import(`${SRC}waf.ts`);

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

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
