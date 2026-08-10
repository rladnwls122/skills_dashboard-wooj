const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { testRule, defaultTestRequests, RULE_JSON_MAX, MAX_REQUESTS, FIELD_MAX } = await import(
  `${SRC}rulesim.ts`
);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};
const throws = (name, fn, needle) => {
  let msg = null;
  try {
    fn();
  } catch (e) {
    msg = e instanceof Error ? e.message : String(e);
  }
  const ok = msg !== null && msg.includes(needle);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` + (ok ? "" : `\n        expected a message containing ${JSON.stringify(needle)}, got ${JSON.stringify(msg)}`),
  );
};

// --- Default request set tracks APP_TRAFFIC_PATHS ---
const defaults = defaultTestRequests();
check("default set has one row per served path plus loadgen and healthcheck", defaults.length, 6);
check("default ids are unique", new Set(defaults.map((r) => r.id)).size, defaults.length);
check(
  "default set covers the served surface",
  defaults.some((r) => r.path === "/v1/user") &&
    defaults.some((r) => r.path === "/v1/product") &&
    defaults.some((r) => r.path === "/v1/stress") &&
    defaults.some((r) => r.path === "/v1/image"),
  true,
);
check("default set includes the healthcheck", defaults.some((r) => r.path === "/healthcheck"), true);

const rule = (statement, action) =>
  JSON.stringify({ Name: "t", Priority: 100, Statement: statement, ...(action ? { Action: action } : {}) });
const uaContains = (needle) => ({
  ByteMatchStatement: {
    SearchString: needle,
    FieldToMatch: { SingleHeader: { Name: "user-agent" } },
    TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
    PositionalConstraint: "CONTAINS",
  },
});
const pathStarts = (p) => ({
  ByteMatchStatement: {
    SearchString: p,
    FieldToMatch: { UriPath: {} },
    TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
    PositionalConstraint: "STARTS_WITH",
  },
});

// --- A rule aimed off the served surface leaves normal traffic alone ---
const safe = testRule({ ruleJson: rule(pathStarts("/wp-login"), { Block: {} }), requests: defaults });
check("off-surface block rule blocks nothing normal", safe.blocked, 0);
check("off-surface block rule verdict is SAFE", safe.verdict, "SAFE");
check("off-surface block rule passes everything", safe.passed, defaults.length);
check("rule name is read", safe.ruleName, "t");
check("Block action is read", safe.action, "Block");

// --- A rule that catches the load generator's UA is a false positive ---
const fp = testRule({ ruleJson: rule(uaContains("go-http-client"), { Block: {} }), requests: defaults });
check("load-generator UA rule blocks one row", fp.blocked, 1);
check("load-generator UA rule verdict is the risk", fp.verdict, "FALSE_POSITIVE_RISK");
check(
  "the blocked row is the load generator",
  fp.rows.find((r) => r.outcome === "BLOCKED")?.requestId,
  defaults.find((r) => r.userAgent.includes("Go-http-client"))?.id,
);

// --- Count does not block ---
const counted = testRule({ ruleJson: rule(uaContains("go-http-client"), { Count: {} }), requests: defaults });
check("Count action is read", counted.action, "Count");
check("Count blocks nothing", counted.blocked, 0);
check("Count counts the match", counted.counted, 1);
check("Count verdict is SAFE", counted.verdict, "SAFE");

// --- Unsupported statement never reads as a pass ---
const unknown = testRule({
  ruleJson: rule({ RateBasedStatement: { Limit: 2000, AggregateKeyType: "IP" } }, { Block: {} }),
  requests: defaults,
});
check("rate-based rule yields no passes", unknown.passed, 0);
check("rate-based rule marks every row unknown", unknown.unknown, defaults.length);
check("rate-based rule verdict is inconclusive", unknown.verdict, "INCONCLUSIVE");
check("rate-based rule names the unsupported statement", unknown.unsupported, ["RateBasedStatement"]);

// --- A blocked row wins over an unknown row in the verdict ---
const mixed = testRule({
  ruleJson: rule(
    { OrStatement: { Statements: [uaContains("go-http-client"), { LabelMatchStatement: { Scope: "NAMESPACE", Key: "x" } }] } },
    { Block: {} },
  ),
  requests: defaults,
});
check("blocked beats unknown in the verdict", mixed.verdict, "FALSE_POSITIVE_RISK");

// --- Missing Action cannot be judged ---
const noAction = testRule({ ruleJson: rule(uaContains("go-http-client"), null), requests: defaults });
check("missing Action is reported", noAction.action, "(none)");
check("a match with no Action is unknown, not blocked", noAction.blocked, 0);
check("a match with no Action is unknown", noAction.unknown, 1);

// --- OverrideAction Count (managed groups) ---
const override = testRule({
  ruleJson: JSON.stringify({
    Name: "og",
    Priority: 1,
    Statement: uaContains("go-http-client"),
    OverrideAction: { Count: {} },
  }),
  requests: defaults,
});
check("OverrideAction Count is read as Count", override.action, "Count");

// --- Input limits ---
throws("rejects invalid JSON", () => testRule({ ruleJson: "{ nope", requests: defaults }), "JSON");
throws(
  "rejects a rule with no Statement",
  () => testRule({ ruleJson: JSON.stringify({ Name: "x" }), requests: defaults }),
  "Statement",
);
throws(
  "rejects an over-long rule",
  () => testRule({ ruleJson: "x".repeat(RULE_JSON_MAX + 1), requests: defaults }),
  "20",
);
throws(
  "rejects too many requests",
  () =>
    testRule({
      ruleJson: rule(pathStarts("/x"), { Block: {} }),
      requests: Array.from({ length: MAX_REQUESTS + 1 }, (_, i) => ({ ...defaults[0], id: `r${i}` })),
    }),
  String(MAX_REQUESTS),
);
throws(
  "rejects an over-long request field",
  () =>
    testRule({
      ruleJson: rule(pathStarts("/x"), { Block: {} }),
      requests: [{ ...defaults[0], path: "/".repeat(FIELD_MAX + 1) }],
    }),
  String(FIELD_MAX),
);
throws("rejects an empty request list", () => testRule({ ruleJson: rule(pathStarts("/x"), { Block: {} }), requests: [] }), "요청");

// --- Every row is accounted for ---
check(
  "counts always sum to the row count",
  safe.passed + safe.blocked + safe.counted + safe.unknown,
  safe.rows.length,
);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
