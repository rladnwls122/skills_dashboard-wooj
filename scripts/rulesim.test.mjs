const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { testRule, defaultTestRequests, maliciousExampleRequests, RULE_JSON_MAX, MAX_REQUESTS, MAX_RULES, FIELD_MAX } =
  await import(`${SRC}rulesim.ts`);

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

const rule = (statement, action, extra = {}) =>
  JSON.stringify({ Name: "t", Priority: 100, Statement: statement, ...(action ? { Action: action } : {}), ...extra });
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
check("a single rule reports one rule", safe.ruleCount, 1);
check("nothing matched means no deciding rule", safe.rows.every((r) => r.ruleName === null), true);

// --- A rule that catches the load generator's UA is a false positive ---
const fp = testRule({ ruleJson: rule(uaContains("go-http-client"), { Block: {} }), requests: defaults });
check("load-generator UA rule blocks one row", fp.blocked, 1);
check("load-generator UA rule verdict is the risk", fp.verdict, "FALSE_POSITIVE_RISK");
check(
  "the blocked row is the load generator",
  fp.rows.find((r) => r.outcome === "BLOCKED")?.requestId,
  defaults.find((r) => r.userAgent.includes("Go-http-client"))?.id,
);
check(
  "the blocked row names the rule that decided it",
  fp.rows.find((r) => r.outcome === "BLOCKED")?.ruleName,
  "t",
);

// --- Count does not block ---
const counted = testRule({ ruleJson: rule(uaContains("go-http-client"), { Count: {} }), requests: defaults });
check("Count action is read", counted.action, "Count");
check("Count blocks nothing", counted.blocked, 0);
check("Count counts the match", counted.counted, 1);
check("Count verdict is SAFE", counted.verdict, "SAFE");

// --- Captcha / Challenge ---
const captcha = testRule({ ruleJson: rule(uaContains("go-http-client"), { Captcha: {} }), requests: defaults });
check("Captcha action is read", captcha.action, "Captcha");
check("Captcha challenges rather than blocks", [captcha.challenged, captcha.blocked], [1, 0]);

// --- Statements that used to be unevaluable now produce a verdict ---
const rateRule = testRule({
  ruleJson: rule({ RateBasedStatement: { Limit: 2000, AggregateKeyType: "IP", ScopeDownStatement: pathStarts("/wp-login") } }, { Block: {} }),
  requests: defaults,
});
check("a rate rule with an off-surface scope-down leaves traffic alone", rateRule.blocked, 0);
check("a rate rule is no longer inconclusive", rateRule.unknown, 0);
check("a rate rule is flagged as approximated", rateRule.approximated, ["RateBasedStatement"]);

const managedRule = testRule({
  ruleJson: JSON.stringify({
    Name: "crs",
    Priority: 1,
    Statement: { ManagedRuleGroupStatement: { VendorName: "AWS", Name: "AWSManagedRulesCommonRuleSet" } },
    OverrideAction: { Count: {} },
  }),
  requests: defaults,
});
check("a managed group no longer blanks out every row", managedRule.unknown, 0);
check("a managed group leaves ordinary traffic alone", managedRule.passed, defaults.length);
check(
  "a managed group is flagged as approximated",
  managedRule.approximated,
  ["ManagedRuleGroupStatement(AWSManagedRulesCommonRuleSet)"],
);

// --- What genuinely needs AWS-side data is still UNKNOWN, never a pass ---
const unknown = testRule({
  ruleJson: rule({ IPSetReferenceStatement: { ARN: "arn:aws:wafv2:us-east-1:1:global/ipset/unknown/x" } }, { Block: {} }),
  requests: defaults,
});
check("an unresolvable IP set yields no passes", unknown.passed, 0);
check("an unresolvable IP set marks every row unknown", unknown.unknown, defaults.length);
check("an unresolvable IP set verdict is inconclusive", unknown.verdict, "INCONCLUSIVE");
check("an unresolvable IP set names the unsupported statement", unknown.unsupported, ["IPSetReferenceStatement"]);

// --- The same rule becomes decidable once the set rides along in the JSON ---
const resolved = testRule({
  ruleJson: JSON.stringify({
    IPSets: { "office-ips": ["10.0.2.0/24"] },
    Rules: [
      {
        Name: "block-office",
        Priority: 1,
        Statement: { IPSetReferenceStatement: { ARN: "arn:aws:wafv2:us-east-1:1:global/ipset/office-ips/x" } },
        Action: { Block: {} },
      },
    ],
  }),
  requests: defaults,
});
check("an inline IP set makes the rule decidable", resolved.unknown, 0);
check("the inline IP set actually matches", resolved.blocked, defaults.length);

// --- A blocked row wins over an unknown row in the verdict ---
const mixed = testRule({
  ruleJson: rule(
    { OrStatement: { Statements: [uaContains("go-http-client"), { IPSetReferenceStatement: { ARN: "arn:unknown" } }] } },
    { Block: {} },
  ),
  requests: defaults,
});
check("blocked beats unknown in the verdict", mixed.verdict, "FALSE_POSITIVE_RISK");

// --- Missing Action is reported as a match, not as a failure to evaluate ---
const noAction = testRule({ ruleJson: rule(uaContains("go-http-client"), null), requests: defaults });
check("missing Action is reported", noAction.action, "(none)");
check("a match with no Action is not counted as blocked", noAction.blocked, 0);
check("a match with no Action is its own outcome", noAction.matched, 1);
check("a match with no Action is not unknown", noAction.unknown, 0);

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

// --- Input shapes an operator actually has in hand ---
const bareStatement = testRule({ ruleJson: JSON.stringify(pathStarts("/v1/user")), requests: defaults });
check("a bare Statement body is accepted", bareStatement.ruleCount, 1);
// "/v1/user" is both the first served path and the load generator's target.
check("a bare Statement body still matches", bareStatement.matched, 2);

const asArray = testRule({
  ruleJson: JSON.stringify([
    { Name: "a", Priority: 1, Statement: pathStarts("/wp-login"), Action: { Block: {} } },
    { Name: "b", Priority: 2, Statement: uaContains("go-http-client"), Action: { Count: {} } },
  ]),
  requests: defaults,
});
check("a Rule array is accepted", asArray.ruleCount, 2);
check("the array's Count rule fires", asArray.counted, 1);

const webAcl = testRule({
  ruleJson: JSON.stringify({
    WebACL: {
      Name: "skills-waf",
      Rules: [
        { Name: "allow-health", Priority: 1, Statement: pathStarts("/healthcheck"), Action: { Allow: {} } },
        { Name: "block-go", Priority: 2, Statement: uaContains("go-http-client"), Action: { Block: {} } },
      ],
    },
  }),
  requests: defaults,
});
check("a get-web-acl payload is accepted", webAcl.ruleCount, 2);
check("the WebACL's later Block rule still fires", webAcl.blocked, 1);
check("the deciding rule is named per row", webAcl.rows.find((r) => r.outcome === "BLOCKED")?.ruleName, "block-go");

// Copying two rules out of the WAF console and pasting them back to back
// produces "}{", which is not valid JSON but is exactly what an operator has.
const concatenated = testRule({
  ruleJson:
    JSON.stringify({ Name: "block-scanner-ua", Priority: 1, Statement: uaContains("gobuster"), Action: { Block: {} } }) +
    JSON.stringify({ Name: "block-paths", Priority: 2, Statement: pathStarts("/admin"), Action: { Block: {} } }),
  requests: defaults,
});
check("two rules pasted back to back are both read", concatenated.ruleCount, 2);
check("back-to-back rules leave normal traffic alone", concatenated.verdict, "SAFE");

check(
  "a comma between pasted rules is tolerated",
  testRule({
    ruleJson:
      JSON.stringify({ Name: "a", Priority: 1, Statement: pathStarts("/admin"), Action: { Block: {} } }) +
      ",\n" +
      JSON.stringify({ Name: "b", Priority: 2, Statement: pathStarts("/.env"), Action: { Block: {} } }),
    requests: defaults,
  }).ruleCount,
  2,
);
check(
  "comments and a trailing comma are tolerated",
  testRule({
    ruleJson: `// 스캐너 UA 차단
{
  "Name": "a",
  "Priority": 1,
  /* 경로가 아니라 UA를 본다 */
  "Statement": ${JSON.stringify(uaContains("gobuster"))},
  "Action": { "Block": {} },
}`,
    requests: defaults,
  }).ruleCount,
  1,
);
// A "//" inside a SearchString must not be mistaken for a comment.
check(
  "a URL inside a SearchString survives comment stripping",
  testRule({
    ruleJson:
      JSON.stringify({
        Name: "rfi",
        Priority: 1,
        Statement: {
          ByteMatchStatement: {
            SearchString: "http://evil.example/",
            FieldToMatch: { QueryString: {} },
            TextTransformations: [{ Priority: 0, Type: "URL_DECODE" }],
            PositionalConstraint: "CONTAINS",
          },
        },
        Action: { Block: {} },
      }) + "\n// 끝",
    requests: [
      { ...defaults[0], id: "rfi-hit", query: "next=http://evil.example/x", benign: false },
      ...defaults,
    ],
  }).caught,
  1,
);

// The two-rule scanner/path pair an operator would actually paste.
const scannerAndPaths = testRule({
  ruleJson:
    JSON.stringify({
      Name: "BlockMaliciousScannerUA",
      Priority: 1,
      Statement: {
        OrStatement: {
          Statements: ["masscan", "nuclei", "gobuster", "sqlmap", "nmap"].map(uaContains),
        },
      },
      Action: { Block: {} },
    }) +
    JSON.stringify({
      Name: "BlockSensitivePaths",
      Priority: 2,
      Statement: {
        OrStatement: {
          Statements: ["/.env", "/admin", "/wp-login.php", "/.git/config"].map(pathStarts),
        },
      },
      Action: { Block: {} },
    }),
  requests: [...defaults, ...maliciousExampleRequests()],
});
check("the scanner/path pair blocks no benign traffic", scannerAndPaths.blocked, 0);
check("the scanner/path pair catches the scanner and probe rows", scannerAndPaths.caught >= 4, true);
check("the scanner/path pair needs no AWS-side data", scannerAndPaths.unknown, 0);
check(
  "each caught row names the rule that caught it",
  scannerAndPaths.rows
    .filter((r) => r.outcome === "CAUGHT")
    .every((r) => r.ruleName === "BlockMaliciousScannerUA" || r.ruleName === "BlockSensitivePaths"),
  true,
);

// Priority order decides: an Allow ahead of a Block wins.
const priorityOrder = testRule({
  ruleJson: JSON.stringify({
    Rules: [
      { Name: "block-go", Priority: 20, Statement: uaContains("go-http-client"), Action: { Block: {} } },
      { Name: "allow-loadgen", Priority: 10, Statement: uaContains("go-http-client"), Action: { Allow: {} } },
    ],
  }),
  requests: defaults,
});
check("a lower-priority Allow terminates before the Block", priorityOrder.blocked, 0);
check("the allowing rule is the one named", priorityOrder.rows.find((r) => r.ruleName !== null)?.ruleName, "allow-loadgen");

// Labels set by an earlier rule are visible to a later LabelMatchStatement.
const labelled = testRule({
  ruleJson: JSON.stringify({
    Rules: [
      {
        Name: "tag-loadgen",
        Priority: 1,
        Statement: uaContains("go-http-client"),
        Action: { Count: {} },
        RuleLabels: [{ Name: "local:loadgen" }],
      },
      {
        Name: "block-tagged",
        Priority: 2,
        Statement: { LabelMatchStatement: { Scope: "LABEL", Key: "local:loadgen" } },
        Action: { Block: {} },
      },
    ],
  }),
  requests: defaults,
});
check("a label from an earlier rule reaches the later LabelMatch", labelled.blocked, 1);
check("the label rule is the deciding rule", labelled.rows.find((r) => r.outcome === "BLOCKED")?.ruleName, "block-tagged");
check("labels do not leak between requests", labelled.passed, defaults.length - 1);

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
  String(Math.floor(RULE_JSON_MAX / 1024)),
);
throws(
  "rejects too many rules",
  () =>
    testRule({
      ruleJson: JSON.stringify(
        Array.from({ length: MAX_RULES + 1 }, (_, i) => ({
          Name: `r${i}`,
          Priority: i,
          Statement: pathStarts("/x"),
          Action: { Count: {} },
        })),
      ),
      requests: defaults,
    }),
  String(MAX_RULES),
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
const total = (r) => r.passed + r.blocked + r.counted + r.caught + r.challenged + r.matched + r.unknown;
check("counts always sum to the row count", total(safe), safe.rows.length);

// --- Malicious example set ---
const evil = maliciousExampleRequests();
check("malicious examples are non-empty", evil.length > 0, true);
check("all malicious examples are flagged benign:false", evil.every((r) => r.benign === false), true);
check(
  "malicious examples exercise the header/body surface too",
  evil.some((r) => (r.body ?? "").length > 0) && evil.some((r) => (r.headers ?? {}).cookie),
  true,
);

// A rule that blocks /wp-login catches the malicious wp-login probe (true
// positive) and leaves the normal set alone.
const wp = testRule({
  ruleJson: rule(pathStarts("/wp-login"), { Block: {} }),
  requests: [...defaults, ...evil],
});
check("blocking a malicious example counts as caught, not blocked", wp.blocked, 0);
check("the malicious wp-login probe is caught", wp.caught >= 1, true);
check("a rule catching only malicious traffic stays SAFE", wp.verdict, "SAFE");
check("counts including caught sum to the row count", total(wp), wp.rows.length);

// Blocking a benign row is still a false-positive risk.
const overblock = testRule({
  ruleJson: rule(pathStarts("/v1"), { Block: {} }),
  requests: [...defaults, ...evil],
});
check("blocking benign /v1 rows is a false-positive risk", overblock.verdict, "FALSE_POSITIVE_RISK");
check("benign blocked rows are counted as blocked", overblock.blocked > 0, true);

// The managed groups the dashboard itself recommends now score the malicious
// set instead of returning "cannot evaluate" for every row.
const crs = testRule({
  ruleJson: JSON.stringify({
    Name: "crs",
    Priority: 1,
    Statement: { ManagedRuleGroupStatement: { VendorName: "AWS", Name: "AWSManagedRulesCommonRuleSet" } },
    OverrideAction: { None: {} },
  }),
  requests: [...defaults, ...evil],
});
check("CommonRuleSet catches part of the malicious set", crs.caught > 0, true);
check("CommonRuleSet leaves the benign set alone", crs.blocked, 0);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
