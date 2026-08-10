// The evaluator's contract: everything it cannot decide locally is UNKNOWN,
// never a pass. These cases pin that down alongside the matchers.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { evalStatement, REGEX_MAX } = await import(`${SRC}rulestatement.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const REQ = {
  id: "r1",
  method: "GET",
  path: "/v1/user",
  query: "id=3&name=kim",
  userAgent: "Mozilla/5.0 (Windows NT 10.0)",
  ip: "10.0.2.88",
  country: "KR",
};
const ctx = () => ({ unsupported: new Set(), notes: new Set() });
const ev = (stmt, req = REQ) => evalStatement(stmt, req, ctx());

const byteMatch = (search, field, constraint, transforms = [{ Priority: 0, Type: "NONE" }]) => ({
  ByteMatchStatement: {
    SearchString: search,
    FieldToMatch: field,
    TextTransformations: transforms,
    PositionalConstraint: constraint,
  },
});
const URI = { UriPath: {} };

// --- PositionalConstraint, all five ---
check("EXACTLY hit", ev(byteMatch("/v1/user", URI, "EXACTLY")), true);
check("EXACTLY miss", ev(byteMatch("/v1/use", URI, "EXACTLY")), false);
check("STARTS_WITH hit", ev(byteMatch("/v1/", URI, "STARTS_WITH")), true);
check("STARTS_WITH miss", ev(byteMatch("v1/", URI, "STARTS_WITH")), false);
check("ENDS_WITH hit", ev(byteMatch("user", URI, "ENDS_WITH")), true);
check("ENDS_WITH miss", ev(byteMatch("users", URI, "ENDS_WITH")), false);
check("CONTAINS hit", ev(byteMatch("1/us", URI, "CONTAINS")), true);
check("CONTAINS miss", ev(byteMatch("admin", URI, "CONTAINS")), false);
check("CONTAINS_WORD hit", ev(byteMatch("user", URI, "CONTAINS_WORD")), true);
check("CONTAINS_WORD rejects a substring inside a word", ev(byteMatch("use", URI, "CONTAINS_WORD")), false);

// --- FieldToMatch ---
check("Method field", ev(byteMatch("GET", { Method: {} }, "EXACTLY")), true);
check("QueryString field", ev(byteMatch("name=kim", { QueryString: {} }, "CONTAINS")), true);
check("AllQueryArguments field", ev(byteMatch("id=3", { AllQueryArguments: {} }, "CONTAINS")), true);
check(
  "SingleHeader user-agent",
  ev(byteMatch("Mozilla", { SingleHeader: { Name: "user-agent" } }, "CONTAINS")),
  true,
);
check(
  "SingleHeader we do not model is UNKNOWN, not a pass",
  ev(byteMatch("x", { SingleHeader: { Name: "x-forwarded-for" } }, "CONTAINS")),
  "UNKNOWN",
);
check("Body field is UNKNOWN", ev(byteMatch("x", { Body: {} }, "CONTAINS")), "UNKNOWN");

// --- TextTransformations ---
check(
  "LOWERCASE applies",
  ev(byteMatch("mozilla", { SingleHeader: { Name: "user-agent" } }, "CONTAINS", [
    { Priority: 0, Type: "LOWERCASE" },
  ])),
  true,
);
check(
  "transforms run in Priority order",
  ev(
    byteMatch("a b", { QueryString: {} }, "CONTAINS", [
      { Priority: 1, Type: "COMPRESS_WHITE_SPACE" },
      { Priority: 0, Type: "URL_DECODE" },
    ]),
    { ...REQ, query: "a%20%20%20b" },
  ),
  true,
);
check(
  "TRIM applies",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "TRIM" }]), {
    ...REQ,
    path: "  /v1/user  ",
  }),
  true,
);
check(
  "HTML_ENTITY_DECODE applies",
  ev(
    byteMatch("<script>", { QueryString: {} }, "CONTAINS", [
      { Priority: 0, Type: "HTML_ENTITY_DECODE" },
    ]),
    { ...REQ, query: "q=&lt;script&gt;" },
  ),
  true,
);
check(
  "an unknown transform is UNKNOWN, not a pass",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "MADE_UP_TRANSFORM" }])),
  "UNKNOWN",
);

// --- RegexMatchStatement ---
const regex = (s) => ({
  RegexMatchStatement: {
    RegexString: s,
    FieldToMatch: URI,
    TextTransformations: [{ Priority: 0, Type: "NONE" }],
  },
});
check("regex hit", ev(regex("^/v1/(user|product)$")), true);
check("regex miss", ev(regex("^/admin")), false);
check("invalid regex is UNKNOWN", ev(regex("([unclosed")), "UNKNOWN");
check("over-long regex is UNKNOWN", ev(regex("a".repeat(REGEX_MAX + 1))), "UNKNOWN");

// --- SizeConstraintStatement ---
const size = (op, size) => ({
  SizeConstraintStatement: {
    FieldToMatch: URI,
    ComparisonOperator: op,
    Size: size,
    TextTransformations: [{ Priority: 0, Type: "NONE" }],
  },
});
// "/v1/user" is 8 bytes
check("size EQ", ev(size("EQ", 8)), true);
check("size NE", ev(size("NE", 8)), false);
check("size GT", ev(size("GT", 7)), true);
check("size GE", ev(size("GE", 8)), true);
check("size LT", ev(size("LT", 8)), false);
check("size LE", ev(size("LE", 8)), true);

// --- Newly supported transforms (deterministic, locally decidable) ---
check(
  "BASE64_DECODE decodes the field",
  ev(byteMatch("attack", { QueryString: {} }, "CONTAINS", [{ Priority: 0, Type: "BASE64_DECODE" }]),
    { ...REQ, query: "YXR0YWNr" }),
  true,
);
check(
  "REMOVE_NULLS strips null bytes",
  ev(byteMatch("select", { QueryString: {} }, "CONTAINS", [{ Priority: 0, Type: "REMOVE_NULLS" }]),
    { ...REQ, query: "se le ct" }),
  true,
);
check(
  "NORMALIZE_PATH collapses traversal",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "NORMALIZE_PATH" }]),
    { ...REQ, path: "/v1/a/../user" }),
  true,
);
check(
  "CMD_LINE normalizes command punctuation",
  ev(byteMatch("cat /etc/passwd", { QueryString: {} }, "CONTAINS", [{ Priority: 0, Type: "CMD_LINE" }]),
    { ...REQ, query: "cat    /etc/passwd" }),
  true,
);

// --- GeoMatchStatement ---
const geo = (codes) => ({ GeoMatchStatement: { CountryCodes: codes } });
check("GeoMatch hit on country", ev(geo(["KR", "JP"])), true);
check("GeoMatch miss on country", ev(geo(["US", "CN"])), false);
check("GeoMatch is case-insensitive", ev(geo(["kr"])), true);
check("GeoMatch with empty codes is UNKNOWN", ev(geo([])), "UNKNOWN");

// --- Three-valued And / Or / Not ---
const T = byteMatch("/v1/", URI, "STARTS_WITH");
const F = byteMatch("/admin", URI, "STARTS_WITH");
const U = { ManagedRuleGroupStatement: { VendorName: "AWS", Name: "AWSManagedRulesCommonRuleSet" } };

check("And all true", ev({ AndStatement: { Statements: [T, T] } }), true);
check("And with a false is false", ev({ AndStatement: { Statements: [T, F] } }), false);
check("And false beats UNKNOWN", ev({ AndStatement: { Statements: [F, U] } }), false);
check("And true plus UNKNOWN is UNKNOWN", ev({ AndStatement: { Statements: [T, U] } }), "UNKNOWN");
check("Or with a true is true", ev({ OrStatement: { Statements: [F, T] } }), true);
check("Or true beats UNKNOWN", ev({ OrStatement: { Statements: [U, T] } }), true);
check("Or false plus UNKNOWN is UNKNOWN", ev({ OrStatement: { Statements: [F, U] } }), "UNKNOWN");
check("Or all false", ev({ OrStatement: { Statements: [F, F] } }), false);
check("Not inverts true", ev({ NotStatement: { Statement: T } }), false);
check("Not inverts false", ev({ NotStatement: { Statement: F } }), true);
check("Not keeps UNKNOWN", ev({ NotStatement: { Statement: U } }), "UNKNOWN");
check(
  "nested And/Or/Not",
  ev({
    AndStatement: {
      Statements: [T, { NotStatement: { Statement: { OrStatement: { Statements: [F, F] } } } }],
    },
  }),
  true,
);

// --- Unsupported statements are all UNKNOWN and are reported by name ---
const unsupported = [
  ["IPSetReferenceStatement", { IPSetReferenceStatement: { ARN: "arn:aws:wafv2:...:ipset/x" } }],
  ["RegexPatternSetReferenceStatement", { RegexPatternSetReferenceStatement: { ARN: "arn:...", FieldToMatch: URI, TextTransformations: [] } }],
  ["ManagedRuleGroupStatement", U],
  ["LabelMatchStatement", { LabelMatchStatement: { Scope: "NAMESPACE", Key: "awswaf:managed:aws:" } }],
  ["RateBasedStatement", { RateBasedStatement: { Limit: 2000, AggregateKeyType: "IP" } }],
  ["SqliMatchStatement", { SqliMatchStatement: { FieldToMatch: URI, TextTransformations: [] } }],
  ["XssMatchStatement", { XssMatchStatement: { FieldToMatch: URI, TextTransformations: [] } }],
];
for (const [name, stmt] of unsupported) {
  const c = ctx();
  check(`${name} evaluates to UNKNOWN`, evalStatement(stmt, REQ, c), "UNKNOWN");
  check(`${name} is reported by name`, [...c.unsupported], [name]);
}

// --- Malformed input ---
check("empty statement is UNKNOWN", ev({}), "UNKNOWN");
check("null statement is UNKNOWN", ev(null), "UNKNOWN");
check("unknown statement key is UNKNOWN", ev({ FutureStatement: {} }), "UNKNOWN");

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
