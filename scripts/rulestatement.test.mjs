// The evaluator's contract: everything it cannot decide locally is UNKNOWN,
// never a pass — and UNKNOWN is kept rare, because a sandbox that answers
// "cannot tell" for half of WAF's grammar is not a sandbox. These cases pin
// down both halves: the matchers, and what is honestly out of reach.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { evalStatement, newEvalContext, REGEX_MAX } = await import(`${SRC}rulestatement.ts`);
const { ipInCidr } = await import(`${SRC}rulerequest.ts`);

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
  benign: true,
};
const ctx = () => newEvalContext();
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
check(
  "SingleHeader user-agent",
  ev(byteMatch("Mozilla", { SingleHeader: { Name: "user-agent" } }, "CONTAINS")),
  true,
);
// AWS inspects each query argument's *value*, not the raw "name=value" pair.
check("AllQueryArguments inspects argument values", ev(byteMatch("kim", { AllQueryArguments: {} }, "EXACTLY")), true);
check(
  "AllQueryArguments does not see the argument name",
  ev(byteMatch("id=3", { AllQueryArguments: {} }, "CONTAINS")),
  false,
);
check(
  "SingleQueryArgument picks one argument",
  ev(byteMatch("3", { SingleQueryArgument: { Name: "id" } }, "EXACTLY")),
  true,
);
check(
  "SingleQueryArgument misses an absent argument",
  ev(byteMatch("x", { SingleQueryArgument: { Name: "nope" } }, "CONTAINS")),
  false,
);

// A header the request does not carry is a definite no-match, not an unknown:
// the synthetic request models every header it has.
check(
  "an absent header is a miss, not UNKNOWN",
  ev(byteMatch("x", { SingleHeader: { Name: "x-forwarded-for" } }, "CONTAINS")),
  false,
);
check(
  "a header the operator added is inspected",
  ev(byteMatch("203.0.113.9", { SingleHeader: { Name: "x-forwarded-for" } }, "CONTAINS"), {
    ...REQ,
    headers: { "X-Forwarded-For": "203.0.113.9, 10.0.0.1" },
  }),
  true,
);
check(
  "Headers ALL scope sees names and values",
  ev(byteMatch("accept", { Headers: { MatchPattern: { All: {} }, MatchScope: "KEY" } }, "EXACTLY"), {
    ...REQ,
    headers: { Accept: "application/json" },
  }),
  true,
);
check(
  "Headers IncludedHeaders narrows the inspection",
  ev(
    byteMatch("secret", { Headers: { MatchPattern: { IncludedHeaders: ["authorization"] }, MatchScope: "VALUE" } }, "CONTAINS"),
    { ...REQ, headers: { authorization: "Bearer secret", "x-other": "secret" } },
  ),
  true,
);
check(
  "Cookies field parses the Cookie header",
  ev(byteMatch("abc123", { Cookies: { MatchPattern: { All: {} }, MatchScope: "VALUE" } }, "EXACTLY"), {
    ...REQ,
    headers: { cookie: "session=abc123; theme=dark" },
  }),
  true,
);
check(
  "Body field is inspected",
  ev(byteMatch("union select", { Body: {} }, "CONTAINS"), { ...REQ, body: "q=union select 1" }),
  true,
);
check(
  "JsonBody VALUE scope",
  ev(byteMatch("kim", { JsonBody: { MatchPattern: { All: {} }, MatchScope: "VALUE" } }, "EXACTLY"), {
    ...REQ,
    body: '{"user":{"name":"kim"}}',
  }),
  true,
);
check(
  "JsonBody KEY scope",
  ev(byteMatch("name", { JsonBody: { MatchPattern: { All: {} }, MatchScope: "KEY" } }, "EXACTLY"), {
    ...REQ,
    body: '{"user":{"name":"kim"}}',
  }),
  true,
);
check(
  "a non-JSON body falls back to the raw string",
  ev(byteMatch("not json", { JsonBody: { MatchPattern: { All: {} }, MatchScope: "VALUE" } }, "CONTAINS"), {
    ...REQ,
    body: "not json at all",
  }),
  true,
);
check(
  "HeaderOrder lists the header names",
  ev(byteMatch("user-agent,accept", { HeaderOrder: {} }, "EXACTLY"), {
    ...REQ,
    headers: { accept: "*/*" },
  }),
  true,
);
check(
  "a FieldToMatch we cannot model is UNKNOWN",
  ev(byteMatch("x", { JA3Fingerprint: { FallbackBehavior: "NO_MATCH" } }, "CONTAINS")),
  "UNKNOWN",
);

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
check("the unsupported transform is named", (() => {
  const c = ctx();
  evalStatement(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "MD5" }]), REQ, c);
  return [...c.unsupported];
})(), ["TextTransformation:MD5"]);

const transformCase = (type, raw, needle) =>
  ev(byteMatch(needle, { QueryString: {} }, "CONTAINS", [{ Priority: 0, Type: type }]), {
    ...REQ,
    query: raw,
  });

check("BASE64_DECODE decodes the field", transformCase("BASE64_DECODE", "YXR0YWNr", "attack"), true);
check(
  "BASE64_DECODE leaves an undecodable value alone",
  transformCase("BASE64_DECODE", "id=3", "id=3"),
  true,
);
check("BASE64_DECODE_EXT ignores padding noise", transformCase("BASE64_DECODE_EXT", "YXR0!YWNr", "attack"), true);
check("HEX_DECODE decodes hex", transformCase("HEX_DECODE", "61747461636b", "attack"), true);
check("SQL_HEX_DECODE decodes SQL hex literals", transformCase("SQL_HEX_DECODE", "id=0x61646d696e", "admin"), true);
check("REPLACE_COMMENTS strips SQL comments", transformCase("REPLACE_COMMENTS", "un/*x*/ion", "un ion"), true);
check("ESCAPE_SEQ_DECODE decodes \\x escapes", transformCase("ESCAPE_SEQ_DECODE", "q=\\x3cscript", "<script"), true);
check("JS_DECODE decodes \\u escapes", transformCase("JS_DECODE", "q=\\u003cscript", "<script"), true);
check("CSS_DECODE decodes CSS escapes", transformCase("CSS_DECODE", "q=\\3c script", "<script"), true);
check("URL_DECODE_UNI decodes %uXXXX", transformCase("URL_DECODE_UNI", "q=%u003cscript", "<script"), true);
check("REPLACE_NULLS swaps NUL for a space", transformCase("REPLACE_NULLS", "se\x00lect", "se lect"), true);
check(
  "REMOVE_NULLS strips null bytes",
  transformCase("REMOVE_NULLS", "se\x00le\x00ct", "select"),
  true,
);
check(
  "NORMALIZE_PATH collapses traversal",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "NORMALIZE_PATH" }]), {
    ...REQ,
    path: "/v1/a/../user",
  }),
  true,
);
check(
  "NORMALIZE_PATH_WIN folds backslashes first",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "NORMALIZE_PATH_WIN" }]), {
    ...REQ,
    path: "\\v1\\a\\..\\user",
  }),
  true,
);
check(
  "CMD_LINE normalizes command punctuation",
  transformCase("CMD_LINE", "cat    /etc/passwd", "cat /etc/passwd"),
  true,
);

// --- The base64 SearchString warning fires on blobs, not on ordinary words ---
const searchNote = (s) => {
  const c = ctx();
  evalStatement(byteMatch(s, URI, "CONTAINS"), REQ, c);
  return [...c.notes].some((n) => n.includes("base64"));
};
check("a base64 blob is flagged", searchNote("L3dwLWxvZ2lu"), true);
check("an ordinary lowercase word is not flagged", searchNote("gobuster"), false);
check("a short word is not flagged", searchNote("nmap"), false);
check("a URI path is not flagged", searchNote("/admin/login"), false);

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

// --- GeoMatchStatement ---
const geo = (codes) => ({ GeoMatchStatement: { CountryCodes: codes } });
check("GeoMatch hit on country", ev(geo(["KR", "JP"])), true);
check("GeoMatch miss on country", ev(geo(["US", "CN"])), false);
check("GeoMatch is case-insensitive", ev(geo(["kr"])), true);
check("GeoMatch with empty codes is UNKNOWN", ev(geo([])), "UNKNOWN");

// --- IPSetReferenceStatement ---
check("ipInCidr matches inside the prefix", ipInCidr("10.0.2.88", "10.0.0.0/8"), true);
check("ipInCidr rejects outside the prefix", ipInCidr("11.0.2.88", "10.0.0.0/8"), false);
check("ipInCidr handles /32", ipInCidr("10.0.2.88", "10.0.2.88/32"), true);
check("ipInCidr handles IPv6", ipInCidr("2001:db8::5", "2001:db8::/32"), true);
check("ipInCidr rejects a different IPv6 prefix", ipInCidr("2001:db9::5", "2001:db8::/32"), false);

check(
  "an IP set with inline Addresses is evaluated",
  ev({ IPSetReferenceStatement: { ARN: "arn:x", Addresses: ["10.0.0.0/8"] } }),
  true,
);
check(
  "an IP set that does not contain the IP misses",
  ev({ IPSetReferenceStatement: { ARN: "arn:x", Addresses: ["203.0.113.0/24"] } }),
  false,
);
check("an IP set resolved from the context is evaluated", (() => {
  const c = newEvalContext({ ipSets: new Map([["office-ips", ["10.0.2.0/24"]]]) });
  return evalStatement(
    { IPSetReferenceStatement: { ARN: "arn:aws:wafv2:us-east-1:1:global/ipset/office-ips/abc" } },
    REQ,
    c,
  );
})(), true);
check(
  "an unresolvable IP set is UNKNOWN and named",
  (() => {
    const c = ctx();
    const v = evalStatement({ IPSetReferenceStatement: { ARN: "arn:unknown" } }, REQ, c);
    return [v, [...c.unsupported]];
  })(),
  ["UNKNOWN", ["IPSetReferenceStatement"]],
);
check(
  "IPSetForwardedIPConfig reads the forwarded header",
  ev(
    {
      IPSetReferenceStatement: {
        ARN: "arn:x",
        Addresses: ["203.0.113.0/24"],
        IPSetForwardedIPConfig: { HeaderName: "X-Forwarded-For", FallbackBehavior: "NO_MATCH", Position: "FIRST" },
      },
    },
    { ...REQ, headers: { "x-forwarded-for": "203.0.113.9, 10.0.0.1" } },
  ),
  true,
);

// --- RegexPatternSetReferenceStatement ---
check(
  "a regex pattern set with inline strings is evaluated",
  ev({
    RegexPatternSetReferenceStatement: {
      ARN: "arn:x",
      RegexStrings: ["^/admin", "^/v1/user$"],
      FieldToMatch: URI,
      TextTransformations: [{ Priority: 0, Type: "NONE" }],
    },
  }),
  true,
);
check(
  "an unresolvable regex pattern set is UNKNOWN",
  ev({
    RegexPatternSetReferenceStatement: {
      ARN: "arn:x",
      FieldToMatch: URI,
      TextTransformations: [{ Priority: 0, Type: "NONE" }],
    },
  }),
  "UNKNOWN",
);

// --- Sqli / Xss are approximated locally rather than left unknown ---
const sqli = (field = { QueryString: {} }, transforms = [{ Priority: 0, Type: "URL_DECODE" }]) => ({
  SqliMatchStatement: { FieldToMatch: field, TextTransformations: transforms, SensitivityLevel: "LOW" },
});
check("SQLi payload is detected", ev(sqli(), { ...REQ, query: "id=1%20OR%201=1" }), true);
check("a UNION SELECT body is detected", ev(sqli({ Body: {} }, [{ Priority: 0, Type: "NONE" }]), { ...REQ, body: "a' UNION SELECT pw FROM users--" }), true);
check("an ordinary query is not SQLi", ev(sqli()), false);
check("SqliMatchStatement is reported as an approximation", (() => {
  const c = ctx();
  evalStatement(sqli(), REQ, c);
  return [...c.approximated];
})(), ["SqliMatchStatement"]);

const xss = { XssMatchStatement: { FieldToMatch: { QueryString: {} }, TextTransformations: [{ Priority: 0, Type: "URL_DECODE" }] } };
check("XSS payload is detected", ev(xss, { ...REQ, query: "q=%3Cscript%3Ealert(1)%3C/script%3E" }), true);
check("an ordinary query is not XSS", ev(xss), false);

// --- RateBasedStatement: scope-down is evaluated, volume is not ---
check(
  "a rate rule with no scope-down matches every request",
  ev({ RateBasedStatement: { Limit: 2000, AggregateKeyType: "IP" } }),
  true,
);
check(
  "a rate rule honours its scope-down",
  ev({
    RateBasedStatement: { Limit: 2000, AggregateKeyType: "IP", ScopeDownStatement: byteMatch("/admin", URI, "STARTS_WITH") },
  }),
  false,
);
check("RateBasedStatement is reported as an approximation", (() => {
  const c = ctx();
  evalStatement({ RateBasedStatement: { Limit: 100, AggregateKeyType: "IP" } }, REQ, c);
  return [...c.approximated];
})(), ["RateBasedStatement"]);

// --- LabelMatchStatement ---
check(
  "a label on the request matches",
  ev({ LabelMatchStatement: { Scope: "LABEL", Key: "awswaf:managed:aws:core-rule-set:NoUserAgent_Header" } }, {
    ...REQ,
    labels: ["awswaf:managed:aws:core-rule-set:NoUserAgent_Header"],
  }),
  true,
);
check(
  "NAMESPACE scope matches by prefix",
  ev({ LabelMatchStatement: { Scope: "NAMESPACE", Key: "awswaf:managed:aws:core-rule-set:" } }, {
    ...REQ,
    labels: ["awswaf:managed:aws:core-rule-set:NoUserAgent_Header"],
  }),
  true,
);
check(
  "no labels at all is a miss, not UNKNOWN",
  ev({ LabelMatchStatement: { Scope: "NAMESPACE", Key: "awswaf:managed:" } }),
  false,
);

// --- ManagedRuleGroupStatement is approximated ---
const managed = (name, extra = {}) => ({
  ManagedRuleGroupStatement: { VendorName: "AWS", Name: name, ...extra },
});
check(
  "KnownBadInputs catches a Log4Shell UA",
  ev(managed("AWSManagedRulesKnownBadInputsRuleSet"), { ...REQ, userAgent: "${jndi:ldap://x/a}" }),
  true,
);
check(
  "KnownBadInputs leaves ordinary traffic alone",
  ev(managed("AWSManagedRulesKnownBadInputsRuleSet")),
  false,
);
check(
  "CommonRuleSet catches a missing User-Agent",
  ev(managed("AWSManagedRulesCommonRuleSet"), { ...REQ, userAgent: "" }),
  true,
);
check(
  "CommonRuleSet catches path traversal",
  ev(managed("AWSManagedRulesCommonRuleSet"), { ...REQ, path: "/v1/../../etc/passwd" }),
  true,
);
check(
  "an excluded sub-rule stops matching",
  ev(
    managed("AWSManagedRulesCommonRuleSet", { ExcludedRules: [{ Name: "NoUserAgent_HEADER" }] }),
    { ...REQ, userAgent: "" },
  ),
  false,
);
check(
  "a managed group honours its scope-down",
  ev(
    managed("AWSManagedRulesCommonRuleSet", { ScopeDownStatement: byteMatch("/admin", URI, "STARTS_WITH") }),
    { ...REQ, userAgent: "" },
  ),
  false,
);
check(
  "SQLi rule set catches an injected argument",
  ev(managed("AWSManagedRulesSQLiRuleSet"), { ...REQ, query: "id=1%20UNION%20SELECT%20pw%20FROM%20users" }),
  true,
);
check(
  "the IP reputation list is a definite miss for private space",
  ev(managed("AWSManagedRulesAmazonIpReputationList")),
  false,
);
check(
  "the IP reputation list is UNKNOWN for a public IP",
  ev(managed("AWSManagedRulesAmazonIpReputationList"), { ...REQ, ip: "203.0.113.9" }),
  "UNKNOWN",
);
check(
  "an unknown managed group is UNKNOWN and named",
  (() => {
    const c = ctx();
    const v = evalStatement(managed("AWSManagedRulesMadeUpRuleSet"), REQ, c);
    return [v, [...c.unsupported]];
  })(),
  ["UNKNOWN", ["ManagedRuleGroupStatement(AWSManagedRulesMadeUpRuleSet)"]],
);
check(
  "a third-party managed group is UNKNOWN",
  ev({ ManagedRuleGroupStatement: { VendorName: "Fortinet", Name: "all_rules" } }),
  "UNKNOWN",
);

// --- RuleGroupReferenceStatement ---
check(
  "an inline rule group is evaluated",
  ev({
    RuleGroupReferenceStatement: {
      ARN: "arn:x",
      Rules: [{ Name: "a", Statement: byteMatch("/admin", URI, "STARTS_WITH") }, { Name: "b", Statement: byteMatch("/v1/", URI, "STARTS_WITH") }],
    },
  }),
  true,
);
check(
  "a rule group with no inline rules is UNKNOWN",
  ev({ RuleGroupReferenceStatement: { ARN: "arn:x" } }),
  "UNKNOWN",
);

// --- Three-valued And / Or / Not ---
const T = byteMatch("/v1/", URI, "STARTS_WITH");
const F = byteMatch("/admin", URI, "STARTS_WITH");
const U = { IPSetReferenceStatement: { ARN: "arn:unresolvable" } };

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

// --- What is still out of reach stays UNKNOWN and is reported by name ---
const unsupported = [
  ["ASNMatchStatement", { ASNMatchStatement: { AsnList: [64512] } }],
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
