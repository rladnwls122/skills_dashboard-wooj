// The pattern conventions the assembled rules depend on: lowercase-only
// patterns (a LOWERCASE transform runs first), escaped literals, one regex per
// line, RE2 syntax, and no served path ever turned into a block pattern.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const {
  assembleRule,
  escapeLiteral,
  scopeDownRefusal,
  uaPattern,
  SQLI_PATTERNS,
  MAX_PATTERNS_PER_SET,
  MAX_PATTERN_CHARS,
} = await import(`${SRC}ruleassemble.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const summary = (byPath = [], byUa = [], uaActions = []) => ({
  totalSampled: 1000,
  windowLabel: "15m",
  source: "test",
  byPath,
  byIp: [],
  byUa,
  uaActions,
  byMethod: [],
  queryPatterns: [],
  headerPatterns: [],
  blockedTotal: 0,
  statusDist: null,
  detailedStatus: null,
});
const p = (path, count = 50, suspicious = true) => ({
  path,
  count,
  blocked: 0,
  lowPriority: false,
  suspicious,
});

// --- escaping ---
check("dot is escaped", escapeLiteral("/wp-login.php"), "\\/wp-login\\.php");
check("parens and plus are escaped", escapeLiteral("a(b)+c"), "a\\(b\\)\\+c");
check("brackets are escaped", escapeLiteral("x[1]?"), "x\\[1\\]\\?");

// --- UA patterns ---
check("ua pattern is bounded and lowercase", uaPattern("SQLMap"), "(^|[^a-z0-9])sqlmap([^a-z0-9]|$)");

// A pattern set only ever matches lowercase input, so an uppercase letter in a
// pattern is dead weight that silently never fires.
const noUppercase = (pats) => pats.every((s) => !/[A-Z]/.test(s));
// RE2 rejects POSIX classes; \s+ is the portable spelling.
const noPosixClass = (pats) => pats.every((s) => !s.includes("[[:"));

// --- SQLi: fixed set, independent of traffic ---
const sqli = assembleRule("sqli", summary());
check("sqli needs no observed traffic", sqli.patterns.length, SQLI_PATTERNS.length);
check("sqli patterns carry no uppercase", noUppercase(sqli.patterns), true);
check("sqli patterns use no POSIX class", noPosixClass(sqli.patterns), true);
check("sqli patterns all compile", sqli.patterns.every((s) => { try { new RegExp(s); return true; } catch { return false; } }), true);
check("sqli counts rather than blocks", sqli.ruleJson.includes('"Count"'), true);
check("sqli decodes html entities before matching", sqli.ruleJson.includes("HTML_ENTITY_DECODE"), true);

const sqliMatches = (q) => sqli.patterns.some((s) => new RegExp(s).test(q));
check("union select is caught", sqliMatches("id=1 union select password from users"), true);
check("or 1=1 is caught", sqliMatches("id=1 or 1=1"), true);
check("sleep() is caught", sqliMatches("id=1';sleep(5)"), true);
check("ordinary query is not caught", sqliMatches("id=3&name=kim&sort=asc"), false);
check("a word containing 'or' is not caught", sqliMatches("color=red&order=1"), false);

// The signatures observed in this scenario's own attack traffic, lowercased and
// whitespace-collapsed the way the transforms deliver them.
const attackSamples = [
  "id=1' or '1'='1",
  "id=1 union all select null,null,version()--",
  "id=1'; drop table products; --",
  "email=a@b.c' or 1=1 -- ",
  "id=1 and 1=1",
  "id=-1 union select 1,2,3 from information_schema.tables",
  "id=1'); waitfor delay '0:0:5'--",
  "q=' or ''='",
];
for (const sample of attackSamples) {
  check(`attack sample is caught: ${sample}`, sqliMatches(sample), true);
}

// The benign corpus. This is the regression test for the incident where a
// body-inspecting SQLi rule blocked 12,024 consecutive legitimate PUT
// /v1/product requests: every string below is request text this scenario
// actually produces, and a signature that matches any of them is a signature
// that takes real traffic down. Anything added to SQLI_PATTERNS has to keep
// this list clean.
const benignSamples = [
  // Query strings the load generator sends, verbatim in shape.
  "id=gr200p00000485&requestid=325230325475&uuid=165c5c9b-e26e-49c0-82b8-2c1f5c9b1a2f",
  "email=gr20000001404@example.org&requestid=696625763434&uuid=a0f0cf07-bdf4-4a1e-9f2e-1d0b2b9a77c1",
  "id=seed200p00000044&requestid=593682255061",
  // Product payload text — the field that made the old rule fire.
  '{"name":"select comfort pillow","description":"chosen from our premium range","price":39000}',
  '{"name":"memory foam mattress","description":"deep sleep (8 hours) support","price":250000}',
  '{"name":"drop shoulder tee","description":"insert into your summer wardrobe","price":19000}',
  '{"name":"table lamp","description":"update your desk -- warm light","price":45000}',
  '{"name":"or1 gaming mouse","description":"order now and save","price":58000}',
  '{"description":"select from 12 colors, and 3 sizes"}',
  '{"note":"css block: /* rounded */ and code sample"}',
  // Ordinary reads.
  "page=2&sort=price_desc&category=home",
  "keyword=sleep&limit=20",
];
for (const sample of benignSamples) {
  check(`benign sample is not blocked: ${sample.slice(0, 48)}`, sqliMatches(sample), false);
}

// The field list is part of the false-positive story: the body is where the
// legitimate payload lives, and the observed injections are all in the query
// string.
check("sqli inspects the query string", sqli.ruleJson.includes("QueryString"), true);
check("sqli does not inspect the body", sqli.ruleJson.includes('"Body"'), false);

// --- scope-down: the gate every rule passes through ---
//
// This is the one check whose failure is silent and expensive. A rule without a
// path scope-down fires on undefined paths too, so a request that should have
// reached the ALB and come back 404 gets a 403 from WAF instead — and the
// grader's Exception Handling key drops with nothing on screen saying why.
// Both entry points (the assembler's own output and pasted JSON) go through
// `scopeDownRefusal`, so it is tested against both shapes.
const byteMatch = (path) => ({
  ByteMatchStatement: {
    SearchString: path,
    FieldToMatch: { UriPath: {} },
    PositionalConstraint: "STARTS_WITH",
  },
});
const detection = { RegexPatternSetReferenceStatement: { FieldToMatch: { SingleHeader: {} } } };
const and = (...stmts) => ({ Statement: { AndStatement: { Statements: stmts } } });

check("the assembler's own SQLi rule passes", scopeDownRefusal(JSON.parse(sqli.ruleJson)), null);
check(
  "a served path scopes the rule down",
  scopeDownRefusal(and(byteMatch("/v1/user"), detection)),
  null,
);
check(
  "an Or of served paths also scopes it down",
  scopeDownRefusal(and({ OrStatement: { Statements: [byteMatch("/v1/user"), byteMatch("/v1/stress")] } }, detection)),
  null,
);
check(
  "a pattern set on UriPath is taken at its word",
  scopeDownRefusal(
    and({ RegexPatternSetReferenceStatement: { FieldToMatch: { UriPath: {} } } }, detection),
  ),
  null,
);

const refused = (rule) => scopeDownRefusal(rule) !== null;
check("a bare detection statement is refused", refused({ Statement: detection }), true);
check("an And with no path condition is refused", refused(and(detection, detection)), true);
// The trap: it looks scoped, but /admin is not a path we serve, so the rule
// still fires everywhere the detection matches outside the surface.
check(
  "scoping onto a path we do not serve is not a scope-down",
  refused(and(byteMatch("/admin"), detection)),
  true,
);
check(
  "one unserved path in the Or spoils it",
  refused(and({ OrStatement: { Statements: [byteMatch("/v1/user"), byteMatch("/admin")] } }, detection)),
  true,
);
// A UriPath match is what narrows the rule; the same bytes matched against a
// header narrow nothing.
check(
  "a ByteMatch on some other field is not a path scope",
  refused(
    and(
      { ByteMatchStatement: { SearchString: "/v1/user", FieldToMatch: { SingleHeader: {} } } },
      detection,
    ),
  ),
  true,
);
check("an And of one is not an And", refused(and(byteMatch("/v1/user"))), true);
check("a rule with no Statement is refused", refused({ Name: "r" }), true);
check("garbage is refused", refused("not json"), true);
check("null is refused", refused(null), true);

// --- ua: everything that is not an expected client ---
// The rule covers each observed UA that is not on the allow list, not only the
// ones matching a named tool. A deny list leaves the forged-browser case — the
// one an attacker actually sends — walking straight through.
const uas = assembleRule(
  "ua",
  summary([], [
    { key: "sqlmap/1.7.2", count: 60 },
    { key: "Go-http-client/2.0", count: 900 },
    { key: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120", count: 300 },
    { key: "ELB-HealthChecker/2.0", count: 400 },
    { key: "python-requests/2.31.0", count: 40 },
    { key: "Mozilla/5.0 (compatible)", count: 25 },
    { key: "MyCorpAgent/3.1", count: 10 },
  ]),
);
check("ua patterns carry no uppercase", noUppercase(uas.patterns), true);
check("ua rule blocks", uas.ruleJson.includes('"Block"'), true);
const uaMatches = (ua) => uas.patterns.some((s) => new RegExp(s).test(ua.toLowerCase()));
check("스캐너 UA 가 잡힌다", uaMatches("sqlmap/1.7.2#stable"), true);
check("python-requests 가 잡힌다", uaMatches("python-requests/2.31.0"), true);
check("엔진 없는 Mozilla 위장이 잡힌다", uaMatches("mozilla/5.0 (compatible)"), true);
check("처음 보는 클라이언트가 잡힌다", uaMatches("mycorpagent/3.1"), true);
// The version moved but the rule still fires — the pattern is the product
// token, not the whole string.
check("버전이 올라가도 계속 잡힌다", uaMatches("python-requests/9.99.0"), true);
// And the traffic the score depends on must not be touched.
check("Go 부하생성기는 잡히지 않는다", uaMatches("Go-http-client/2.0"), false);
check("실제 브라우저는 잡히지 않는다", uaMatches("mozilla/5.0 (windows nt 10.0) applewebkit/537.36 chrome/120"), false);
check("ELB 헬스체커는 잡히지 않는다", uaMatches("elb-healthchecker/2.0"), false);
check("이 대시보드의 점검 요청은 잡히지 않는다", uaMatches("skills-dashboard/traffic-check"), false);
check("도구 이름을 품은 다른 이름은 잡히지 않는다", uaMatches("sqlmapper-client/1.0"), false);
// The trap this nearly walked into: "Mozilla/5.0 (compatible)" leads with the
// same token every real browser does, so matching on the token would have taken
// the whole site down. Browser-ish tokens are matched as the whole string.
check(
  "위장 Mozilla 는 전체 문자열로 고정된다",
  uas.patterns.some((s) => s === String.raw`^mozilla\/5\.0 \(compatible\)$`),
  true,
);
check("mozilla 토큰만으로는 패턴을 만들지 않는다", uaMatches("mozilla/5.0 (macintosh) applewebkit/605 safari/605"), false);
// Empty UA needs ^$ — a literal pattern built from an empty token would match
// every request instead.
const emptyUa = assembleRule("ua", summary([], [{ key: "(empty UA)", count: 30 }]));
check("빈 UA 는 ^$ 로 잡는다", emptyUa.patterns, ["^$"]);
check("빈 UA 패턴이 아무 UA 나 잡지는 않는다", new RegExp(emptyUa.patterns[0]).test("curl/8.4.0"), false);

let uaThrew = null;
try {
  assembleRule("ua", summary([], [
    { key: "Mozilla/5.0 Chrome/120 AppleWebKit/537.36", count: 900 },
    { key: "Go-http-client/2.0", count: 500 },
  ]));
} catch (e) {
  uaThrew = e.message;
}
check("정상 클라이언트뿐이면 빈 규칙이 아니라 오류", uaThrew !== null, true);
// "Nothing suspicious was seen" and "nothing was seen at all" send the operator
// to different places, so the two must not share a message. The second is the
// live state of this environment: WAF samples only rule matches, and the app
// log carries no user_agent field.
let emptyThrew = null;
try {
  assembleRule("ua", summary([], []));
} catch (e) {
  emptyThrew = e.message;
}
check("UA 통계가 비면 수집 문제라고 말한다", emptyThrew?.includes("WAF_LOG_GROUP"), true);
check("정상뿐인 경우와 다른 메시지", emptyThrew !== uaThrew, true);

// --- the false-positive gate ---
//
// The incident this encodes: this scenario's load generator rotates generic
// client User-Agents (curl, wget, python-requests, okhttp, axios, Postman,
// Apache-HttpClient), each carrying thousands of allowed /v1/* requests. Every
// one of them classifies as AUTOMATION and would become a Block pattern on name
// alone. The measured verdict split is what tells them apart from a scanner, so
// a UA with live allowed traffic must never reach the pattern set.
const gated = assembleRule(
  "ua",
  summary(
    [],
    [
      { key: "curl/8.7.1", count: 6141 },
      { key: "python-requests/2.32.3", count: 5943 },
      { key: "sqlmap/1.8.5#stable (https://sqlmap.org)", count: 123 },
    ],
    [
      { key: "curl/8.7.1", allowed: 6141, blocked: 309 },
      { key: "python-requests/2.32.3", allowed: 5943, blocked: 346 },
      { key: "sqlmap/1.8.5#stable (https://sqlmap.org)", allowed: 2, blocked: 640 },
    ],
  ),
);
const gatedMatches = (ua) => gated.patterns.some((s) => new RegExp(s).test(ua.toLowerCase()));
check("정상 통과 중인 curl 은 패턴이 되지 않는다", gatedMatches("curl/8.7.1"), false);
check("정상 통과 중인 python-requests 도 제외된다", gatedMatches("python-requests/2.32.3"), false);
check("실제 공격 도구는 그대로 잡는다", gatedMatches("sqlmap/1.8.5#stable"), true);
check(
  "제외 사유가 근거에 남는다",
  gated.notes.some((n) => n.includes("오탐 가드로 제외된 후보")),
  true,
);
// With no verdict data (sampled-requests mode) the gate cannot run, and the old
// behaviour stands — the note on screen is what says the check was unavailable.
const ungated = assembleRule("ua", summary([], [{ key: "curl/8.7.1", count: 6141 }]));
check("검증 데이터가 없으면 종전대로 패턴화된다", ungated.patterns.length > 0, true);

// Everything allowed → refusing to build is the correct answer, and it must say
// why rather than emitting an empty rule.
let allAllowedThrew = null;
try {
  assembleRule(
    "ua",
    summary(
      [],
      [{ key: "curl/8.7.1", count: 6141 }],
      [{ key: "curl/8.7.1", allowed: 6141, blocked: 0 }],
    ),
  );
} catch (e) {
  allAllowedThrew = e.message;
}
check("전부 정상 통과면 규칙을 만들지 않고 이유를 말한다", allAllowedThrew?.includes("정상 통과"), true);

// A SPOOFED classification's label ("injection-in-ua", "base64-ua") is a
// category name, not text found in the UA. Turning it into a literal builds a
// rule that matches nothing, so those must come out as real regexes.
const spoofed = assembleRule(
  "ua",
  summary([], [
    { key: "${jndi:ldap://x/a}", count: 40 },
    { key: "Z2V0fHBvc3RfZGF0YV9leGZpbGw=", count: 20 },
  ]),
);
check(
  "a spoofed label never becomes a literal pattern",
  spoofed.patterns.some((s) => s.includes("injection-in-ua") || s.includes("base64-ua")),
  false,
);
const spoofedMatches = (ua) => spoofed.patterns.some((s) => new RegExp(s).test(ua.toLowerCase()));
check("the jndi UA it was built from is matched", spoofedMatches("${jndi:ldap://x/a}"), true);
check("the base64 UA it was built from is matched", spoofedMatches("Z2V0fHBvc3RfZGF0YV9leGZpbGw="), true);
check("a real browser UA is not matched", spoofedMatches(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120",
), false);

// Every rule is now AND(path scope-down, detection), so the detection half has
// to be unwrapped before the field/transform conventions can be read off it.
const detectionOf = (rule) => {
  const and = JSON.parse(rule.ruleJson).Statement.AndStatement.Statements;
  return and[1];
};

// Query string only. Adding the body back would put every legitimate PUT
// payload in front of these signatures again — the shape of the outage this
// rule caused — while the injections observed here all ride in the query
// string, which the managed SQLi group flags as SQLi_QUERYARGUMENTS too.
const sqliStmt = detectionOf(sqli);
check(
  "sqli inspects the query string alone",
  Object.keys(sqliStmt.RegexPatternSetReferenceStatement.FieldToMatch),
  ["QueryString"],
);

// --- the rule JSON the sandbox has to be able to read back ---
check("세트는 규칙과 별개 산출물로 나옴", sqli.sets.length, 1);
check("세트 생성 CLI 에 스코프가 들어감", sqli.sets[0].createCli.includes("--scope"), true);
check(
  "transform priorities are 0..n in order",
  sqliStmt.RegexPatternSetReferenceStatement.TextTransformations.map((t) => t.Priority),
  [0, 1, 2, 3],
);
// A single-field kind stays a bare statement rather than a one-armed Or.
check(
  "a single-field rule is not wrapped in OrStatement",
  detectionOf(uas).RegexPatternSetReferenceStatement !== undefined,
  true,
);

// --- the written standard, enforced over every rule this module can emit ---
// Each check below is one of the conventions the patterns are written to, so a
// future edit that breaks one fails here instead of at the WAF console.
const everyRule = [
  ["sqli", sqli],
  ["ua", uas],
  ["ua-spoofed", spoofed],
  // Enough distinct User-Agents to need more than one pattern set.
  ["ua-many", assembleRule("ua", summary([], Array.from({ length: 23 }, (_, i) => ({
    key: `scanner-${i}/1.0`,
    count: 100 - i,
  }))))],
];

for (const [label, rule] of everyRule) {
  const sets = rule.sets.map((s) => s.patterns);
  const stmt = detectionOf(rule);
  const refs = stmt.OrStatement ? stmt.OrStatement.Statements : [stmt];

  // 0. Detection is never allowed to stand alone: without the path AND, a
  //    malicious UA on an undefined path is answered 403 by the WAF instead of
  //    404 by the ALB, and Exception Handling drops for it (04).
  check(`[${label}] 스코프다운 통과`, scopeDownRefusal(JSON.parse(rule.ruleJson)), null);

  // 1. LOWERCASE runs first, so an uppercase letter could never match.
  check(`[${label}] 패턴에 대문자 없음`, rule.patterns.every((s) => !/[A-Z]/.test(s)), true);
  // 2. RE2: no POSIX classes, and every pattern must actually compile.
  check(`[${label}] POSIX 클래스 없음`, rule.patterns.every((s) => !s.includes("[[:")), true);
  check(`[${label}] 전부 컴파일됨`, rule.patterns.every((s) => {
    try { new RegExp(s); return true; } catch { return false; }
  }), true);
  // 3. Decoding transforms run before the match, and LOWERCASE runs last so the
  //    decoded output is what gets folded.
  for (const ref of refs) {
    const t = ref.RegexPatternSetReferenceStatement.TextTransformations;
    check(`[${label}] 변환 Priority 가 0..n 연속`, t.map((x) => x.Priority), t.map((_, i) => i));
    check(`[${label}] URL_DECODE 가 맨 앞`, t[0].Type, "URL_DECODE");
    check(`[${label}] LOWERCASE 가 맨 뒤`, t[t.length - 1].Type, "LOWERCASE");
    check(`[${label}] 변환 10개 한도 이내`, t.length <= 10, true);
  }
  // 4. AWS fixed quotas: 10 patterns per set, 200 chars per pattern.
  check(`[${label}] 세트당 정규식 ${MAX_PATTERNS_PER_SET}개 이하`,
    sets.every((s) => s.length <= MAX_PATTERNS_PER_SET), true);
  check(`[${label}] 정규식 ${MAX_PATTERN_CHARS}자 이하`,
    rule.patterns.every((s) => s.length <= MAX_PATTERN_CHARS), true);
  // Every emitted pattern belongs to exactly one set, and every referenced set
  // exists — a split must not lose or duplicate a pattern.
  check(`[${label}] 패턴이 전부 세트에 담김`, sets.flat().length, rule.patterns.length);
  // The console rule must reference an ARN placeholder, never a bare set name:
  // AWS rejects a name in the ARN field, and it would fail only after the
  // operator pasted it.
  const names = new Set(rule.sets.map((s) => s.name));
  check(`[${label}] ARN 자리에 세트 이름이 들어가지 않음`,
    refs.some((r) => names.has(r.RegexPatternSetReferenceStatement.ARN)), false);
  check(`[${label}] 모든 ARN 이 자리표시자`,
    refs.every((r) => rule.sets.some((s) => s.arnPlaceholder === r.RegexPatternSetReferenceStatement.ARN)),
    true);
  check(`[${label}] 콘솔용 규칙에는 패턴이 인라인되지 않음`,
    JSON.parse(rule.ruleJson).RegexPatternSets, undefined);
  // Creating the set is the operator's step, so the command must be shown.
  check(`[${label}] 세트마다 생성 CLI 가 있음`,
    rule.sets.every((s) => s.createCli.includes("create-regex-pattern-set") && s.createCli.includes(s.name)),
    true);
}

// Splitting must add sets rather than drop patterns.
const many = everyRule.find(([l]) => l === "ua-many")[1];
check("23개 패턴은 버려지지 않음", many.patterns.length, 23);
check("세트 3개로 쪼개짐", many.sets.length, 3);
check("세트 이름이 서로 다름", new Set(many.sets.map((s) => s.name)).size, 3);
check("세트마다 ARN 자리표시자가 다름", new Set(many.sets.map((s) => s.arnPlaceholder)).size, 3);
check("쪼개진 사실이 판단 기준에 적힘",
  many.notes.some((n) => n.includes("세트 3개")), true);

// Both generated cards can be pasted into one WebACL: AWS rejects duplicate
// rule priorities before evaluating the statements.
check(
  "UA와 SQLi 규칙의 Priority 가 서로 다름",
  new Set([sqli, uas].map((rule) => JSON.parse(rule.ruleJson).Priority)).size,
  2,
);

console.log(failures === 0 ? "\nALL PASS" : `${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
