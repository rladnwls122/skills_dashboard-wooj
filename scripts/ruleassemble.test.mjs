// The pattern conventions the assembled rules depend on: lowercase-only
// patterns (a LOWERCASE transform runs first), escaped literals, one regex per
// line, RE2 syntax, and no served path ever turned into a block pattern.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const {
  assembleRule,
  escapeLiteral,
  pathPattern,
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

const summary = (byPath = [], byUa = []) => ({
  totalSampled: 1000,
  windowLabel: "15m",
  source: "test",
  byPath,
  byIp: [],
  byUa,
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

// --- path patterns ---
check("path anchors and bounds the segment", pathPattern("/admin"), "^\\/admin(/|$)");
check("path is lowercased", pathPattern("/Admin/Panel"), "^\\/admin\\/panel(/|$)");
check("query string is dropped", pathPattern("/x?a=1"), "^\\/x(/|$)");
check("trailing slash is dropped", pathPattern("/admin/"), "^\\/admin(/|$)");

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
check("sqli blocks", sqli.ruleJson.includes('"Block"'), true);
check("sqli decodes html entities before matching", sqli.ruleJson.includes("HTML_ENTITY_DECODE"), true);

const sqliMatches = (q) => sqli.patterns.some((s) => new RegExp(s).test(q));
check("union select is caught", sqliMatches("id=1 union select password from users"), true);
check("or 1=1 is caught", sqliMatches("id=1 or 1=1"), true);
check("sleep() is caught", sqliMatches("id=1;sleep(5)"), true);
check("ordinary query is not caught", sqliMatches("id=3&name=kim&sort=asc"), false);
check("a word containing 'or' is not caught", sqliMatches("color=red&order=1"), false);

// --- path: off-surface only ---
const paths = assembleRule(
  "path",
  summary([p("/wp-login.php"), p("/v1/user", 900, false), p("/healthcheck", 400, false), p("/.env")]),
);
check("served path is never patterned", paths.patterns.some((s) => s.includes("v1")), false);
check("health check is never patterned", paths.patterns.some((s) => s.includes("healthcheck")), false);
check("off-surface paths are patterned", paths.patterns.length, 2);
check("path patterns carry no uppercase", noUppercase(paths.patterns), true);
// A path list is a sample, so it instruments rather than blocks.
check("path rule counts rather than blocks", paths.ruleJson.includes('"Count"'), true);

const pathMatches = (path) => paths.patterns.some((s) => new RegExp(s).test(path));
check("the observed path matches", pathMatches("/wp-login.php"), true);
check("a subpath matches", pathMatches("/.env/x"), true);
check("a prefix-sharing path does not match", pathMatches("/wp-login.php.bak"), false);
check("a served path does not match", pathMatches("/v1/user"), false);

let threw = null;
try {
  assembleRule("path", summary([p("/v1/user", 900, false)]));
} catch (e) {
  threw = e.message;
}
check("no off-surface path is an error, not an empty rule", threw !== null, true);

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

// A served-path prefix must not launder a traversal: NORMALIZE_PATH resolves it
// before the served/off-surface decision, so the pattern describes the target.
const traversal = assembleRule("path", summary([p("/v1/image/../../etc/passwd")]));
check("traversal under a served prefix is still patterned", traversal.patterns, ["^\\/etc\\/passwd(/|$)"]);
check(
  "the evidence shows the resolved path",
  traversal.evidence[0]?.includes("→ /etc/passwd"),
  true,
);

// Image delivery is normal traffic here, and it arrives under more than one
// shape — through the API and as static assets. A rule built against either
// blocks the traffic the score depends on, so neither may become a pattern.
const withImages = assembleRule(
  "path",
  summary([p("/images/product-1.png"), p("/v1/image/42"), p("/IMAGES/x.PNG"), p("/wp-login.php")]),
);
check("image 경로는 패턴이 되지 않음", withImages.patterns, ["^\\/wp-login\\.php(/|$)"]);
check(
  "근거에도 image 경로가 남지 않음",
  withImages.evidence.some((e) => e.toLowerCase().includes("image")),
  false,
);
// The traversal case must still win: the resolved target is what decides, so a
// served image prefix cannot smuggle one through.
check(
  "image 접두어를 단 traversal 은 그대로 걸린다",
  assembleRule("path", summary([p("/v1/image/../../etc/passwd")])).patterns,
  ["^\\/etc\\/passwd(/|$)"],
);
let noneLeft = null;
try {
  assembleRule("path", summary([p("/images/a.png")]));
} catch (e) {
  noneLeft = e.message;
}
check("image 경로만 있으면 만들 대상이 없다고 알린다", noneLeft !== null, true);

// Query-string-only SQLi misses the POST body, which is where an injection
// usually sits once a form is involved.
const sqliStmt = JSON.parse(sqli.ruleJson).Statement;
check(
  "sqli inspects both the query string and the body",
  sqliStmt.OrStatement.Statements.map((s) => Object.keys(s.RegexPatternSetReferenceStatement.FieldToMatch)[0]),
  ["QueryString", "Body"],
);
check(
  "both fields share one pattern set",
  new Set(sqliStmt.OrStatement.Statements.map((s) => s.RegexPatternSetReferenceStatement.ARN)).size,
  1,
);

// --- the rule JSON the sandbox has to be able to read back ---
check("세트는 규칙과 별개 산출물로 나옴", sqli.sets.length, 1);
check("세트 생성 CLI 에 스코프가 들어감", sqli.sets[0].createCli.includes("--scope"), true);
check(
  "transform priorities are 0..n in order",
  sqliStmt.OrStatement.Statements[0].RegexPatternSetReferenceStatement.TextTransformations.map(
    (t) => t.Priority,
  ),
  [0, 1, 2, 3],
);
// A single-field kind stays a bare statement rather than a one-armed Or.
check(
  "a single-field rule is not wrapped in OrStatement",
  JSON.parse(uas.ruleJson).Statement.RegexPatternSetReferenceStatement !== undefined,
  true,
);

// --- the written standard, enforced over every rule this module can emit ---
// Each check below is one of the conventions the patterns are written to, so a
// future edit that breaks one fails here instead of at the WAF console.
const everyRule = [
  ["sqli", sqli],
  ["ua", uas],
  ["path", paths],
  ["ua-spoofed", spoofed],
  ["path-traversal", traversal],
  // Enough off-surface paths to need more than one pattern set.
  ["path-many", assembleRule("path", summary(
    Array.from({ length: 23 }, (_, i) => p(`/probe-${i}`, 100 - i)),
  ))],
];

for (const [label, rule] of everyRule) {
  const sets = rule.sets.map((s) => s.patterns);
  const stmt = JSON.parse(rule.ruleJson).Statement;
  const refs = stmt.OrStatement ? stmt.OrStatement.Statements : [stmt];

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
  // The sandbox copy is the opposite: patterns inline, referenced by name, so a
  // rule can be judged before the set exists.
  const sandbox = JSON.parse(rule.sandboxRuleJson);
  const sbStmt = sandbox.Rules[0].Statement;
  const sbRefs = sbStmt.OrStatement ? sbStmt.OrStatement.Statements : [sbStmt];
  check(`[${label}] 샌드박스용은 패턴을 인라인으로 담음`,
    Object.keys(sandbox.RegexPatternSets).length, rule.sets.length);
  check(`[${label}] 샌드박스용은 이름으로 참조`,
    sbRefs.every((r) => sandbox.RegexPatternSets[r.RegexPatternSetReferenceStatement.ARN] !== undefined),
    true);
  // Creating the set is the operator's step, so the command must be shown.
  check(`[${label}] 세트마다 생성 CLI 가 있음`,
    rule.sets.every((s) => s.createCli.includes("create-regex-pattern-set") && s.createCli.includes(s.name)),
    true);
}

// Splitting must add sets rather than drop patterns.
const many = everyRule.find(([l]) => l === "path-many")[1];
check("23개 패턴은 버려지지 않음", many.patterns.length, 23);
check("세트 3개로 쪼개짐", many.sets.length, 3);
check("세트 이름이 서로 다름", new Set(many.sets.map((s) => s.name)).size, 3);
check("세트마다 ARN 자리표시자가 다름", new Set(many.sets.map((s) => s.arnPlaceholder)).size, 3);
check("쪼개진 사실이 판단 기준에 적힘",
  many.notes.some((n) => n.includes("세트 3개")), true);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
