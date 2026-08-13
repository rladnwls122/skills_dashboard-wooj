// The promotion decision rests on this join. Two things are easy to get wrong
// and expensive when wrong: filtering COUNT matches on `action` (which never
// says COUNT), and folding requests with no join key into the "abnormal" pile,
// which would make an untested rule look safe to promote.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { buildCountQuery, buildJoinQuery, extractRequestId, verdictFor, summarize, promotionNote } =
  await import(`${SRC}wafcountevidence.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};
const has = (name, haystack, needle) => check(name, haystack.includes(needle), true);
const lacks = (name, haystack, needle) => check(name, haystack.includes(needle), false);

// --- the count query -------------------------------------------------------

const q = buildCountQuery("block-suspicious-ua");
has("matches the rule id inside the message", q, '/"ruleId":"block-suspicious-ua"/');
has("excludes requests another rule terminated", q, 'filter action != "BLOCK"');
lacks("never filters on action = COUNT, which matches nothing", q, 'action = "COUNT"');
has("bounds the result set", q, "limit 500");

has(
  "a rule name with regex characters is escaped",
  buildCountQuery("rule.v1+beta"),
  '/"ruleId":"rule\\.v1\\+beta"/',
);

// --- the join query --------------------------------------------------------

const j = buildJoinQuery(["abc", "def"]);
has("parses the app log's JSON envelope", j, "parse log");
has("filters on the id list", j, 'filter requestid in ["abc", "def"]');
has("limits explicitly, because Insights truncates at 10k silently", j, "limit 2");
check(
  "a quote in an id cannot break out of the list",
  buildJoinQuery(['a"b']).includes('["ab"]'),
  true,
);

// --- the join key ----------------------------------------------------------

check("reads requestid from the query string", extractRequestId("?requestid=r1&x=2"), "r1");
check("works without the leading question mark", extractRequestId("requestid=r1"), "r1");
check("falls back to uuid", extractRequestId("?uuid=u1"), "u1");
check("prefers whichever comes first", extractRequestId("?uuid=u1&requestid=r1"), "u1");
check("percent escapes are decoded", extractRequestId("?requestid=a%2Db"), "a-b");
check("a broken escape is still a usable key", extractRequestId("?requestid=a%zz"), "a%zz");
check("an empty value is not a key", extractRequestId("?requestid="), null);
check("no query string means no key", extractRequestId(""), null);
check("an unrelated query string means no key", extractRequestId("?page=2"), null);

// --- classification --------------------------------------------------------

check("a served request is normal", verdictFor(200), "normal");
check("a 204 is still served", verdictFor(204), "normal");
check("a 404 is not evidence of a false block", verdictFor(404), "abnormal");
check("a 500 is not either", verdictFor(500), "abnormal");
check("no application row means unjoinable, not abnormal", verdictFor(null), "unjoinable");

const m = (verdict) => ({ verdict });
const s = summarize("r", [m("normal"), m("abnormal"), m("abnormal"), m("unjoinable")]);
check("the three buckets are counted separately", [s.total, s.normal, s.abnormal, s.unjoinable], [
  4, 1, 2, 1,
]);

// --- the advisory note -----------------------------------------------------

has(
  "one legitimate request is enough to warn",
  promotionNote({ total: 40, normal: 1 }),
  "403이 나갑니다",
);
has("a thin sample says so", promotionNote({ total: 5, normal: 0 }), "표본 부족");
has("a clean sample clears the rule", promotionNote({ total: 40, normal: 0 }), "정상 응답 0건");

console.log(failures === 0 ? "\nall passed" : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
