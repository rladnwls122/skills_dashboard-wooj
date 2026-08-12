// WAF-log aggregation folds (key, action) rows into one row per key plus a
// blocked subtotal. The grouping is what lets an empty blocked count mean
// "nothing was blocked" rather than "nothing arrived", so the totals must come
// from the full result set, not from the rows that happen to be BLOCK.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { foldByAction, totals, topKeyCounts, rowCount } = await import(`${SRC}waflogagg.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const rows = [
  { path: "/v1/user", action: "ALLOW", cnt: "900" },
  { path: "/v1/user", action: "BLOCK", cnt: "12" },
  { path: "/wp-login.php", action: "BLOCK", cnt: "40" },
  { path: "/health", action: "ALLOW", cnt: "500" },
  { path: "/x", action: "COUNT", cnt: "7" },
];

const folded = foldByAction(rows, "path");
check("both actions on one path fold into one entry", folded.get("/v1/user"), { count: 912, blocked: 12 });
check("an allow-only path has no blocked subtotal", folded.get("/health"), { count: 500, blocked: 0 });
check("a block-only path counts in both", folded.get("/wp-login.php"), { count: 40, blocked: 40 });
// COUNT is a match that was not blocked; folding it into `blocked` would
// overstate what the firewall actually stopped.
check("COUNT is not counted as blocked", folded.get("/x"), { count: 7, blocked: 0 });
check("keys are not duplicated", folded.size, 4);

check("totals span every action, not just blocks", totals(folded), { total: 1459, blockedTotal: 52 });
check("totals of nothing are zero, not NaN", totals(new Map()), { total: 0, blockedTotal: 0 });

// Action casing varies by source; matching only the exact string would silently
// zero the blocked column.
check(
  "lowercase action still folds as a block",
  foldByAction([{ path: "/a", action: "block", cnt: "3" }], "path").get("/a"),
  { count: 3, blocked: 3 },
);

// --- top-N ---
const uaRows = [
  { ua: "curl/8", cnt: "50" },
  { ua: "sqlmap/1.7", cnt: "300" },
  { ua: "", cnt: "999" },
  { ua: "Mozilla/5.0", cnt: "120" },
];
check("top-N sorts by count and drops the empty key", topKeyCounts(uaRows, "ua", 2), [
  { key: "sqlmap/1.7", count: 300 },
  { key: "Mozilla/5.0", count: 120 },
]);
check("asking for more than exists returns what exists", topKeyCounts(uaRows, "ua", 99).length, 3);

// A malformed count must not poison a total.
check("a non-numeric count reads as zero", rowCount({ cnt: "abc" }), 0);
check("a missing count reads as zero", rowCount({}), 0);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
