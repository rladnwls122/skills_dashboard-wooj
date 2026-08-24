import assert from "node:assert/strict";
import test from "node:test";

import {
  apiOf,
  buildGradingPanel,
  buildGradingQuery,
  isImagePath,
  type GradingParams,
  type PathRow,
} from "./grading.ts";
import type { GradingPanel, GradingScore, ResolvedWindow } from "../../src/lib/types.ts";

const WINDOW: ResolvedWindow = {
  windowMin: 60,
  intervalMin: 1,
  startMs: 0,
  endMs: 3_600_000,
  buckets: 60,
  label: "60m",
};

function lineByLabel(p: GradingPanel, label: string): GradingScore {
  return (
    p.lines.find((l) => l.label === label) ?? {
      label: "(missing) " + label,
      pct: 0,
      okCount: -1,
      total: -1,
      source: "",
      approximate: false,
    }
  );
}

const row = (over: Partial<PathRow> & { path: string }): PathRow => ({
  total: 0,
  availOk: 0,
  fastOk: 0,
  slowOk: 0,
  notFound: 0,
  forbidden: 0,
  serverErr: 0,
  ...over,
});

// The keys are the ones the grader's own results_<비번호>.log carries — image
// download, Exception Handling, (api) availability, (api) performance — because
// the operator reads the two side by side and a renamed key costs them the
// comparison. Each is fed from the source that can actually see it.
test("the panel carries every scoring key, from the source that sees it", () => {
  const params: GradingParams = {
    rows: [
      // 100 user requests: 90 served fast, 5 served slow (>200ms but <5s), 3 app 403 (duplicate), 2 500.
      row({ path: "/v1/user", total: 100, availOk: 95, fastOk: 90, slowOk: 95, forbidden: 3, serverErr: 2 }),
      row({ path: "/v1/product", total: 50, availOk: 50, fastOk: 50, slowOk: 50 }),
      // stress: 20 served, 15 of them inside 1s; the fast column would undercount it.
      row({ path: "/v1/stress", total: 20, availOk: 20, fastOk: 2, slowOk: 15 }),
      // Image delivery is its own key and must not fall into any API's numbers.
      row({ path: "/images/product50001.jpg", total: 40, availOk: 36, fastOk: 30, slowOk: 34 }),
      row({ path: "/healthcheck", total: 500, availOk: 500, fastOk: 500, slowOk: 500 }),
      // undefined paths the app answered: 8 with 404 (the contract), 2 with 200.
      row({ path: "/v1/none", total: 8, notFound: 8 }),
      row({ path: "/admin", total: 2, availOk: 2, fastOk: 2, slowOk: 2 }),
    ],
    wafAvailable: true,
    wafRows: [
      { uri: "/v1/user", method: "POST", action: "BLOCK", count: 30 },
      { uri: "/v1/product", method: "POST", action: "BLOCK", count: 10 },
      { uri: "/v1/user", method: "GET", action: "ALLOW", count: 1000 },
      { uri: "/.env", method: "GET", action: "BLOCK", count: 5 }, // a 404 that became a 403
      { uri: "/healthcheck", method: "GET", action: "BLOCK", count: 1 },
      // A block on the image surface would cost image download points; it is
      // neither an abnormal-request success nor an undefined-path violation.
      { uri: "/images/x.jpg", method: "GET", action: "BLOCK", count: 7 },
    ],
    trapLeaked: 4,
    window: WINDOW,
  };
  const panel = buildGradingPanel(params);

  const check = (label: string, ok: number, total: number, approx: boolean): void => {
    const l = lineByLabel(panel, label);
    assert.deepEqual(
      { okCount: l.okCount, total: l.total, approximate: l.approximate },
      { okCount: ok, total, approximate: approx },
      label,
    );
    assert.notEqual(l.source, "", `${label}: source must be stated`);
  };

  check("image download", 36, 40, false);
  // Exception Handling: WAF blocks on the served surface (40 — the image block
  // is excluded) plus the 8 undefined paths the app ended as 404. The
  // denominator adds the 4 that leaked to the app, the 2 undefined paths that
  // answered 200, and the 5 undefined paths the WAF wrongly turned into 403.
  check("Exception Handling", 48, 59, true);
  check("(user) availability", 95, 100, false);
  check("(product) availability", 50, 50, false);
  check("(stress) availability", 20, 20, false);
  check("(user) performance ≤ 0.2s", 90, 100, false);
  check("(stress) performance ≤ 1.0s", 15, 20, false);

  assert.equal(panel.lines.length, 8);
  assert.equal(lineByLabel(panel, "(user) availability").pct, 95);

  const joined = panel.notes.join("\n");
  assert.ok(joined.includes("results_"), "notes must name the grader's own log");
  assert.ok(joined.includes("클라이언트 도착 기준"), "notes must state the latency is optimistic");
  assert.ok(joined.includes("4건"), "notes must say how many abnormal requests leaked");
});

// The sheet pays per threshold crossed, so a bare percentage does not tell the
// operator whether the next point is reachable. Each line carries the band it
// has earned and the gap to the next one.
test("each line names the score band it sits in and the gap to the next", () => {
  const panel = buildGradingPanel({
    // 86% availability: past the 85 rung, short of 87.5.
    rows: [row({ path: "/v1/user", total: 100, availOk: 86, fastOk: 86, slowOk: 86 })],
    window: WINDOW,
  });
  const avail = lineByLabel(panel, "(user) availability");
  assert.equal(avail.pct, 86);
  assert.equal(avail.tier, "85% 구간");
  assert.equal(avail.nextTier, "87.5% 까지 1.5%p");

  // Nothing observed: a band would be a claim about data that does not exist.
  const idle = buildGradingPanel({ rows: [], window: WINDOW });
  assert.equal(lineByLabel(idle, "(user) availability").tier, null);
  assert.equal(lineByLabel(idle, "(user) availability").nextTier, null);
});

// 비정상 요청 처리 pays on four rungs, not the eight the availability keys use.
test("the abnormal-request keys use their own shorter ladder", () => {
  const panel = buildGradingPanel({
    rows: [row({ path: "/images/a.jpg", total: 100, availOk: 86 })],
    window: WINDOW,
  });
  const image = lineByLabel(panel, "image download");
  assert.equal(image.pct, 86);
  // 87.5 is not a rung here — the next one up is 90.
  assert.equal(image.tier, "85% 구간");
  assert.equal(image.nextTier, "90% 까지 4%p");
});

// Without a WAF log group the 403 side of Exception Handling is invisible, and
// the panel has to say so rather than show a clean number.
test("without a WAF log group the panel says so", () => {
  const panel = buildGradingPanel({
    rows: [row({ path: "/v1/product", total: 10, availOk: 10, fastOk: 10, slowOk: 10 })],
    trapLeaked: 2,
    window: WINDOW,
  });
  const l = lineByLabel(panel, "Exception Handling");
  assert.equal(l.okCount, 0);
  assert.equal(l.total, 2);
  assert.ok(
    panel.notes.join("\n").includes("WAF_LOG_GROUP"),
    "must tell the operator the WAF log group is missing",
  );
});

test("isImagePath splits the static surface off the API surface", () => {
  assert.ok(isImagePath("/images/product50001.jpg"));
  assert.ok(isImagePath("/images"));
  assert.ok(isImagePath("/images/a/b.png?x=1"));
  assert.ok(!isImagePath("/v1/product"));
  // Prefix collision: a route that merely starts with the same letters.
  assert.ok(!isImagePath("/imagesearch"));
});

test("apiOf maps a path to its API, and nothing else", () => {
  const cases: [string, string][] = [
    ["/v1/user", "user"],
    ["/v1/user?email=x&requestid=1", "user"],
    ["/v1/product/", "product"],
    ["/v1/stress", "stress"],
    ["/v1/users", ""],
    ["/healthcheck", ""],
    ["/v1/none", ""],
  ];
  for (const [input, want] of cases) {
    assert.equal(apiOf(input), want, input);
  }
});

test("the grading query groups by route and reads the gin line", () => {
  const q = buildGradingQuery();
  assert.ok(q.includes("by path"), q);
  assert.ok(q.includes("parse @message /"), q);
  assert.ok(q.includes("latency_ms <= 5000"), q);
  assert.ok(!q.includes(`"latency_ms":`), "query still parses the old JSON log shape");
});
