// The pure halves of the COUNT-evidence join and the WAF log query builder.

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildCountQuery,
  extractRequestId,
  promotionNote,
  verdictFor,
} from "./countevidence.ts";
import { buildWafLogQuery } from "./waflog.ts";
import type { CountEvidence } from "../../src/lib/types.ts";

const evidence = (over: Partial<CountEvidence>): CountEvidence => ({
  ruleName: "r",
  total: 0,
  matches: [],
  normal: 0,
  abnormal: 0,
  unjoinable: 0,
  bytesScanned: 0,
  notes: [],
  ...over,
});

test("buildCountQuery embeds the rule name and excludes BLOCK", () => {
  const q = buildCountQuery("sqli-block");
  assert.ok(
    q.includes(String.raw`filter @message like /"ruleId":"sqli\-block"/`) ||
      q.includes(`filter @message like /"ruleId":"sqli-block"/`),
    q,
  );
  // A counting rule never terminates, so the action filter must exclude BLOCK,
  // not require COUNT.
  assert.ok(q.includes(`filter action != "BLOCK"`), q);
  // Regex metacharacters in a rule name must not escape the literal.
  assert.ok(buildCountQuery("a.b(c)").includes(String.raw`a\.b\(c\)`), "metacharacters not escaped");
});

test("extractRequestId reads the join key out of the WAF's args", () => {
  const cases: [string, string | null][] = [
    ["requestid=abc-123", "abc-123"],
    ["?uuid=u-9", "u-9"],
    ["a=1&requestid=x%2Fy", "x/y"],
    ["a=1&b=2", null],
    ["", null],
    ["requestid=", null],
  ];
  for (const [args, want] of cases) {
    assert.equal(extractRequestId(args), want, args);
  }
});

test("verdictFor treats only 2xx as served", () => {
  assert.equal(verdictFor(null), "unjoinable");
  assert.equal(verdictFor(200), "normal");
  assert.equal(verdictFor(299), "normal");
  assert.equal(verdictFor(403), "abnormal");
  assert.equal(verdictFor(302), "abnormal");
});

test("promotionNote names what promoting the rule would cost", () => {
  assert.ok(promotionNote(evidence({ total: 30, normal: 2 })).includes("2건"));
  assert.ok(promotionNote(evidence({ total: 5 })).includes("표본 부족"));
  assert.ok(promotionNote(evidence({ total: 40 })).includes("정상 응답 0건"));
});

test("buildWafLogQuery filters, and the validator is the whole injection guard", () => {
  const q = buildWafLogQuery("BLOCK", "v1/user");
  assert.ok(q.includes(`filter action = "BLOCK"`), q);
  assert.ok(q.includes(`filter uri like "v1/user"`), q);

  // ALL adds no action filter.
  assert.ok(!buildWafLogQuery("ALL", "").includes("filter action ="));

  // The path filter is interpolated into the query, so the validator is the
  // whole injection guarantee.
  assert.throws(() => buildWafLogQuery("ALL", `x" or 1=1`), "quote in path filter must be rejected");
  assert.throws(() => buildWafLogQuery("DROP", ""), "unknown action must be rejected");
});
