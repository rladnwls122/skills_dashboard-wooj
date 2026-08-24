import assert from "node:assert/strict";
import test from "node:test";

import {
  apiOf,
  buildGradingPanel,
  buildGradingQuery,
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

// The keys follow the 2025 task-3 scoring sheet; each is fed from the source
// that can actually see it.
test("the panel carries every scoring key, from the source that sees it", () => {
  const params: GradingParams = {
    rows: [
      // 100 user requests: 90 served fast, 5 served slow (>200ms but <5s), 3 app 403 (duplicate), 2 500.
      row({ path: "/v1/user", total: 100, availOk: 95, fastOk: 90, slowOk: 95, forbidden: 3, serverErr: 2 }),
      row({ path: "/v1/product", total: 50, availOk: 50, fastOk: 50, slowOk: 50 }),
      // stress: 20 served, 15 of them inside 1s; the fast column would undercount it.
      row({ path: "/v1/stress", total: 20, availOk: 20, fastOk: 2, slowOk: 15 }),
      row({ path: "/healthcheck", total: 500, availOk: 500, fastOk: 500, slowOk: 500 }),
      // undefined paths the app answered: 8 with 404 (gin's default), 2 with 200 (a misrouted catch-all).
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
  check("user API 로드 처리", 95, 100, false);
  check("product API 로드 처리", 50, 50, false);
  check("stress API 로드 처리", 20, 20, false);
  check("user API 로드 처리 ≤ 0.2s", 90, 100, false);
  check("stress API 로드 처리 ≤ 1.0s", 15, 20, false);
  // Email validation: only the WAF's POST /v1/user blocks are visible.
  check("Email Request Validation (403)", 30, 30, true);
  // Abnormal handling: served-surface blocks over blocks + what leaked to the app.
  check("비정상 요청 처리율 (403)", 40, 44, true);
  // Undefined paths: app 404s over app-seen undefined + WAF-blocked undefined
  // (not the health check).
  check("미지정 경로 404", 8, 15, false);

  assert.equal(panel.lines.length, 9);
  assert.equal(lineByLabel(panel, "user API 로드 처리").pct, 95);

  const joined = panel.notes.join("\n");
  assert.ok(joined.includes("Attacker-Bot"), "notes must name the trap");
  assert.ok(joined.includes("4건"), "notes must say how many abnormal requests leaked");
});

// Without a WAF log group the 403 keys fall back to app-side evidence only, and
// the panel has to say so rather than show a clean 0.
test("without a WAF log group the panel says so", () => {
  const panel = buildGradingPanel({
    rows: [row({ path: "/v1/product", total: 10, availOk: 10, fastOk: 10, slowOk: 10 })],
    trapLeaked: 2,
    window: WINDOW,
  });
  const l = lineByLabel(panel, "비정상 요청 처리율 (403)");
  assert.equal(l.okCount, 0);
  assert.equal(l.total, 2);
  assert.ok(
    panel.notes.join("\n").includes("WAF_LOG_GROUP"),
    "must tell the operator the WAF log group is missing",
  );
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
