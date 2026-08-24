import assert from "node:assert/strict";
import test from "node:test";

import { detectAnomalies, type AnomalyInput } from "./anomaly.ts";
import { aggregateFingerprints } from "./fingerprint.ts";
import { packToLimit } from "./gateway.ts";
import { GIN_PARSE, PARSE_FIELDS, cleanUri } from "./logfields.ts";
import { maskLine } from "./mask.ts";
import { analyzeRequestLog, durationMs, requestIdOf } from "./requestlog.ts";
import type { PathLatencyStat } from "../../src/lib/types.ts";

test("maskLine removes secrets", () => {
  const out = maskLine("authorization: Bearer abc.def token=supersecret AKIA1234567890ABCDEF");
  assert.ok(!out.includes("supersecret"), out);
  assert.ok(!out.includes("AKIA1234567890ABCDEF"), out);
});

test("aggregateFingerprints groups the same error", () => {
  const lines = [
    "2026-08-14T01:00:00Z error: connection refused to 10.0.0.1:5432 id=abc123def4567890abcd",
    "2026-08-14T01:00:05Z error: connection refused to 10.0.0.2:5432 id=ffff123def4567890abc",
    "2026-08-14T01:00:06Z ok request served",
  ];
  const fps = aggregateFingerprints([{ pod: "p1", lines }]);
  assert.equal(fps.length, 1);
  assert.equal(fps[0]!.count, 2);
});

// The binaries' own failure lines must fingerprint: the product trap line has
// no generic error keyword, and a 5xx access line is an error by status.
test("aggregateFingerprints catches the binaries' failure lines", () => {
  const lines = [
    "2026-08-14T01:00:00Z Consumed resources by malicious attacks.",
    "2026-08-14T01:00:01Z Consumed resources by malicious attacks.",
    String.raw`2026-08-14T01:00:02Z [GIN] 2025/09/23 - 03:12:47 | 500 |  1.234567891s |   203.0.113.10 | POST     "/v1/stress"`,
    "2026-08-14T01:00:03Z 2025/09/23 03:12:47 Failed to query DB: Error 1062 (23000): Duplicate entry 'x' for key 'user.uk_username'",
    String.raw`2026-08-14T01:00:04Z [GIN] 2025/09/23 - 03:12:48 | 201 |   12.345678ms |   203.0.113.10 | POST     "/v1/user"`,
  ];
  const fps = aggregateFingerprints([{ pod: "p1", lines }]);
  assert.equal(fps.length, 3, JSON.stringify(fps));
  assert.ok(fps[0]!.fingerprint.includes("malicious"), fps[0]!.fingerprint);
  assert.equal(fps[0]!.count, 2);
});

// Real lines from the 2025 task binaries (gin 1.10 default logger), in every
// unit a Go duration prints, plus the stderr middleware line that must not be
// counted as a second request.
test("analyzeRequestLog reads the gin access line", () => {
  const lines = [
    String.raw`[GIN] 2025/09/23 - 03:12:45 | 201 |   12.345678ms |   203.0.113.10 | POST     "/v1/user"`,
    String.raw`[GIN] 2025/09/23 - 03:12:46 | 200 |     45.678µs |   203.0.113.10 | GET      "/v1/user?email=dbdump500001%40example.org&requestid=999999999999&uuid=7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729"`,
    String.raw`[GIN] 2025/09/23 - 03:12:47 | 500 |  1.234567891s |   203.0.113.10 | POST     "/v1/stress"`,
    String.raw`[GIN] 2025/09/23 - 03:12:48 | 404 |       2.501µs |   203.0.113.11 | GET      "/v1/none"`,
    String.raw`[GIN] 2025/09/23 - 03:12:49 | 200 |         1m2s |      10.0.1.5 | GET      "/healthcheck"`,
    String.raw`[GIN] 2025/09/23 - 03:12:50 | 200 |         850ns |      10.0.1.5 | GET      "/healthcheck"`,
    String.raw`2025/09/23 03:12:45 [2025-09-23T03:12:45Z] POST /v1/user from 203.0.113.10`,
    String.raw`2025/09/23 03:12:47 Failed to query DB: Error 1062 (23000): Duplicate entry`,
    String.raw`[GIN-debug] Listening and serving HTTP on :8080`,
    // k8s API read: RFC3339 prefix; EKS shipper: JSON-wrapped with \" around the path.
    String.raw`2026-08-20T09:13:06.402Z {"log":"[GIN] 2025/09/23 - 03:12:54 | 403 |     3.456ms |   203.0.113.10 | POST     \"/v1/user\"\n","stream":"stdout"}`,
  ];
  const a = analyzeRequestLog(lines);
  assert.equal(a.entries.length, 7, JSON.stringify(a.entries));

  const want = [
    { method: "POST", path: "/v1/user", status: 201, ms: 12.346, ip: "203.0.113.10", rid: "" },
    {
      method: "GET",
      path: "/v1/user",
      status: 200,
      ms: 0.046,
      ip: "203.0.113.10",
      rid: "999999999999",
    },
    { method: "POST", path: "/v1/stress", status: 500, ms: 1234.568, ip: "203.0.113.10", rid: "" },
    { method: "GET", path: "/v1/none", status: 404, ms: 0.003, ip: "203.0.113.11", rid: "" },
    { method: "GET", path: "/healthcheck", status: 200, ms: 62000, ip: "10.0.1.5", rid: "" },
    { method: "GET", path: "/healthcheck", status: 200, ms: 0.001, ip: "10.0.1.5", rid: "" },
    { method: "POST", path: "/v1/user", status: 403, ms: 3.456, ip: "203.0.113.10", rid: "" },
  ];
  for (const [i, w] of want.entries()) {
    const e = a.entries[i]!;
    assert.deepEqual(
      {
        method: e.method,
        path: e.path,
        status: e.status,
        ms: e.latencyMs,
        ip: e.clientIp ?? "",
        rid: e.requestId ?? "",
      },
      w,
      `entry ${i}`,
    );
  }

  assert.equal(a.nonOkEntries.length, 3, JSON.stringify(a.nonOkEntries));

  // Grouped by route, not by the full URI — the requestid query must not split
  // /v1/user into one row per request.
  const byPath = new Map<string, PathLatencyStat>(a.byPath.map((p) => [p.path, p]));
  assert.equal(byPath.get("/v1/user")?.count, 3);
  assert.equal(byPath.get("/v1/user")?.nonOkCount, 1);

  // The DB error is an error line; the access lines and the arrival line are not.
  assert.equal(a.errorWarnLines.length, 1, JSON.stringify(a.errorWarnLines));
  assert.ok(a.errorWarnLines[0]!.includes("Failed to query DB"));

  // The counters the panel prints. This is the Kubernetes fallback — the path
  // taken when Logs Insights failed — and it used to leave all three unset, so
  // the request-log panel drew blank totals over a populated table at exactly
  // the moment something was already wrong. Counted over everything parsed, not
  // over the truncated sample lists above.
  assert.equal(a.totalRequests, 7);
  assert.equal(a.nonOkTotal, 3);
  assert.equal(a.errorWarnTotal, 1);
});

// The totals describe the whole input, not the tail the panel shows: the sample
// lists are capped (500 entries / 100 non-OK / 100 error lines) and a count that
// silently saturated at the cap would understate a real incident.
test("analyzeRequestLog counts past the sample caps", () => {
  const lines: string[] = [];
  for (let i = 0; i < 620; i++) {
    lines.push(
      `[GIN] 2025/09/23 - 03:12:45 | 500 |   1.0ms |   203.0.113.10 | POST     "/v1/user?requestid=${i}"`,
    );
  }
  const a = analyzeRequestLog(lines);
  assert.equal(a.entries.length, 500, "the sample list is still capped");
  assert.equal(a.nonOkEntries.length, 100);
  assert.equal(a.totalRequests, 620);
  assert.equal(a.nonOkTotal, 620);
  // "500" is not an error word, and the [GIN] line carries none of them.
  assert.equal(a.errorWarnTotal, 0);
});

test("durationMs reads every unit Go prints", () => {
  const cases: [string, number][] = [
    ["850ns", 0.00085],
    ["45.678µs", 0.045678],
    ["45.678us", 0.045678],
    ["12.345678ms", 12.345678],
    ["1.234567891s", 1234.567891],
    ["1m2s", 62000],
    ["1h0m0s", 3600000],
  ];
  for (const [input, want] of cases) {
    const got = durationMs(input);
    assert.ok(got !== null, input);
    assert.ok(Math.abs(got - want) < 1e-9, `${input}: got ${got} want ${want}`);
  }
  assert.equal(durationMs("fast"), null, "garbage must not parse");
});

test("requestIdOf finds the grader's key", () => {
  assert.equal(requestIdOf("/v1/user?email=a%40b.org&requestid=999999999999&uuid=x"), "999999999999");
  assert.equal(requestIdOf("/v1/product?id=1&requestid=abc-1"), "abc-1");
  assert.equal(requestIdOf("/v1/user"), "");
  assert.equal(requestIdOf("/v1/user?uuid=only"), "");
});

test("cleanUri strips the EKS backslash and, on request, the query", () => {
  // Concatenated rather than written inline: a raw template literal cannot end
  // with a backslash, which is exactly the input under test.
  assert.equal(cleanUri("/v1/user?requestid=2" + "\\", false), "/v1/user?requestid=2");
  assert.equal(cleanUri("/v1/user?requestid=2", true), "/v1/user");
});

// The Insights chain has to name the fields every query downstream reads, and
// the pattern form is the one verified against a real log group (see
// logfields.ts) — a well-meaning "tightening" with a backslash breaks it.
test("PARSE_FIELDS keeps the shape verified against Insights", () => {
  for (const f of [
    "(?<status>",
    "(?<lat_num>",
    "(?<lat_unit>",
    "(?<client_ip>",
    "(?<method>",
    "(?<uri>",
    "as latency_ms",
    "(?<path>",
    "(?<requestid>",
  ]) {
    assert.ok(PARSE_FIELDS.includes(f), `PARSE_FIELDS lacks ${f}`);
  }
  assert.ok(GIN_PARSE.includes(String.raw`.?"(?<uri>[^"]*)`), GIN_PARSE);
  assert.ok(!PARSE_FIELDS.includes("\\\\"), "no backslash may be written in any pattern");
  assert.ok(
    PARSE_FIELDS.startsWith("parse @message /"),
    "must read @message so ECS awslogs and EKS Container Insights groups both work",
  );
});

test("a scanner User-Agent is critical", () => {
  const input: AnomalyInput = {
    metrics: [],
    httpSummary: {
      totalSampled: 10,
      windowLabel: "",
      source: "",
      byPath: [],
      byIp: [],
      byUa: [{ key: "sqlmap/1.7", count: 3 }],
      uaActions: [],
      surface: null,
      byMethod: [],
      queryPatterns: [],
      headerPatterns: [],
      blockedTotal: 0,
      statusDist: null,
      detailedStatus: null,
      notes: [],
    },
    pods: [],
    events: [],
    fingerprints: [],
  };
  const anomalies = detectAnomalies(input, new Date());
  const hit = anomalies.find((a) => a.type === "MALICIOUS_CLIENT_SUSPECTED");
  assert.ok(hit, "scanner UA must raise MALICIOUS_CLIENT_SUSPECTED");
  assert.equal(hit.severity, "CRITICAL");
});

test("packToLimit drops whole sections first and says so", () => {
  const long = Array.from({ length: 100 }, () => "x".repeat(50));
  const out = packToLimit(["h"], [
    { title: "[A]", lines: long },
    { title: "[B]", lines: ["short"] },
  ], 1000);
  assert.ok(out.length <= 1000, `len=${out.length}`);
  assert.ok(out.includes("생략"), "must state what was dropped");
});
