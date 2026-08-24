import assert from "node:assert/strict";
import test from "node:test";

import { normalizePath, normalizePathSegments } from "../config/paths.ts";
import { assembleRule, pathPattern } from "./assemble.ts";
import { parseJsonDocuments } from "./jsondoc.ts";
import { ipInCidr, isPrivateIp } from "./request.ts";
import { testRule } from "./sim.ts";
import { applyTransforms } from "./transform.ts";
import {
  CATEGORY_AUTOMATION,
  CATEGORY_RECON,
  CATEGORY_SCANNER,
  CATEGORY_SPOOFED,
  CATEGORY_UNKNOWN,
  classifyUa,
} from "./threatsig.ts";
import type { HttpSummary, TestRequest } from "../../src/lib/types.ts";

const EMPTY_SUMMARY: HttpSummary = {
  totalSampled: 0,
  windowLabel: "",
  source: "",
  byPath: [],
  byIp: [],
  byUa: [],
  uaActions: [],
  surface: null,
  byMethod: [],
  queryPatterns: [],
  headerPatterns: [],
  blockedTotal: 0,
  statusDist: null,
  detailedStatus: null,
  notes: [],
};

const req = (over: Partial<TestRequest> & { id: string }): TestRequest => ({
  method: "GET",
  path: "/v1/user",
  query: "",
  userAgent: "",
  ip: "10.0.0.1",
  country: "KR",
  benign: true,
  headers: {},
  body: "",
  labels: [],
  ...over,
});

test("the sandbox blocks a malicious path without touching the benign one", () => {
  const ruleJson = `{
    "Name": "block-wp",
    "Priority": 0,
    "Action": { "Block": {} },
    "Statement": {
      "ByteMatchStatement": {
        "SearchString": "/wp-login.php",
        "FieldToMatch": { "UriPath": {} },
        "PositionalConstraint": "STARTS_WITH",
        "TextTransformations": [ { "Priority": 0, "Type": "LOWERCASE" } ]
      }
    }
  }`;
  const res = testRule(ruleJson, [
    req({
      id: "benign",
      userAgent: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36",
    }),
    req({
      id: "mal",
      path: "/wp-login.php",
      userAgent: "curl/8",
      ip: "203.0.113.9",
      country: "CN",
      benign: false,
    }),
  ]);
  assert.deepEqual(
    { caught: res.caught, blocked: res.blocked, passed: res.passed },
    { caught: 1, blocked: 0, passed: 1 },
  );
  assert.equal(res.verdict, "SAFE");
});

test("a managed group is approximated, and says so", () => {
  const ruleJson = `{
    "Name": "managed",
    "Priority": 0,
    "OverrideAction": { "None": {} },
    "Statement": {
      "ManagedRuleGroupStatement": { "VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet" }
    }
  }`;
  const res = testRule(ruleJson, [
    req({
      id: "traversal",
      path: "/v1/user/../../etc/passwd",
      userAgent: "curl/8.4.0",
      ip: "203.0.113.14",
      country: "CN",
      benign: false,
    }),
  ]);
  assert.equal(res.caught, 1, JSON.stringify(res.rows));
  assert.ok(res.approximated.length > 0, "managed group must be reported as approximated");
});

const SCANNER_SUMMARY: HttpSummary = {
  ...EMPTY_SUMMARY,
  totalSampled: 12,
  byUa: [
    { key: "sqlmap/1.7", count: 6 },
    { key: "Attacker-Bot", count: 4 },
    // A real browser must not become a pattern, or the rule blocks the grader.
    { key: "Mozilla/5.0 (X11) AppleWebKit/537.36", count: 2 },
  ],
};

test("the scanner rule ANDs the served-path set with the User-Agent set", () => {
  const assembled = assembleRule("ua", SCANNER_SUMMARY, {
    wafScope: "CLOUDFRONT",
    wafRegion: "us-east-1",
  });
  assert.equal(assembled.name, "scanner-ua");

  // Two sets, each with its own ARN placeholder and its own transforms.
  assert.deepEqual(
    assembled.sets.map((s) => s.name),
    ["waf-api-paths", "waf-scanner-uas"],
  );
  const rule = JSON.parse(assembled.ruleJson) as Record<string, any>;
  assert.equal(rule.Priority, 30);
  assert.ok(rule.Action.Block, "the scanner rule blocks");
  const arms = rule.Statement.AndStatement.Statements as Record<string, any>[];
  assert.equal(arms.length, 2, "path AND user-agent");

  const pathArm = arms[0]!.OrStatement?.Statements[0] ?? arms[0]!;
  assert.deepEqual(pathArm.RegexPatternSetReferenceStatement.FieldToMatch, { UriPath: {} });
  assert.equal(pathArm.RegexPatternSetReferenceStatement.ARN, "<waf-api-paths-ARN>");
  assert.deepEqual(
    pathArm.RegexPatternSetReferenceStatement.TextTransformations.map((t: any) => t.Type),
    ["URL_DECODE", "NORMALIZE_PATH"],
  );

  const uaArm = arms[1]!.OrStatement?.Statements[0] ?? arms[1]!;
  assert.deepEqual(uaArm.RegexPatternSetReferenceStatement.FieldToMatch, {
    SingleHeader: { Name: "user-agent" },
  });
  assert.equal(uaArm.RegexPatternSetReferenceStatement.ARN, "<waf-scanner-uas-ARN>");
  assert.deepEqual(
    uaArm.RegexPatternSetReferenceStatement.TextTransformations.map((t: any) => t.Type),
    ["COMPRESS_WHITE_SPACE", "LOWERCASE"],
  );
});

// The whole point of the second arm: a scanner off the served surface must be
// left to the app's 404, because a WAF block there answers 403 and breaks the
// task's undefined-path contract.
test("the scanner rule catches a scanner on the API surface and only there", () => {
  const assembled = assembleRule("ua", SCANNER_SUMMARY, {
    wafScope: "CLOUDFRONT",
    wafRegion: "us-east-1",
  });
  const res = testRule(assembled.sandboxRuleJson, [
    // Scanner on a served path — the request the rule exists for.
    req({ id: "scanner-on-api", path: "/v1/user", userAgent: "sqlmap/1.7", ip: "203.0.113.8", country: "RU", benign: false }),
    // Same scanner on an undefined path — must NOT be blocked (404 is the contract).
    req({ id: "scanner-off-api", path: "/admin", userAgent: "sqlmap/1.7", ip: "203.0.113.8", country: "RU", benign: false }),
    // The product binary's own trap UA, on a served path.
    req({ id: "attacker-bot", path: "/v1/product", method: "POST", userAgent: "Attacker-Bot", ip: "203.0.113.17", benign: false }),
    // Real traffic on a served path — the false positive that would cost score.
    req({ id: "browser", path: "/v1/user", userAgent: "Mozilla/5.0 (X11) AppleWebKit/537.36", ip: "10.0.2.88" }),
    // The load generator, which must never be touched.
    req({ id: "loadgen", path: "/v1/user", userAgent: "Go-http-client/2.0", ip: "10.0.2.23" }),
  ]);
  const outcome = (id: string): string => res.rows.find((r) => r.requestId === id)!.outcome;

  // CAUGHT = matched a Block rule and the request was malicious; BLOCKED is the
  // same match on a benign one, which is the false positive that costs score.
  assert.equal(outcome("scanner-on-api"), "CAUGHT");
  assert.equal(outcome("scanner-off-api"), "PASS", "an undefined path must be left to the app's 404");
  assert.equal(outcome("attacker-bot"), "CAUGHT");
  assert.equal(outcome("browser"), "PASS");
  assert.equal(outcome("loadgen"), "PASS");
  assert.equal(res.blocked, 0, "no benign request may be blocked");
});

test("classifyUa allows the load generator and names the tools", () => {
  const cases: [string, string][] = [
    ["sqlmap/1.7", CATEGORY_SCANNER],
    ["nmap scripting engine", CATEGORY_RECON],
    ["${jndi:ldap://x/a}", CATEGORY_SPOOFED],
    ["curl/8.4.0", CATEGORY_AUTOMATION],
    // "" = allowed.
    ["Go-http-client/2.0", ""],
    ["Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36", ""],
    ["ELB-HealthChecker/2.0", ""],
    ["Mozilla/5.0 (compatible)", CATEGORY_UNKNOWN],
  ];
  for (const [ua, category] of cases) {
    const hit = classifyUa(ua);
    if (category === "") {
      assert.equal(hit, null, `${ua}: expected allowed`);
      continue;
    }
    assert.equal(hit?.category, category, ua);
  }
});

// The product binary answers 500 to this User-Agent itself; the WAF has to turn
// it into a 403 first, so the assembler must recognise it as an attack.
test("Attacker-Bot is a scanner signature", () => {
  assert.equal(classifyUa("Attacker-Bot")?.category, CATEGORY_SCANNER);
});

test("ipInCidr and isPrivateIp", () => {
  assert.ok(ipInCidr("10.1.2.3", "10.0.0.0/8"));
  assert.ok(!ipInCidr("11.0.0.1", "10.0.0.0/8"));
  assert.ok(ipInCidr("2001:db8::1", "2001:db8::/32"), "v6 prefix");
  assert.ok(isPrivateIp("192.168.0.7"));
  assert.ok(!isPrivateIp("203.0.113.5"));
});

test("parseJsonDocuments tolerates trailing commas and comments", () => {
  const docs = parseJsonDocuments(`{"a":1,} // comment\n{"b":2}`);
  assert.equal(docs.length, 2);
});

// The assembler describes a path with config/paths.ts and the sandbox evaluates
// it with rules/transform.ts. Those were two implementations of one AWS
// transform, and they disagreed about the trailing slash — which is exactly the
// kind of drift that makes the simulator say "allowed" about a request the real
// WebACL blocks. There is one implementation now; this test is what keeps it
// that way.
test("NORMALIZE_PATH has one implementation, shared by the assembler and the sandbox", () => {
  const normalizeThroughSandbox = (raw: string): string =>
    applyTransforms(raw, [{ Priority: 0, Type: "NORMALIZE_PATH" }]).value;

  for (const raw of [
    "/v1/image/../../etc/passwd",
    "/a//b/./c",
    "/admin/",
    "/admin",
    "/",
    "//",
    "/v1/user",
  ]) {
    assert.equal(normalizeThroughSandbox(raw), normalizePathSegments(raw), raw);
  }

  // The trailing slash is kept, because that is what AWS does.
  assert.equal(normalizeThroughSandbox("/admin/"), "/admin/");
  // The path policy is the same transform with the query stripped first, and
  // stripping the query is the *only* thing it adds.
  assert.equal(normalizePath("/admin/?x=1"), "/admin/");
  assert.equal(normalizePath("/v1/image/../../etc/passwd"), "/etc/passwd");
  assert.equal(normalizePath("/"), "/");

  // What the disagreement actually threatened: the pattern the assembler built
  // has to match the value the sandbox produces, slash or no slash.
  const pattern = new RegExp(pathPattern("/admin/"));
  assert.match(normalizeThroughSandbox("/admin/"), pattern);
  assert.match(normalizeThroughSandbox("/admin"), pattern);
  assert.match(normalizeThroughSandbox("/admin/x"), pattern);
  assert.doesNotMatch(normalizeThroughSandbox("/administration"), pattern);
});
