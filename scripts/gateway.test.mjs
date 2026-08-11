// The contract: the gateway answers 404 on unlisted paths, 200 on listed paths
// with normal requests, 403 on listed paths with abnormal ones. The report must
// read 404/403 as policy working (not an outage), flag the two things the
// contract does not allow (5XX, and an unlisted path that was let through), and
// the Amazon Q hand-off must never exceed 10,000 characters.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const {
  GATEWAY_CONTRACT,
  MAX_Q_PROMPT_CHARS,
  contractLines,
  evaluateContract,
  packToLimit,
  responseGuidance,
} = await import(`${SRC}gateway.ts`);
const { toQPrompt } = await import(`${SRC}incident.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};
const has = (name, haystack, needle) => check(name, haystack.some((x) => x.includes(needle)), true);

// --- The contract itself ---
check("unlisted paths are 404", GATEWAY_CONTRACT.unlistedStatus, 404);
check("normal requests are 200", GATEWAY_CONTRACT.normalStatus, 200);
check("abnormal requests are 403", GATEWAY_CONTRACT.abnormalStatus, 403);
has("contract names the 404 scanning policy", contractLines(), "404 Not Found");
has("contract names the abnormal kinds", contractLines(), "SQL Injection");

const summary = (byPath, statusDist = { c2xx: 100, c3xx: 0, c4xx: 0, c5xx: 0 }) => ({
  totalSampled: byPath.reduce((a, p) => a + p.count, 0),
  windowLabel: "15m",
  source: "test",
  byPath,
  byIp: [],
  byUa: [],
  byMethod: [],
  queryPatterns: [],
  headerPatterns: [],
  statusDist,
  detailedStatus: null,
});
const p = (path, count, blocked = 0, lowPriority = false) => ({ path, count, blocked, lowPriority });

// --- Listed path, blocked: 403 is the contract working, not a finding ---
{
  const r = evaluateContract(summary([p("/v1/user", 500, 12)]));
  check("blocked traffic on a listed path is not a deviation", r.deviations, []);
  has("blocked traffic on a listed path is reported as conforming", r.conforming, "지정 경로 차단 12건");
}

// --- Unlisted path that got through: the gateway must have answered 404 ---
{
  const r = evaluateContract(summary([p("/v1/user", 100), p("/login", 40)]));
  has("an unlisted path passing the WAF is a deviation", r.deviations, "미지정 경로 1개(요청 40건)가 WAF를 통과");
  has("the deviation names the 404 expectation", r.deviations, "404");
}

// --- Unlisted path blocked: 403 leaks that the path is guarded ---
{
  const r = evaluateContract(summary([p("/v1/admin", 30, 30)]));
  has("blocking an unlisted path with 403 is a deviation", r.deviations, "CustomResponse 404");
  check("a fully blocked unlisted path is not also reported as passed", r.deviations.length, 1);
}

// --- Status classes outside the contract ---
{
  const r = evaluateContract(summary([p("/v1/user", 100)], { c2xx: 90, c3xx: 0, c4xx: 5, c5xx: 7 }));
  has("5XX is always a deviation", r.deviations, "5XX 7건/분");
}
{
  const r = evaluateContract(summary([p("/v1/user", 100)], { c2xx: 90, c3xx: 4, c4xx: 0, c5xx: 0 }));
  has("3XX is outside the contract", r.deviations, "3XX 4건/분");
}
{
  const r = evaluateContract(summary([p("/.env", 60)], { c2xx: 10, c3xx: 0, c4xx: 60, c5xx: 0 }));
  has("4XX against unlisted paths is explained, not alarmed", r.conforming, "장애로 판정하지 말 것");
}
check("no traffic yields no verdicts", evaluateContract(null), { conforming: [], deviations: [] });

// --- Rule authoring guidance follows the same split ---
has("unlisted-path rules get CustomResponse 404", [responseGuidance("/v1/admin")], "CustomResponse 404");
has("listed-path rules keep the default 403", [responseGuidance("/v1/user")], "403가 계약과 일치");
has("path-agnostic rules are told to scope down", [responseGuidance(undefined)], "scope-down");

// --- packToLimit: hard budget, and it says what it dropped ---
{
  const big = Array.from({ length: 400 }, (_, i) => `- 라인 ${i} ${"가".repeat(60)}`);
  const out = packToLimit(["# 헤더"], [{ title: "[A] 큰 섹션", lines: big }, { title: "[B] 뒤 섹션", lines: big }], 2000);
  check("packed output respects the limit", out.length <= 2000, true);
  check("truncation is disclosed", out.includes("생략"), true);
  check("a dropped section is named", out.includes("[B] 뒤 섹션"), true);
}
{
  const out = packToLimit(["# 헤더"], [{ title: "[A]", lines: ["- 한 줄"] }], 2000);
  check("short output is not padded or cut", out, "# 헤더\n\n[A]\n- 한 줄");
  check("nothing is marked omitted when everything fit", out.includes("생략"), false);
}

// --- The Amazon Q prompt fits, and leads with the judgement criteria ---
{
  const line = (i) => `2026-08-11T00:00:0${i % 10}Z ERROR ${"스택".repeat(40)}`;
  const snapshot = {
    timestamp: "2026-08-11T00:00:00.000Z",
    metrics: Array.from({ length: 12 }, (_, i) => ({
      key: `m${i}`,
      label: `메트릭 ${i}`,
      previous: i,
      current: i * 3,
      delta: i * 2,
      percentChange: 200,
      status: i % 2 === 0 ? "CRITICAL" : "NORMAL",
    })),
    httpSummary: summary(
      Array.from({ length: 40 }, (_, i) => p(`/scan/path/${i}`, 50, i % 2 === 0 ? 50 : 0)),
      { c2xx: 10, c3xx: 2, c4xx: 900, c5xx: 30 },
    ),
    kube: {
      nodesReady: 2,
      nodesTotal: 3,
      pods: Array.from({ length: 30 }, (_, i) => ({
        name: `pod-${i}`,
        statusLabel: "CrashLoopBackOff",
        ready: "0/1",
        totalRestarts: i,
        recentRestartIncrease: 1,
        nodeName: `node-${i}`,
        phase: "Running",
        containers: [],
      })),
      events: [],
    },
    anomalies: Array.from({ length: 20 }, (_, i) => ({
      id: `a${i}`,
      type: "4XX_SPIKE",
      severity: "CRITICAL",
      title: `이상 ${i}`,
      detail: "상세".repeat(60),
      evidence: ["근거".repeat(40), "근거2".repeat(40)],
      confidence: "HIGH",
      detectedAt: "2026-08-11T00:00:00.000Z",
    })),
    correlations: Array.from({ length: 10 }, (_, i) => ({
      category: `C${i}`,
      reason: "원인".repeat(50),
      confidence: "MEDIUM",
      evidence: [],
    })),
    timeline: Array.from({ length: 100 }, (_, i) => ({ ts: `t${i}`, source: "s", text: line(i) })),
    fingerprints: Array.from({ length: 20 }, (_, i) => ({
      fingerprint: `지문 ${i} ${"내용".repeat(50)}`,
      count: i,
      pods: [`pod-${i}`],
    })),
    logs: { pod: "pod-0", container: "app", previous: false, lines: Array.from({ length: 200 }, (_, i) => line(i)) },
    previousLogs: { pod: "pod-0", container: "app", lines: Array.from({ length: 200 }, (_, i) => line(i)) },
    wafHistory: Array.from({ length: 20 }, (_, i) => ({ ts: `t${i}`, ruleName: `r${i}`, action: "BLOCK", status: "SUCCESS", detail: "d" })),
    deployHistory: Array.from({ length: 20 }, (_, i) => ({ ts: `t${i}`, target: `default/app-${i}`, change: "replicas 2→4", verdict: "IMPROVED" })),
    verifications: Array.from({ length: 20 }, (_, i) => ({ actionId: i, verdict: "IMPROVED", checkedAt: "t", details: ["상세"] })),
    wafRecommendations: Array.from({ length: 15 }, (_, i) => ({
      id: `r${i}`,
      kind: "BYTE_MATCH",
      name: `dash-${i}`,
      targetPattern: `패턴 ${i}`,
      criteria: { path: i % 2 === 0 ? "/v1/admin" : "/v1/user" },
      threshold: null,
      evaluationWindowSec: null,
      action: "BLOCK",
      confidence: "HIGH",
      reason: "이유".repeat(40),
      evidence: [],
      expectedImpact: "영향",
      falsePositiveRisk: "LOW",
      hasScopeDown: false,
      ruleJson: JSON.stringify({ Name: `dash-${i}`, Statement: { ByteMatchStatement: { SearchString: "x".repeat(400) } } }, null, 2),
    })),
  };

  const q = toQPrompt(snapshot);
  check("an oversized snapshot still fits Amazon Q's limit", q.length <= MAX_Q_PROMPT_CHARS, true);
  check("the criteria section leads the prompt", q.indexOf("[A] 판정 기준") < q.indexOf("[C] 이상 징후"), true);
  check("rule JSON bodies are excluded", q.includes("ByteMatchStatement"), false);
  check("raw pod log lines are excluded", q.includes("ERROR 스택"), false);
  check("the response-code guidance rides along with each rule", q.includes("CustomResponse 404"), true);
  check("truncation is disclosed to the reader", q.includes("생략"), true);
}

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
