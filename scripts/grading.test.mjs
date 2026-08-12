// The panel lines observed traffic up against the grader's metric keys. These
// lock the definitions taken from skills-grader — which path counts toward
// which key, the per-API SLO split — and that no score is invented here.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { buildGradingPanel, buildGradingQuery, toPathRow, apiOf, isImagePath, SLO_MS, AVAIL_DEADLINE_MS } =
  await import(`${SRC}grading.ts`);
const { resolveWindow } = await import(`${SRC}window.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const win = resolveWindow({ windowMin: 60, intervalMin: 1 }, Date.UTC(2026, 7, 12, 12, 0, 0));
const row = (path, o = {}) => ({
  path,
  total: o.total ?? 0,
  availOk: o.availOk ?? 0,
  fastOk: o.fastOk ?? 0,
  slowOk: o.slowOk ?? 0,
  handledOk: o.handledOk ?? 0,
});
const panel = (rows, wafBlocked = 0) =>
  buildGradingPanel({ rows, wafBlocked, window: win, source: "test", scannedBytes: 0, notes: [] });
const line = (p, label) => p.lines.find((l) => l.label === label);

// --- path classification ---
check("서비스 경로가 API 로 분류됨", ["/v1/user", "/v1/product/42", "/v1/stress"].map(apiOf), ["user", "product", "stress"]);
check("쿼리는 무시", apiOf("/v1/user?id=1"), "user");
check("접두어만 같은 경로는 아님", apiOf("/v1/userx"), null);
check("미지정 경로는 API 아님", apiOf("/wp-login.php"), null);
check("이미지 경로 판별", [isImagePath("/images/a.png"), isImagePath("/v1/product")], [true, false]);

// --- no score is invented here ---
// The grade belongs to the grader's own run. A second score computed on this
// side would compete with it, so the panel carries values and nothing else.
const shape = panel([row("/v1/user", { total: 10, availOk: 9, fastOk: 8, slowOk: 9 })]);
check("점수 필드가 없음", "points" in shape, false);
check("만점 필드가 없음", "maxPoints" in shape, false);
check("줄에도 점수가 없음", Object.keys(shape.lines[0]).sort(), ["label", "okCount", "pct", "total"]);
check("점수는 채점기가 정한다고 적힘", shape.notes.some((n) => n.includes("results_")), true);

// Keys appear in the grader's own order so the two lists read side by side.
check("채점기 키 순서", panel([]).lines.map((l) => l.label), [
  "(user) availability",
  "(product) availability",
  "(stress) availability",
  "(user) performance",
  "(product) performance",
  "(stress) performance",
  "image download",
  "Exception Handling",
]);

// --- availability / performance split ---
// user: 1000건 중 900건이 2xx·5s 이내, 그중 850건이 200ms 이내.
const p1 = panel([row("/v1/user", { total: 1000, availOk: 900, fastOk: 850, slowOk: 890 })]);
check("가용성 비율", line(p1, "(user) availability").pct, 90);
check("성능은 빠른 SLO 기준", line(p1, "(user) performance").pct, 85);
// stress 는 SLO 가 1초라 느린 쪽 카운트를 쓴다 — 여기서 갈리지 않으면 점수가 크게 틀린다.
const p2 = panel([row("/v1/stress", { total: 100, availOk: 100, fastOk: 10, slowOk: 95 })]);
check("stress 성능은 1초 기준", line(p2, "(stress) performance").pct, 95);
check("user 였다면 10% 였을 것", SLO_MS.stress > SLO_MS.user, true);

// --- image download ---
const p3 = panel([row("/images/a.png", { total: 200, availOk: 180 })]);
check("이미지 다운로드 비율", line(p3, "image download").pct, 90);
check("이미지는 가용성 API 에 섞이지 않음", line(p3, "(product) availability").total, 0);

// --- exception handling ---
// 미지정 경로 100건 중 85건이 404/403 으로 끝남.
const p4 = panel([
  row("/wp-login.php", { total: 60, handledOk: 55 }),
  row("/.env", { total: 40, handledOk: 30 }),
  row("/v1/user", { total: 500, availOk: 500, fastOk: 500, slowOk: 500 }),
  row("/healthcheck", { total: 900, availOk: 900, fastOk: 900, slowOk: 900 }),
]);
check("예외 처리 비율은 미지정 경로만", line(p4, "Exception Handling").pct, 85);
check("서비스 경로는 예외 분모에 없음", line(p4, "Exception Handling").total, 100);
check("헬스체크도 예외 분모에 없음", line(p4, "Exception Handling").total, 100);

// --- what the panel refuses to claim ---
check("비용은 관측 대상이 아니라 줄에 없음", p1.lines.some((l) => l.label.includes("cost")), false);
check("2xx 근사임이 명시됨", p1.notes.some((n) => n.includes("2xx")), true);
check("WAF 차단 건수가 별도로 적힘", panel([], 42).notes.some((n) => n.includes("42건")), true);

// --- empty traffic must not read as a score ---
const empty = panel([]);
check("트래픽이 없으면 0%", line(empty, "(user) availability").pct, 0);
check("분모가 0임을 알 수 있음", line(empty, "(user) availability").total, 0);

// --- the query counts in Insights rather than pulling rows back ---
const q = buildGradingQuery();
check("가용성 마감시간이 쿼리에 들어감", q.includes(`latency_ms <= ${AVAIL_DEADLINE_MS}`), true);
check("두 SLO 를 모두 세어 옴", q.includes(`<= ${SLO_MS.user}`) && q.includes(`<= ${SLO_MS.stress}`), true);
check("경로별 집계", q.includes("by path"), true);
check("행이 아니라 집계를 가져옴", q.includes("stats count(*)"), true);

check("행 파싱", toPathRow({ path: "/v1/user", total: "10", availOk: "9", fastOk: "8", slowOk: "9", handledOk: "0" }), {
  path: "/v1/user", total: 10, availOk: 9, fastOk: 8, slowOk: 9, handledOk: 0,
});
check("깨진 숫자는 0", toPathRow({ path: "/x", total: "abc" }).total, 0);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
