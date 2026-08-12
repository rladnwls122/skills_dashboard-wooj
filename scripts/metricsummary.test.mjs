// A headline metric must mean the same thing at every interval. Thresholds are
// absolute, so if the number scaled with the bucket size, widening the window
// would raise an alert without the traffic changing.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { summarize } = await import(`${SRC}cloudwatch.ts`);
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

const now = Date.UTC(2026, 7, 12, 12, 0, 0);
// 100 requests per minute, expressed at three different bucket sizes. The
// trailing bucket is dropped as incomplete, so each series carries one extra.
const series = (perBucket, buckets) => ({
  key: "http4xx",
  label: "4XX",
  unit: "req/min",
  stat: "Sum",
  metric: "AWS/ApplicationELB HTTPCode_Target_4XX_Count",
  points: Array.from({ length: buckets }, (_, i) => ({ t: now + i * 60_000, v: perBucket })),
});

const at = (intervalMin, perBucket) =>
  summarize(series(perBucket, 8), resolveWindow({ windowMin: 240, intervalMin }, now)).current;

check("1분 간격에서 분당 100건", at(1, 100), 100);
check("5분 간격에서도 분당 100건", at(5, 500), 100);
check("10분 간격에서도 분당 100건", at(10, 1000), 100);
check("60분 간격에서도 분당 100건", at(60, 6000), 100);

// Average metrics are a level, not a count — they must NOT be divided.
const avg = summarize(
  { key: "targetResponseTime", label: "TRT", unit: "s", stat: "Average", metric: "AWS/ApplicationELB TargetResponseTime", points: Array.from({ length: 8 }, (_, i) => ({ t: now + i * 60_000, v: 0.4 })) },
  resolveWindow({ windowMin: 240, intervalMin: 10 }, now),
);
check("평균 지표는 환산하지 않음", avg.current, 0.4);

// The basis has to say which of the two happened.
check("합계 지표의 기준에 환산이 적힘", summarize(series(100, 8), resolveWindow({ windowMin: 60, intervalMin: 5 }, now)).basis.includes("분당으로 환산"), true);
check("평균 지표의 기준에는 환산이 없음", avg.basis.includes("환산"), false);

// Empty data must not produce NaN — a NaN sails past every threshold compare.
const empty = summarize({ key: "http4xx", label: "4XX", unit: "req/min", stat: "Sum", metric: "AWS/ApplicationELB HTTPCode_Target_4XX_Count", points: [] }, resolveWindow({ windowMin: 60, intervalMin: 1 }, now));
check("데이터가 없으면 0", empty.current, 0);

// The basis has to name the CloudWatch metric, not our display label. "4XX" is
// not searchable in the console; the metric name is.
check("기준에 CloudWatch 지표 이름이 적힘", empty.basis.startsWith("AWS/ApplicationELB HTTPCode_Target_4XX_Count Sum"), true);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
