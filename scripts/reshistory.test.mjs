// Pod and node names are the one part of a sample key we do not control, and a
// node name contains colons. Splitting the key on every colon would have put
// half an IP address in the "name" field and silently dropped the series.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { sampleKey, parseSampleKey } = await import(`${SRC}reshistory.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

check("키 왕복", parseSampleKey(sampleKey("pod", "cpu", "user-7d9f-abc")), {
  kind: "pod",
  metric: "cpu",
  name: "user-7d9f-abc",
});
check("이름에 콜론이 있어도 깨지지 않음", parseSampleKey(sampleKey("node", "mem", "ip-10:0:1:2")), {
  kind: "node",
  metric: "mem",
  name: "ip-10:0:1:2",
});
// CloudWatch samples share this table, so the reader has to ignore them.
check("다른 접두어는 무시", parseSampleKey("http4xx"), null);
check("알 수 없는 종류는 무시", parseSampleKey("res:svc:cpu:x"), null);
check("알 수 없는 지표는 무시", parseSampleKey("res:pod:disk:x"), null);
check("이름이 비면 무시", parseSampleKey("res:pod:cpu:"), null);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
