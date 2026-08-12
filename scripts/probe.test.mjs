// The traffic check is the one thing here that leaves the AWS APIs, so what it
// will and will not dial is pinned down, and a failed probe is pinned down as
// a result rather than as a thrown error — the dashboard failing and the
// target failing must not look the same on screen.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { probe, parseTarget, expectLabel } = await import(`${SRC}probe.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};
const throws = (name, fn) => {
  try {
    fn();
    check(name, "예외 없음", "예외");
  } catch {
    check(name, true, true);
  }
};

// --- what it will dial ---
check("스킴이 없으면 http 로 본다", parseTarget("example.com/v1/user").toString(), "http://example.com/v1/user");
check("https 는 그대로", parseTarget("https://example.com/").protocol, "https:");
check("앞뒤 공백은 무시", parseTarget("  http://example.com/  ").toString(), "http://example.com/");
// A dashboard that will GET file:// on request is a file reader with a URL bar.
throws("file:// 은 거부", () => parseTarget("file:///etc/passwd"));
throws("빈 주소는 거부", () => parseTarget("   "));
throws("주소가 아니면 거부", () => parseTarget("http://"));

// --- what counts as healthy ---
check("기대 코드가 없으면 2xx", expectLabel(null), "2xx 응답");
check("기대 코드가 있으면 그 코드만", expectLabel(404), "404 응답만");
check("0 은 미지정과 같다", expectLabel(0), "2xx 응답");

// --- a failed probe is a result, not an error ---
// Port 1 is never listening, and node's fetch reports it as a bare
// "fetch failed" — the reason lives one level down in `cause`, which is the
// only part that tells an operator what to fix.
const refused = await probe("http://127.0.0.1:1/", null);
check("연결 실패도 결과로 돌아옴", refused.ok, false);
check("상태 코드는 없음", refused.status, null);
check("실패 이유가 비어 있지 않음", refused.error !== null && refused.error.length > 0, true);
check("원인이 메시지에 붙음", refused.error.includes("("), true);
check("판정 기준이 결과에 남음", refused.expect, "2xx 응답");

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
