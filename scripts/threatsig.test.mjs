// The contract: this is an ALLOW list, not a deny list. Known offensive tools
// classify with their own category (even inside a Go client), the clients this
// environment expects — real browsers, Go's own client (REQ-01), AWS probes —
// are bypassed, and everything else classifies as UNKNOWN rather than passing.
//
// The inversion is the point. A deny list only catches attackers who announce
// themselves; "Mozilla/5.0 (compatible)" costs nothing to send and defeats
// every signature list. What it costs is that a legitimate client nobody put on
// the allow list is reported too, which is why UNKNOWN is a separate category
// the anomaly detector ignores and only the rule assembler acts on.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { classifyUa, queryHasBase64Blob, spoofedUaPatterns } = await import(`${SRC}threatsig.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};
const cat = (ua) => classifyUa(ua)?.category ?? null;

// --- Go bypass (REQ-01) ---
check("Go-http-client is bypassed", cat("Go-http-client/2.0"), null);
check("Go-Language is bypassed", cat("Go-Language/1.21 client"), null);

// --- Expected clients are bypassed (false-positive guard) ---
// A real browser always names a rendering engine; that is the whole test.
check("Chrome browser does not classify", cat("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120"), null);
check("Safari does not classify", cat("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0"), null);
check("Firefox does not classify", cat("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"), null);
check("ELB health checker does not classify", cat("ELB-HealthChecker/2.0"), null);
check("kube-probe does not classify", cat("kube-probe/1.29"), null);
// This dashboard's own probe must never end up in a rule that blocks the next
// probe.
check("이 대시보드의 점검 요청은 통과", cat("skills-dashboard/traffic-check"), null);

// --- Everything else is reported, not passed ---
check("빈 UA 는 UNKNOWN", cat(""), "UNKNOWN");
// The case that motivated the inversion: a forged browser token naming no
// engine used to sail through every signature list.
check("엔진 없는 Mozilla/5.0 은 잡힌다", cat("Mozilla/5.0"), "UNKNOWN");
check("Mozilla/5.0 (compatible) 도 잡힌다", cat("Mozilla/5.0 (compatible)"), "UNKNOWN");
check("처음 보는 클라이언트는 UNKNOWN", cat("MyCorpAgent/3.1"), "UNKNOWN");
check("UNKNOWN 라벨은 첫 토큰", classifyUa("MyCorpAgent/3.1")?.label, "mycorpagent");
check("빈 UA 라벨은 사람이 읽을 수 있게", classifyUa("")?.label, "(빈 User-Agent)");

// --- HTTP libraries and headless browsers: automation, not a named weapon ---
check("python-requests 는 AUTOMATION", cat("python-requests/2.31"), "AUTOMATION");
check("curl 은 AUTOMATION", cat("curl/8.4.0"), "AUTOMATION");
check("wget 은 AUTOMATION", cat("Wget/1.21.4"), "AUTOMATION");
check("headless chrome 은 AUTOMATION", cat("Mozilla/5.0 HeadlessChrome/120.0.0.0"), "AUTOMATION");
check("okhttp 은 AUTOMATION", cat("okhttp/4.12.0"), "AUTOMATION");
// Ordering: a named tool outranks the library it is built on.
check("sqlmap 이 python 보다 우선", cat("sqlmap/1.7 (python-requests/2.31)"), "SCANNER");
// And a payload outranks a forged browser token.
check("UA 안의 페이로드가 브라우저 위장을 이긴다", cat("Mozilla/5.0 (KHTML, like Gecko) ${jndi:ldap://x/a}"), "SPOOFED");

// --- Scanner tools classify ---
check("sqlmap is a scanner", cat("sqlmap/1.7.2#stable"), "SCANNER");
check("nikto is a scanner", cat("Mozilla/5.00 (Nikto/2.1.6)"), "SCANNER");
check("dirbuster is a scanner", cat("DirBuster-1.0-RC1"), "SCANNER");
check("acunetix is a scanner", cat("acunetix-wvs"), "SCANNER");

// --- Recon tools classify ---
check("nmap is recon", cat("Mozilla/5.0 (compatible; Nmap Scripting Engine)"), "RECON");
check("masscan is recon", cat("masscan/1.3"), "RECON");

// --- Tool signature wins over the Go bypass (gobuster/zgrab are Go-based) ---
check("gobuster inside a Go client still classifies", cat("Go-http-client/2.0 gobuster/3.6"), "SCANNER");
check("zgrab classifies despite Go", cat("Go-http-client/1.1 zgrab/0.x"), "RECON");

// --- Spoofed / obfuscated ---
check("Log4Shell in the UA is spoofed", cat("${jndi:ldap://x/a}"), "SPOOFED");
check("SQLi in the UA is spoofed", cat("Mozilla/5.0' OR 1=1--"), "SPOOFED");
check("gibberish Mozilla is spoofed", cat("Mozilla/5.0 (asdfghjklqwertyuiopzxcvbnm)"), "SPOOFED");
check("base64 blob UA is spoofed", cat("Z2V0fHBvc3RfZGF0YV9leGZpbHRyYXRpb24="), "SPOOFED");
check("label is reported", classifyUa("sqlmap/1.7")?.label, "sqlmap");

// --- Base64-obfuscated query ---
check("base64 blob in query is flagged", queryHasBase64Blob("cmd=Z2V0fHBvc3RfZGF0YV9leGZpbA=="), true);
check("ordinary query is not flagged", queryHasBase64Blob("id=3&name=kim"), false);
check("short token is not a blob", queryHasBase64Blob("id=YWJj"), false);
check("empty query is not flagged", queryHasBase64Blob(""), false);

// --- A SPOOFED label is a category name, so it needs a real regex ---
// A rule that used the label as a literal would match nothing at all. Each
// spoofed classification must hand back patterns that match the UA that
// produced it, and leave ordinary browsers alone.
const BROWSER =
  "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120";
const spoofedHits = (ua) => {
  const label = classifyUa(ua)?.label ?? "";
  return spoofedUaPatterns(label).some((p) => new RegExp(p).test(ua.toLowerCase()));
};
check("jndi UA is matched by its own patterns", spoofedHits("${jndi:ldap://x/a}"), true);
check("SQLi-in-UA is matched by its own patterns", spoofedHits("Mozilla/5.0' OR 1=1--"), true);
check("base64 UA is matched by its own patterns", spoofedHits("Z2V0fHBvc3RfZGF0YV9leGZpbA=="), true);
check(
  "gibberish Mozilla is matched by its own patterns",
  spoofedHits("Mozilla/5.0 (asdfghjklqwertyuiopzxcvbnm)"),
  true,
);
for (const label of ["injection-in-ua", "base64-ua", "malformed-mozilla"]) {
  check(
    `${label} patterns do not fire on a real browser`,
    spoofedUaPatterns(label).some((p) => new RegExp(p).test(BROWSER)),
    false,
  );
  check(
    `${label} patterns are lowercase-only`,
    spoofedUaPatterns(label).every((p) => !/[A-Z]/.test(p)),
    true,
  );
}
check("an unknown label yields no patterns", spoofedUaPatterns("sqlmap"), []);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
