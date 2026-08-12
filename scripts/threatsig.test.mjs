// The contract: known offensive tools classify (even inside a Go client),
// Go's own client is bypassed (REQ-01), and ordinary browsers/libraries do NOT
// classify — a false positive here would block legitimate AI traffic.
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
check("empty UA does not classify", cat(""), null);

// --- Ordinary clients do not classify (false-positive guard) ---
check("Chrome browser does not classify", cat("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120"), null);
check("bare Mozilla/5.0 does not classify", cat("Mozilla/5.0"), null);
check("python-requests is not UA-blocked here", cat("python-requests/2.31"), null);
check("ELB health checker does not classify", cat("ELB-HealthChecker/2.0"), null);

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
