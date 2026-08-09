#!/usr/bin/env node
// Rehearsal traffic generator: drives normal + abnormal HTTP requests at the
// task-3 endpoints so the whole detect -> recommend -> simulate -> apply flow
// can be exercised before the competition, without a real attacker.
//
// This only sends HTTP requests to a target you specify -- it changes nothing
// in AWS or Kubernetes. Use it against your own dashboard/ALB endpoint only.
//
//   node scripts/attack-sim.mjs --target https://<alb-or-cloudfront-host> [opts]
//
// Options:
//   --target <url>     base URL (required)
//   --duration <sec>   how long to run (default 60)
//   --rps <n>          approx requests/sec (default 20)
//   --scenario <name>  normal | ip-flood | path-flood | bad-ua | sqli | mixed
//                      (default mixed)
//   --dry              print the plan and exit without sending

const args = process.argv.slice(2);
function opt(name, fallback) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}
const has = (name) => args.includes(`--${name}`);

const target = opt("target", "");
const duration = Number(opt("duration", "60"));
const rps = Number(opt("rps", "20"));
const scenario = opt("scenario", "mixed");
const dry = has("dry");

if (!target) {
  console.error("--target <url> 필수. 예: node scripts/attack-sim.mjs --target https://skills-alb-xxx.ap-northeast-2.elb.amazonaws.com");
  process.exit(1);
}

const NORMAL_PATHS = ["/v1/user", "/v1/product", "/healthcheck"];
const NORMAL_UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
];

// Deterministic pseudo-random (seeded) so runs are repeatable and reviewable.
let seed = 1337;
function rand() {
  seed = (seed * 1103515245 + 12345) & 0x7fffffff;
  return seed / 0x7fffffff;
}
const pick = (arr) => arr[Math.floor(rand() * arr.length)];

function buildRequest() {
  switch (scenario) {
    case "normal":
      return { path: pick(NORMAL_PATHS), method: "GET", ua: pick(NORMAL_UAS) };
    case "ip-flood":
      // same client hammering one path (WAF sees one ClientIP dominating)
      return { path: "/v1/product", method: "GET", ua: pick(NORMAL_UAS), xff: "203.0.113.45" };
    case "path-flood":
      return { path: "/v1/stress", method: "POST", ua: pick(NORMAL_UAS) };
    case "bad-ua":
      return { path: "/v1/user", method: "GET", ua: "sqlmap/1.7-dev" };
    case "sqli":
      return {
        path: "/v1/user",
        method: "GET",
        ua: "python-requests/2.31",
        query: "id=1%27%20OR%20%271%27%3D%271",
      };
    case "mixed":
    default: {
      const r = rand();
      if (r < 0.6) return { path: pick(NORMAL_PATHS), method: "GET", ua: pick(NORMAL_UAS) };
      if (r < 0.75) return { path: "/v1/product", method: "GET", ua: pick(NORMAL_UAS), xff: "203.0.113.45" };
      if (r < 0.9) return { path: "/v1/user", method: "GET", ua: "sqlmap/1.7-dev" };
      return { path: "/v1/user", method: "GET", ua: "python-requests/2.31", query: "id=1%27%20OR%201%3D1" };
    }
  }
}

const total = duration * rps;
console.log(`대상: ${target}`);
console.log(`시나리오: ${scenario} · ${rps} rps · ${duration}s · 총 ~${total}건`);
console.log("주의: 지정한 대상에만 HTTP 요청을 보냄. AWS/K8s 변경 없음.\n");

if (dry) {
  console.log("샘플 요청 5건:");
  for (let i = 0; i < 5; i++) {
    const r = buildRequest();
    console.log(`  ${r.method} ${r.path}${r.query ? `?${r.query}` : ""}  UA="${r.ua}"${r.xff ? `  XFF=${r.xff}` : ""}`);
  }
  console.log("\n--dry 모드 — 실제 전송 안 함.");
  process.exit(0);
}

let sent = 0;
let ok = 0;
let failed = 0;
const started = Date.now();

async function fire() {
  const r = buildRequest();
  const url = `${target.replace(/\/$/, "")}${r.path}${r.query ? `?${r.query}` : ""}`;
  const headers = { "User-Agent": r.ua };
  if (r.xff) headers["X-Forwarded-For"] = r.xff;
  try {
    const res = await fetch(url, { method: r.method, headers, redirect: "manual" });
    sent++;
    if (res.status < 500) ok++;
    else failed++;
  } catch {
    sent++;
    failed++;
  }
}

const intervalMs = 1000 / rps;
const timer = setInterval(() => {
  if (Date.now() - started >= duration * 1000) {
    clearInterval(timer);
    return;
  }
  void fire();
}, intervalMs);

const progress = setInterval(() => {
  process.stdout.write(`\r전송 ${sent}  성공(<500) ${ok}  실패(5xx/네트워크) ${failed}`);
}, 1000);

process.on("SIGINT", () => {
  clearInterval(timer);
  clearInterval(progress);
  console.log("\n중단됨.");
  process.exit(0);
});

setTimeout(
  () => {
    clearInterval(timer);
    setTimeout(() => {
      clearInterval(progress);
      console.log(`\n완료. 전송 ${sent} · 성공 ${ok} · 실패 ${failed}`);
      console.log("대시보드 WAF 탭에서 샘플 요청/추천 규칙을 확인하세요 (반영까지 수 분 소요될 수 있음).");
      process.exit(0);
    }, 1500);
  },
  duration * 1000 + 200,
);
