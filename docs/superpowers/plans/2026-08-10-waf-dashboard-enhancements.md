# WAF 대시보드 확장 (파트 C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 잘리는 텍스트에 뷰포트 안에 머무는 반투명 툴팁을 대시보드 전역에 달고, 규칙 평가기가 로컬에서 판정 가능한 WAFv2 문법(GeoMatch·추가 TextTransformation)을 최대한 지원하며, 악성 클라이언트(스캐너/정찰 툴·위조 UA·base64 난독 쿼리)를 이상 탐지와 WAF 추천에 반영하고, 샌드박스에 악성 예시 요청을 넣어 규칙의 true-positive를 확인한다.

**Architecture:** 위협 시그니처 판정은 AWS 의존이 없는 순수 모듈 `threatsig.ts` 하나로 모으고, 이상 탐지(`anomaly.ts`)와 WAF 추천(`waf.ts`)이 이를 공유한다. 평가기 확장은 기존 순수 모듈 `rulestatement.ts`/`rulesim.ts`에 문법을 더하되 **로컬에서 결정 불가한 것은 계속 UNKNOWN**(Sqli/Xss/Managed/RateBased은 그대로)이다. 툴팁은 `shared.tsx`의 단일 `Tooltip` 컴포넌트로 만들어 모든 잘림 지점이 재사용한다.

**Tech Stack:** Next.js 15 App Router, React 19, TypeScript strict(`noUncheckedIndexedAccess`), Tailwind v4. 평가기·위협 모듈은 표준 JS만 사용, AWS SDK 임포트 없음. 테스트는 파트 A의 Node 타입 스트리핑 하네스 — **새 의존성 없음**.

## Global Constraints

- 브랜치: `feat/waf-log-query-and-rule-sandbox`. `main` 직접 커밋 금지
- **선행 조건: 파트 A·B 완료.** `scripts/testing/register.mjs`, `rulestatement.ts`, `rulesim.ts`, `SandboxTab.tsx` 존재
- 새 npm 의존성 추가 금지 (dev 포함)
- 순수 모듈(`threatsig.ts`, `rulestatement.ts`, `rulesim.ts`)은 AWS SDK 임포트 금지
- 모든 서버 액션은 `ok()`/`fail()` 패턴, 절대 throw 금지
- **로컬에서 판정 불가는 UNKNOWN. 절대 PASS 아님** — 파트 B의 핵심 불변식 유지
- **REQ-01 (Go 바이패스):** User-Agent에 `Go-http-client/` 또는 `Go-Language` 포함 요청은 정상 AI 트래픽 — 이상 플래그·차단 추천 대상에서 제외. 단 알려진 공격 툴 시그니처(gobuster·zgrab 등)가 함께 있으면 시그니처가 우선해 차단
- **REQ-02 (고성능 차단):** 추천 규칙은 ByteMatch 인덱스 매칭 + Action Block + 정적 403/400 응답을 전제로 문구화. Rate-based 금지(기존 `ddos-policy` 테스트가 강제)
- **회귀 불변식:** `scripts/ddos-policy.test.mjs`는 계속 통과해야 한다 — Go-http-client는 바이패스되어 loadgen/scan 이상 개수 불변, evidence에 IP 없음, `generateRecommendations` 본문에 `RateBasedStatement:`/`kind: "RATE_BASED"` 문자열 없음
- 사용자 노출 문구 한국어, 코드 주석 영어
- 각 태스크 종료 시 `npx tsc --noEmit` 통과

## 스펙과의 의도적 결정 2건

1. **악성 UA 5분류 중 라이브러리/스크래퍼(카테고리 3·4)는 UA 단독으로 차단 추천하지 않는다.** REQ-01이 Go 기본 클라이언트를 정상으로 규정하고, python-requests·axios 같은 일반 라이브러리도 정상 클라이언트가 흔히 쓰므로 UA 단독 차단은 오탐 위험이 크다. 명백한 공격 툴(카테고리 1·2)과 위조/주입 UA(카테고리 5), base64 난독 쿼리만 시그니처로 판정한다.
2. **`SearchString`은 파트 B대로 평문만 해석**한다. base64 판별 불가 근거는 파트 B 스펙에 이미 기록됨. 본 파트는 그 규칙을 바꾸지 않는다.

---

## File Structure

| 파일 | 책임 |
|---|---|
| `src/lib/server/threatsig.ts` (신규, 순수) | UA 분류(`classifyUa`), base64 블롭·위조 Mozilla·UA 주입 판정. AWS 의존 없음 |
| `scripts/threatsig.test.mjs` (신규) | 위협 판정 단위 테스트 (Go 바이패스·툴 시그니처 우선·오탐 방지) |
| `src/lib/server/anomaly.ts` (수정) | `MALICIOUS_CLIENT_SUSPECTED` 탐지 추가 (threatsig 사용, IP evidence 없음) |
| `src/lib/types.ts` (수정) | `AnomalyType`에 항목 추가; `TestRequest.country`·`TestRequest.benign`; `RuleTestOutcome`에 `CAUGHT`; `RuleTestResult.caught/missed` |
| `scripts/ddos-policy.test.mjs` (수정) | 신규 탐지가 회귀 불변식을 깨지 않음을 고정하는 케이스 추가 |
| `src/lib/server/waf.ts` (수정) | 스캐너/정찰 UA·base64 쿼리 ByteMatch Block 추천 (REQ-01 바이패스, REQ-02 문구) |
| `src/lib/server/rulestatement.ts` (수정) | `GeoMatchStatement` 평가, 추가 TextTransformation(BASE64_DECODE·CMD_LINE·REMOVE_NULLS·NORMALIZE_PATH) |
| `scripts/rulestatement.test.mjs` (수정) | country 필드·GeoMatch·새 transform 케이스; BASE64_DECODE UNKNOWN 예시를 실제 미지원 transform으로 교체 |
| `src/lib/server/rulesim.ts` (수정) | `defaultTestRequests`에 country; `maliciousExampleRequests()`; benign 인지 판정·`CAUGHT`·verdict |
| `scripts/rulesim.test.mjs` (수정) | country·악성 예시·CAUGHT·verdict 케이스 |
| `src/app/actions/dashboard.ts` (수정) | `getMaliciousExampleRequestsAction` |
| `src/app/dashboard/ui/shared.tsx` (수정) | `Tooltip`·`Truncate` 컴포넌트 (반투명, 뷰포트 클램프) |
| `src/app/dashboard/ui/*.tsx` (수정) | 잘림/`title` 지점을 `Truncate`로 교체 |
| `src/app/dashboard/ui/SandboxTab.tsx` (수정) | 악성 예시 추가 버튼·CAUGHT 표시·결과 열 `Truncate` |

---

## Task 1: 위협 시그니처 순수 모듈

**Files:**
- Create: `src/lib/server/threatsig.ts`
- Create: `scripts/threatsig.test.mjs`
- Modify: `package.json` (scripts)

**Interfaces:**
- Consumes: 파트 A 테스트 진입점
- Produces:
  - `type ThreatCategory = "SCANNER" | "RECON" | "SPOOFED"`
  - `classifyUa(ua: string): { category: ThreatCategory; label: string } | null`
  - `queryHasBase64Blob(query: string): boolean`

- [ ] **Step 1: 실패하는 테스트 작성**

`scripts/threatsig.test.mjs`:

```js
// The contract: known offensive tools classify (even inside a Go client),
// Go's own client is bypassed (REQ-01), and ordinary browsers/libraries do NOT
// classify — a false positive here would block legitimate AI traffic.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { classifyUa, queryHasBase64Blob } = await import(`${SRC}threatsig.ts`);

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

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
```

`package.json`의 `scripts`: `test` 체인 끝에 `&& pnpm test:threatsig`를 붙이고 항목 추가:

```json
    "test:threatsig": "node --import ./scripts/testing/register.mjs scripts/threatsig.test.mjs",
```

- [ ] **Step 2: 실패 확인**

Run: `pnpm test:threatsig`
Expected: FAIL — `ERR_MODULE_NOT_FOUND` (`threatsig.ts` 없음)

- [ ] **Step 3: 순수 모듈 구현**

`src/lib/server/threatsig.ts`:

```ts
import "server-only";

// Threat classification for a synthetic or sampled request's User-Agent and
// query. Pure and AWS-free so it is shared by anomaly detection, the WAF
// recommender, and the rule sandbox, and unit-tested without a cloud call.
export type ThreatCategory = "SCANNER" | "RECON" | "SPOOFED";

// Go's default HTTP client is the competition's load generator and the expected
// AI-agent traffic (REQ-01): always allowed, unless an explicit tool signature
// below fires first.
const GO_ALLOW_RE = /go-http-client\/|go-language/i;

// Named offensive tools. A hit is an unambiguous attack signature.
const SCANNER_TOOLS = [
  "sqlmap", "nikto", "acunetix", "dirbuster", "dirb", "w3af", "netsparker",
  "zaproxy", "gobuster", "wpscan", "arachni", "nessus", "openvas", "commix",
];
const RECON_TOOLS = ["nmap", "masscan", "zgrab", "censysinspect", "zmap"];

// Word-ish boundary: tool names sit next to /, digits, spaces or string edges.
const SCANNER_RE = new RegExp(`(^|[^a-z])(${SCANNER_TOOLS.join("|")})([^a-z]|$)`, "i");
const RECON_RE = new RegExp(`(^|[^a-z])(${RECON_TOOLS.join("|")})([^a-z]|$)`, "i");

// Injection payloads smuggled into the UA field (Log4Shell, SQLi, OS command).
const UA_INJECTION_RE =
  /(\$\{jndi:|\bunion\s+select\b|['"]\s*or\s+1\s*=\s*1|;\s*(cat|wget|curl|nc|bash|sh)\b)/i;

// A standalone base64 blob long enough to hide a payload.
const B64_BLOB_RE = /(^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})($|[^A-Za-z0-9+/=])/;

function hasBase64Blob(s: string): boolean {
  const m = B64_BLOB_RE.exec(s);
  const blob = m?.[2] ?? "";
  return blob.length >= 24 && blob.length % 4 === 0;
}

// Starts like a browser but names no rendering engine and carries a long
// unbroken letter run no real token has — reads as filler.
function isMalformedMozilla(ua: string): boolean {
  if (!/^mozilla\/\d/i.test(ua)) return false;
  const hasEngine =
    /(applewebkit|gecko|trident|khtml|presto|chrome|firefox|safari|edg|opr)\b/i.test(ua);
  return !hasEngine && /[a-z]{20,}/i.test(ua);
}

export function classifyUa(ua: string): { category: ThreatCategory; label: string } | null {
  const scan = SCANNER_RE.exec(ua);
  if (scan) return { category: "SCANNER", label: (scan[2] ?? "scanner").toLowerCase() };
  const recon = RECON_RE.exec(ua);
  if (recon) return { category: "RECON", label: (recon[2] ?? "recon").toLowerCase() };
  // The Go bypass applies only after explicit tool signatures are ruled out.
  if (GO_ALLOW_RE.test(ua)) return null;
  if (UA_INJECTION_RE.test(ua)) return { category: "SPOOFED", label: "injection-in-ua" };
  if (isMalformedMozilla(ua)) return { category: "SPOOFED", label: "malformed-mozilla" };
  if (hasBase64Blob(ua)) return { category: "SPOOFED", label: "base64-ua" };
  return null;
}

export function queryHasBase64Blob(query: string): boolean {
  return hasBase64Blob(query);
}
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `pnpm test:threatsig`
Expected: 전부 `PASS`, `ALL PASS`. 특히 Go 바이패스 3건, 오탐 방지 4건, 툴 시그니처 우선 2건이 통과해야 한다.

- [ ] **Step 5: 타입체크 + 커밋**

Run: `npx tsc --noEmit`
Expected: 출력 없음

```bash
git add src/lib/server/threatsig.ts scripts/threatsig.test.mjs package.json
git commit -m "Add a pure threat-signature module for UA and query classification"
```

---

## Task 2: 이상 탐지 통합

`detectAnomalies`에 악성 클라이언트 탐지를 추가한다. Go 바이패스와 IP-무기록 정책을 지키고, 회귀 불변식(`ddos-policy` 테스트)을 깨지 않는다.

**Files:**
- Modify: `src/lib/types.ts` (`AnomalyType`)
- Modify: `src/lib/server/anomaly.ts`
- Modify: `scripts/ddos-policy.test.mjs`

**Interfaces:**
- Consumes: Task 1의 `classifyUa`, `queryHasBase64Blob`; 기존 `HttpSummary.byUa`/`queryPatterns`, `push(...)` 클로저, `escalate`
- Produces: `Anomaly`(type `MALICIOUS_CLIENT_SUSPECTED`) — evidence는 UA 라벨·건수와 base64 쿼리 사실만, **IP 없음**

- [ ] **Step 1: 타입에 항목 추가**

`src/lib/types.ts`의 `AnomalyType` 유니온에 `MALICIOUS_CLIENT_SUSPECTED`를 추가한다 (기존 항목 뒤, `UNKNOWN_ANOMALY` 앞):

```ts
  | "MALICIOUS_CLIENT_SUSPECTED"
```

- [ ] **Step 2: 회귀 고정 테스트 추가**

`scripts/ddos-policy.test.mjs`의 마지막 `console.log(...ALL PASS...)` 앞에 추가한다. 기존 `summary`/`input`/`detectAnomalies` 헬퍼를 재사용한다:

```js
// New malicious-client detection must not disturb the volumetric policy:
// Go-http-client is bypassed, so the load generator and the off-surface scan
// (both Go UA) keep their existing anomaly counts.
const malicious = (as) => as.filter((a) => a.type === "MALICIOUS_CLIENT_SUSPECTED");
check("Go load generator raises no malicious-client anomaly", malicious(loadGen).length, 0);
check("Go off-surface scan raises no malicious-client anomaly", malicious(scan).length, 0);
check("Mozilla traffic raises no malicious-client anomaly", malicious(mixed).length, 0);

// A named scanner tool in the UA mix does raise one, citing the tool, never an IP.
const scanner = detectAnomalies(
  input(summary(
    [{ path: "/v1/user", count: 500, blocked: 0, lowPriority: false }],
    [{ key: "sqlmap/1.7", count: 60 }],
  )),
);
check("scanner UA raises a malicious-client anomaly", malicious(scanner).length, 1);
check(
  "malicious-client finding cites no source IP",
  malicious(scanner)[0]?.evidence.some((e) => e.includes("203.0.113.7")) ?? true,
  false,
);
check(
  "malicious-client finding names the tool",
  malicious(scanner)[0]?.evidence.some((e) => e.toLowerCase().includes("sqlmap")) ?? false,
  true,
);
```

- [ ] **Step 3: 실패 확인**

Run: `pnpm test:ddos`
Expected: FAIL — 새 케이스가 아직 구현되지 않아 `malicious(scanner).length`가 0

- [ ] **Step 4: 탐지기 구현**

`src/lib/server/anomaly.ts` 상단 import에 추가:

```ts
import { classifyUa, queryHasBase64Blob } from "./threatsig";
```

`TRAFFIC_ANOMALY_SUSPECTED` 블록(현재 `input.httpSummary` 가드 안, 그 탐지 직후)에 이어서 추가한다. `push`/`escalate`/`total` 등 주변 지역 변수는 기존 블록과 같은 스코프이므로 그대로 쓴다. **IP는 절대 넣지 않는다.**

```ts
    // Malicious-client signatures in the sampled UA/query mix. Independent of
    // request volume — a single scanner fingerprint is a finding — and blind to
    // source IP by policy. The Go client is bypassed inside classifyUa (REQ-01).
    const flaggedUa = input.httpSummary.byUa
      .map((u) => ({ hit: classifyUa(u.key), key: u.key, count: u.count }))
      .filter((x): x is { hit: NonNullable<ReturnType<typeof classifyUa>>; key: string; count: number } => x.hit !== null);
    const b64Query = input.httpSummary.queryPatterns.filter((q) => queryHasBase64Blob(q.key));
    if (flaggedUa.length > 0 || b64Query.length > 0) {
      const evidence: string[] = [];
      for (const f of flaggedUa.slice(0, 5)) {
        evidence.push(`악성 클라이언트 UA "${f.key}" (${f.hit.category}/${f.hit.label}): ${f.count}건`);
      }
      for (const q of b64Query.slice(0, 3)) {
        evidence.push(`base64 난독화 쿼리 의심: "${q.key.slice(0, 60)}"`);
      }
      const hasScanner = flaggedUa.some((f) => f.hit.category !== "SPOOFED");
      push(
        "MALICIOUS_CLIENT_SUSPECTED",
        hasScanner ? "CRITICAL" : "WARNING",
        "악성 클라이언트 시그니처 탐지",
        "샘플 트래픽에서 스캐너·정찰 툴 또는 위조/난독 시그니처가 관측됨",
        evidence,
        "HIGH",
      );
    }
```

`push`의 시그니처가 `push(type, base, title, detail, evidence, confidence)`와 다르면(파트별 구현 차이) 기존 호출부의 인자 순서를 그대로 따른다 — 새 문법을 발명하지 말고 같은 파일의 다른 `push(...)` 호출을 복제해 맞춘다. `base`가 `Status`(`"CRITICAL"|"WARNING"|"NORMAL"`) 타입이 아니면 해당 파일의 severity 표기를 따른다.

- [ ] **Step 5: 테스트 통과 + 회귀**

Run: `pnpm test:ddos`
Expected: 기존 케이스 전부 + 신규 6케이스 `PASS`, `ALL PASS`. 특히 `Go ... raises no malicious-client anomaly` 3건과 `scanner UA raises ... 1`이 통과해야 한다.

Run: `pnpm test`
Expected: 모든 suite `ALL PASS`

- [ ] **Step 6: 타입체크 + 커밋**

Run: `npx tsc --noEmit`
Expected: 출력 없음

```bash
git add src/lib/types.ts src/lib/server/anomaly.ts scripts/ddos-policy.test.mjs
git commit -m "Detect malicious-client signatures in traffic without citing IPs"
```

---

## Task 3: WAF 추천 — 스캐너 UA · base64 쿼리 차단

`generateRecommendations`에 명백한 공격 시그니처에 대한 ByteMatch Block 추천을 더한다. REQ-01(Go 바이패스)·REQ-02(정적 403·인덱스 매칭 문구)를 지키고, 회귀 grep(`RateBasedStatement:`/`kind: "RATE_BASED"` 부재)을 깨지 않는다.

**Files:**
- Modify: `src/lib/server/waf.ts`

**Interfaces:**
- Consumes: Task 1의 `classifyUa`; 기존 `summary.byUa`, `summary.queryPatterns`, `hash`, `utf8`, `recs`(StoredRecommendation 배열), `WafRecommendation`
- Produces: 추가 `WafRecommendation`(kind `"BYTE_MATCH"`, action `"BLOCK"`)

- [ ] **Step 1: import 추가**

`src/lib/server/waf.ts` 상단 import 블록에:

```ts
import { classifyUa, queryHasBase64Blob } from "./threatsig";
```

- [ ] **Step 2: 스캐너 UA 차단 추천 추가**

`generateRecommendations` 본문의 기존 UA-match(COUNT) 추천 블록 **뒤에** 추가한다. 기존 ua-match는 top UA만 보지만, 스캐너는 상위권에 없어도 잡아야 하므로 `summary.byUa` 전체를 훑는다. `utf8`/`hash`는 같은 파일의 기존 헬퍼다. **`RateBasedStatement`/`RATE_BASED` 문자열을 쓰지 않는다.**

```ts
  // Unambiguous offensive-tool and spoofed-UA signatures get a Block rule, not
  // a Count one: these are never legitimate traffic. REQ-02 — ByteMatch is an
  // indexed, sub-millisecond match at the WAF edge returning a static 403, so
  // the backend never sees the request. The Go client is bypassed in classifyUa
  // (REQ-01); gobuster/zgrab still hit because a tool signature wins.
  const seenSig = new Set<string>();
  for (const ua of summary.byUa) {
    const hit = classifyUa(ua.key);
    if (!hit || seenSig.has(hit.label)) continue;
    seenSig.add(hit.label);
    const needle = hit.label;
    const id = `bytematch-threat-${Math.abs(hash(needle))}`;
    recs.push({
      isManagedGroup: false,
      statement: {
        ByteMatchStatement: {
          SearchString: utf8(needle),
          FieldToMatch: { SingleHeader: { Name: "user-agent" } },
          TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
          PositionalConstraint: "CONTAINS",
        },
      },
      rec: {
        id,
        kind: "BYTE_MATCH",
        name: "dash-threat-ua",
        targetPattern: `공격 시그니처 UA "${needle}" (${hit.category})`,
        criteria: { userAgent: needle },
        threshold: null,
        evaluationWindowSec: null,
        action: "BLOCK",
        confidence: "HIGH",
        reason: `알려진 ${hit.category === "SCANNER" ? "취약점 스캐너" : hit.category === "RECON" ? "정찰 스캐너" : "위조/난독"} 시그니처 "${needle}" 관측. ByteMatch(CONTAINS, lowercase) 인덱스 매칭으로 최전단에서 즉시 차단.`,
        evidence: [`UA "${ua.key}": ${ua.count}건`],
        expectedImpact: "정적 403 응답 — 백엔드 도달 전 WAF에서 종료되므로 응답 시간 영향 없음. 정상 Go/브라우저 트래픽은 매칭되지 않음.",
        falsePositiveRisk: "LOW",
        hasScopeDown: false,
        ruleJson: "",
      },
    });
  }
```

- [ ] **Step 3: base64 난독 쿼리 차단 추천 추가**

바로 뒤에 추가한다. `queryPatterns` 중 base64 블롭이 있으면 상위 1건에 대해 Block 추천:

```ts
  const b64q = summary.queryPatterns.find((q) => queryHasBase64Blob(q.key));
  if (b64q) {
    const id = `bytematch-b64query-${Math.abs(hash(b64q.key))}`;
    recs.push({
      isManagedGroup: false,
      statement: {
        ByteMatchStatement: {
          SearchString: utf8(b64q.key.slice(0, 60)),
          FieldToMatch: { QueryString: {} },
          TextTransformations: [{ Priority: 0, Type: "URL_DECODE" }],
          PositionalConstraint: "CONTAINS",
        },
      },
      rec: {
        id,
        kind: "BYTE_MATCH",
        name: "dash-b64-query",
        targetPattern: `base64 난독 쿼리 "${b64q.key.slice(0, 40)}"`,
        criteria: { query: b64q.key.slice(0, 60) },
        threshold: null,
        evaluationWindowSec: null,
        action: "COUNT",
        confidence: "MEDIUM",
        reason: "쿼리 문자열에 base64로 인코딩된 페이로드 의심 패턴 관측. 우선 COUNT로 관찰 후 차단 권장 — 정상 base64 파라미터 오탐 가능.",
        evidence: [`쿼리 "${b64q.key.slice(0, 60)}": ${b64q.count}건`],
        expectedImpact: "해당 인코딩 문자열 포함 요청 계측 — 오탐 없음 확인 후 Block 전환.",
        falsePositiveRisk: "MEDIUM",
        hasScopeDown: false,
        ruleJson: "",
      },
    });
  }
```

`WafRecommendation`의 `criteria` 타입에 `query` 키가 없으면, 같은 파일의 query-match 추천이 쓰는 실제 키 이름을 따른다(예: `criteria: { queryString: ... }`). 필드명이 다르면 그 파일 관례에 맞춘다 — 발명 금지.

- [ ] **Step 4: 회귀 grep 확인**

Run: `pnpm test:ddos`
Expected: `generateRecommendations builds no RateBasedStatement`·`emits no RATE_BASED kind`가 계속 `PASS`, `ALL PASS`

- [ ] **Step 5: 타입체크 + 커밋**

Run: `npx tsc --noEmit`
Expected: 출력 없음

```bash
git add src/lib/server/waf.ts
git commit -m "Recommend Block rules for scanner UAs and obfuscated queries"
```

---

## Task 4: 평가기 문법 확대 (GeoMatch · 추가 TextTransformation)

로컬에서 결정 가능한 문법을 더 지원한다. GeoMatch를 위해 `TestRequest.country`를 추가하고, 결정적 변환 4종을 구현한다. **Sqli/Xss/Managed/RateBased·모델 밖 필드(Body 등)는 계속 UNKNOWN.**

**Files:**
- Modify: `src/lib/types.ts` (`TestRequest.country`)
- Modify: `src/lib/server/rulestatement.ts`
- Modify: `scripts/rulestatement.test.mjs`

**Interfaces:**
- Consumes: 없음(순수)
- Produces: `evalStatement`가 `GeoMatchStatement`와 transform `BASE64_DECODE`/`CMD_LINE`/`REMOVE_NULLS`/`NORMALIZE_PATH` 지원

- [ ] **Step 1: 타입에 country 추가**

`src/lib/types.ts`의 `TestRequest`에 마지막 필드로 추가:

```ts
  // ISO 3166-1 alpha-2 country code for GeoMatchStatement evaluation
  country: string;
```

- [ ] **Step 2: 실패하는 테스트 작성 (transform·GeoMatch)**

`scripts/rulestatement.test.mjs`를 수정한다.

(a) 상단 `REQ` 객체에 `country: "KR"`를 추가한다.

(b) 기존 `"an unknown transform is UNKNOWN, not a pass"` 케이스의 transform 타입을 `BASE64_DECODE`에서 실제 미지원 값으로 바꾼다(이제 BASE64_DECODE를 구현하므로):

```js
check(
  "an unknown transform is UNKNOWN, not a pass",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "MADE_UP_TRANSFORM" }])),
  "UNKNOWN",
);
```

(c) transform·GeoMatch 케이스를 SizeConstraint 블록 뒤에 추가한다:

```js
// --- Newly supported transforms (deterministic, locally decidable) ---
check(
  "BASE64_DECODE decodes the field",
  ev(byteMatch("attack", { QueryString: {} }, "CONTAINS", [{ Priority: 0, Type: "BASE64_DECODE" }]),
    { ...REQ, query: "YXR0YWNr" }),
  true,
);
check(
  "REMOVE_NULLS strips null bytes",
  ev(byteMatch("select", { QueryString: {} }, "CONTAINS", [{ Priority: 0, Type: "REMOVE_NULLS" }]),
    { ...REQ, query: "se le ct" }),
  true,
);
check(
  "NORMALIZE_PATH collapses traversal",
  ev(byteMatch("/v1/user", URI, "EXACTLY", [{ Priority: 0, Type: "NORMALIZE_PATH" }]),
    { ...REQ, path: "/v1/a/../user" }),
  true,
);
check(
  "CMD_LINE normalizes command punctuation",
  ev(byteMatch("cat /etc/passwd", { QueryString: {} }, "CONTAINS", [{ Priority: 0, Type: "CMD_LINE" }]),
    { ...REQ, query: "cat    /etc/passwd" }),
  true,
);

// --- GeoMatchStatement ---
const geo = (codes) => ({ GeoMatchStatement: { CountryCodes: codes } });
check("GeoMatch hit on country", ev(geo(["KR", "JP"])), true);
check("GeoMatch miss on country", ev(geo(["US", "CN"])), false);
check("GeoMatch is case-insensitive", ev(geo(["kr"])), true);
check("GeoMatch with empty codes is UNKNOWN", ev(geo([])), "UNKNOWN");
```

GeoMatch는 미지원 목록에서 빠지므로, 기존 unsupported 테스트 배열에 GeoMatch가 있으면 제거한다(없으면 그대로).

- [ ] **Step 3: 실패 확인**

Run: `pnpm test:rulestatement`
Expected: FAIL — BASE64_DECODE/GeoMatch 케이스 실패

- [ ] **Step 4: 구현**

`src/lib/server/rulestatement.ts`를 수정한다.

(a) `applyTransforms`의 `switch`에 케이스를 추가한다(`default: return null` 앞):

```ts
      case "BASE64_DECODE":
        try {
          out = Buffer.from(out, "base64").toString("utf8");
        } catch {
          // WAF leaves an undecodable value unchanged.
        }
        break;
      case "REMOVE_NULLS":
        out = out.replace(/ /g, "");
        break;
      case "NORMALIZE_PATH": {
        // Collapse repeated slashes and resolve ./ and ../ segments.
        const segs: string[] = [];
        for (const seg of out.split("/")) {
          if (seg === "" || seg === ".") continue;
          if (seg === "..") segs.pop();
          else segs.push(seg);
        }
        out = `/${segs.join("/")}`;
        break;
      }
      case "CMD_LINE":
        // AWS CMD_LINE: drop \ " ' ^, collapse whitespace to one space, lowercase.
        out = out
          .replace(/[\\"'^]/g, "")
          .replace(/\s+/g, " ")
          .trim()
          .toLowerCase();
        break;
```

`Buffer`는 Node 전역이라 import 불필요하고, 이 모듈은 `server-only`라 클라이언트 번들에 들어가지 않는다.

(b) `evalStatement`의 `SizeConstraintStatement` 블록 뒤, `UNSUPPORTED_STATEMENTS` 루프 앞에 GeoMatch를 추가한다:

```ts
  const geo = asRecord(s["GeoMatchStatement"]);
  if (geo) {
    const raw = Array.isArray(geo["CountryCodes"]) ? geo["CountryCodes"] : [];
    const codes = raw.map((c) => str(c)).filter((c): c is string => c !== null);
    if (codes.length === 0) {
      ctx.notes.add("GeoMatchStatement에 CountryCodes가 없음 — 평가 불가");
      return "UNKNOWN";
    }
    return codes.map((c) => c.toUpperCase()).includes(req.country.toUpperCase());
  }
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `pnpm test:rulestatement`
Expected: 전부 `PASS`, `ALL PASS`. 새 transform 4건·GeoMatch 4건 포함.

- [ ] **Step 6: 타입체크**

Run: `npx tsc --noEmit`
Expected: 출력 없음. `TestRequest.country`가 필수 필드가 되었으므로, `rulesim.ts`의 `defaultTestRequests` 등 `TestRequest`를 만드는 모든 곳에서 country 누락 오류가 나면 **여기서 멈추지 말고 Task 5에서 다룬다** — 단, `npx tsc --noEmit`을 통과시켜야 하므로 이 태스크에서 `rulesim.ts`의 기존 `TestRequest` 생성부에 `country: "KR"`를 최소 추가한다:
  - `defaultTestRequests`의 `APP_TRAFFIC_PATHS.map(...)` 객체, `loadgen`, `healthcheck` 각각에 `country: "KR"` 추가.

이 최소 수정 후 다시:

Run: `npx tsc --noEmit`
Expected: 출력 없음

- [ ] **Step 7: 전체 회귀 + 커밋**

Run: `pnpm test`
Expected: 모든 suite `ALL PASS` (rulesim의 기본 요청 6건 불변 — country 추가는 개수에 영향 없음)

```bash
git add src/lib/types.ts src/lib/server/rulestatement.ts src/lib/server/rulesim.ts scripts/rulestatement.test.mjs
git commit -m "Support GeoMatch and more text transforms in the evaluator"
```

---

## Task 5: 대시보드 전역 반투명 툴팁

잘리는 텍스트에 마우스를 올리면 전체 내용을 반투명 박스로 보여주고, 뷰포트 밖으로 나가지 않게 한다. 단일 `Truncate` 컴포넌트로 만들어 모든 잘림 지점에 적용한다.

**Files:**
- Modify: `src/app/dashboard/ui/shared.tsx`
- Modify: `src/app/dashboard/ui/OverviewTab.tsx`, `InvestigationTab.tsx`, `WafTab.tsx`, `RequestLogPanel.tsx`, `SandboxTab.tsx`

**Interfaces:**
- Consumes: 없음 (React만)
- Produces: `export function Truncate({ text, className }: { text: string; className?: string }): JSX.Element` — 잘린 텍스트 + 호버 시 뷰포트 클램프 반투명 툴팁

- [ ] **Step 1: Truncate 컴포넌트 작성**

`src/app/dashboard/ui/shared.tsx` 끝에 추가한다. 마운트된 포털 대신 `position: fixed` 스팬을 hover 좌표에서 렌더하고, 오른쪽/아래 넘침을 clamp한다:

```tsx
// Truncated inline text with a hover tooltip that shows the full value in a
// translucent box, clamped so it never leaves the viewport.
export function Truncate({ text, className = "" }: { text: string; className?: string }) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);

  const show = (e: React.MouseEvent<HTMLSpanElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    setPos({ x: r.left, y: r.bottom + 4 });
  };
  const hide = () => setPos(null);

  return (
    <span
      className={`truncate ${className}`}
      onMouseEnter={show}
      onMouseMove={pos ? undefined : show}
      onMouseLeave={hide}
    >
      {text}
      {pos && text && (
        <span
          role="tooltip"
          style={{
            position: "fixed",
            left: `min(${pos.x}px, calc(100vw - 20rem - 8px))`,
            top: pos.y,
            maxWidth: "20rem",
            zIndex: 50,
          }}
          className="pointer-events-none block max-h-40 overflow-hidden rounded border border-neutral-700 bg-neutral-900/85 px-2 py-1 text-[11px] whitespace-pre-wrap break-words text-neutral-100 shadow-lg backdrop-blur-sm"
        >
          {text}
        </span>
      )}
    </span>
  );
}
```

`useState`가 이미 이 파일에서 import되어 있는지 확인하고, 없으면 상단 `import { useState } from "react"` 목록에 추가한다.

- [ ] **Step 2: 잘림 지점 교체 — RequestLogPanel · SandboxTab (이번 브랜치 신규 UI)**

`RequestLogPanel.tsx`의 경로 셀:

```tsx
<td className="max-w-64 px-2 py-0.5">
  <Truncate text={r.path} />
</td>
```

`SandboxTab.tsx` 결과 표의 경로·User-Agent 셀도 `title` 대신 `<Truncate text={req?.path ?? ""} />` / `<Truncate text={req?.userAgent ?? ""} />`로 바꾼다. 두 파일 상단 `./shared` import에 `Truncate`를 추가한다.

- [ ] **Step 3: 잘림 지점 교체 — WafTab 샘플 표**

`WafTab.tsx`의 샘플 표에서 `title={s.path}`/`title={s.query}`/`title={s.userAgent}`/`title={s.rule}`가 달린 `truncate` 셀을 각각 `<Truncate text={s.path} />` 등으로 바꾼다. 헤더의 `상태` 힌트(`title={h.hint}`)는 잘림이 아니라 설명 툴팁이므로 그대로 둔다.

- [ ] **Step 4: 잘림 지점 교체 — Overview · Investigation**

`OverviewTab.tsx`의 pod name `truncate` 스팬 2곳, `InvestigationTab.tsx`의 `truncate` 스팬들과 `title={e.message}` Warning Event 메시지 셀, byPath 경로 스팬을 `<Truncate text={...} />`로 바꾼다. 각 파일에 `Truncate` import 추가. 레이아웃 폭 클래스(`max-w-*`)는 감싸는 `<td>`/부모에 유지한다.

- [ ] **Step 5: 타입체크 + 실제 확인**

Run: `npx tsc --noEmit`
Expected: 출력 없음

```bash
pnpm dev
```

`http://localhost:3100/dashboard`에서 확인:
- WAF 탭 샘플 표의 긴 UA/쿼리/룰에 마우스를 올리면 반투명 박스로 전체가 보이는지
- 화면 오른쪽 끝 셀에서도 박스가 잘리지 않고 왼쪽으로 밀려 뷰포트 안에 있는지
- 조사 탭 Warning Event 긴 메시지가 보이는지
- 마우스를 떼면 사라지는지

`.env`/AWS가 없어 데이터가 비어도 툴팁 동작 자체는 확인 가능. 확인 후 dev 서버 종료.

- [ ] **Step 6: 커밋**

```bash
git add src/app/dashboard/ui/shared.tsx src/app/dashboard/ui/OverviewTab.tsx src/app/dashboard/ui/InvestigationTab.tsx src/app/dashboard/ui/WafTab.tsx src/app/dashboard/ui/RequestLogPanel.tsx src/app/dashboard/ui/SandboxTab.tsx
git commit -m "Add a viewport-clamped translucent tooltip for truncated text"
```

---

## Task 6: 샌드박스 악성 예시 요청 + true-positive 판정

샌드박스 기본 요청은 정상 6건 그대로 두고, **악성 예시 요청**을 버튼으로 추가할 수 있게 한다. 악성 요청이 차단되는 것은 오탐이 아니라 정탐이므로 판정 로직을 benign/malicious 구분으로 바꾼다.

**Files:**
- Modify: `src/lib/types.ts` (`TestRequest.benign`, `RuleTestOutcome` `CAUGHT`, `RuleTestResult.caught/missed`)
- Modify: `src/lib/server/rulesim.ts`
- Modify: `scripts/rulesim.test.mjs`
- Modify: `src/app/actions/dashboard.ts`
- Modify: `src/app/dashboard/ui/SandboxTab.tsx`

**Interfaces:**
- Consumes: Task 1의 시그니처 감각(악성 예시 UA/쿼리), 기존 `testRule`
- Produces:
  - `maliciousExampleRequests(): TestRequest[]`
  - `getMaliciousExampleRequestsAction(): Promise<ActionResult<TestRequest[]>>`
  - `RuleTestResult.caught`, `RuleTestResult.missed`, outcome `"CAUGHT"`

- [ ] **Step 1: 타입 확장**

`src/lib/types.ts`:

(a) `TestRequest`에 추가:

```ts
  // false marks a deliberately malicious example — blocking it is a true
  // positive, not a false positive.
  benign: boolean;
```

(b) `RuleTestOutcome`에 `"CAUGHT"` 추가:

```ts
export type RuleTestOutcome = "PASS" | "BLOCKED" | "COUNTED" | "CAUGHT" | "UNKNOWN";
```

(c) `RuleTestResult`에 두 필드 추가(`counted` 뒤):

```ts
  // malicious examples the rule blocked (true positives)
  caught: number;
  // malicious examples the rule let through
  missed: number;
```

- [ ] **Step 2: 실패하는 테스트 작성**

`scripts/rulesim.test.mjs`를 수정한다.

(a) 기존 `defaults`는 이제 `benign: true`, `country: "KR"`를 갖는다. `defaults.length`가 6임은 불변. 다음 케이스를 추가한다(파일의 마지막 sum 케이스 앞):

```js
// --- Malicious example set ---
const evil = maliciousExampleRequests();
check("malicious examples are non-empty", evil.length > 0, true);
check("all malicious examples are flagged benign:false", evil.every((r) => r.benign === false), true);

// A rule that blocks /wp-login catches the malicious wp-login probe (true
// positive) and leaves the normal set alone.
const wp = testRule({
  ruleJson: rule(pathStarts("/wp-login"), { Block: {} }),
  requests: [...defaults, ...evil],
});
check("blocking a malicious example counts as caught, not blocked", wp.blocked, 0);
check("the malicious wp-login probe is caught", wp.caught >= 1, true);
check("a rule catching only malicious traffic stays SAFE", wp.verdict, "SAFE");

// Blocking a benign row is still a false-positive risk.
const overblock = testRule({
  ruleJson: rule(pathStarts("/v1"), { Block: {} }),
  requests: [...defaults, ...evil],
});
check("blocking benign /v1 rows is a false-positive risk", overblock.verdict, "FALSE_POSITIVE_RISK");
check("benign blocked rows are counted as blocked", overblock.blocked > 0, true);

// counts (incl. caught) always account for every row
check(
  "counts including caught sum to the row count",
  wp.passed + wp.blocked + wp.counted + wp.caught + wp.unknown,
  wp.rows.length,
);
```

(b) 파일 상단 import에 `maliciousExampleRequests`를 추가한다:

```js
const { testRule, defaultTestRequests, maliciousExampleRequests, RULE_JSON_MAX, MAX_REQUESTS, FIELD_MAX } =
  await import(`${SRC}rulesim.ts`);
```

- [ ] **Step 3: 실패 확인**

Run: `pnpm test:rulesim`
Expected: FAIL — `maliciousExampleRequests is not a function`, `CAUGHT` 미구현

- [ ] **Step 4: rulesim 구현**

`src/lib/server/rulesim.ts`를 수정한다.

(a) `defaultTestRequests`의 각 생성 객체에 `benign: true`를 추가한다(Task 4에서 이미 `country: "KR"` 추가됨).

(b) `maliciousExampleRequests`를 `defaultTestRequests` 뒤에 추가한다:

```ts
// Deliberately malicious sample requests. Blocking any of these is the point of
// a WAF rule — the sandbox scores them as caught, not as a false positive.
export function maliciousExampleRequests(): TestRequest[] {
  return [
    { id: "mal-wplogin", method: "GET", path: "/wp-login.php", query: "", userAgent: "Mozilla/5.0", ip: "203.0.113.7", country: "CN", benign: false },
    { id: "mal-sqlmap", method: "GET", path: "/v1/user", query: "id=1%20OR%201=1", userAgent: "sqlmap/1.7", ip: "203.0.113.8", country: "RU", benign: false },
    { id: "mal-env", method: "GET", path: "/.env", query: "", userAgent: "python-requests/2.31", ip: "203.0.113.9", country: "CN", benign: false },
    { id: "mal-jndi", method: "GET", path: "/v1/user", query: "", userAgent: "${jndi:ldap://x/a}", ip: "203.0.113.10", country: "US", benign: false },
    { id: "mal-b64", method: "GET", path: "/v1/product", query: "cmd=Z2V0fHBvc3RfZGF0YV9leGZpbA==", userAgent: "Mozilla/5.0", ip: "203.0.113.11", country: "CN", benign: false },
    { id: "mal-gobuster", method: "GET", path: "/admin", query: "", userAgent: "gobuster/3.6", ip: "203.0.113.12", country: "RU", benign: false },
  ];
}
```

(c) `validateRequests`의 필드 루프에 `["country", r.country]`를 추가한다.

(d) `outcomeFor`가 benign 여부를 알아야 한다. 시그니처를 바꾼다:

```ts
function outcomeFor(
  matched: boolean | null,
  action: Action,
  benign: boolean,
): { outcome: RuleTestRow["outcome"]; reason: string } {
  if (matched === null) {
    return { outcome: "UNKNOWN", reason: "규칙을 로컬에서 평가할 수 없음 — 미지원 문법 포함" };
  }
  if (!matched) {
    return benign
      ? { outcome: "PASS", reason: "정상 요청이 규칙에 매칭되지 않음 — 통과" }
      : { outcome: "PASS", reason: "악성 예시가 규칙에 걸리지 않음 — 미탐(놓침)" };
  }
  switch (action) {
    case "Block":
      return benign
        ? { outcome: "BLOCKED", reason: "정상 요청이 매칭되고 Block — 오탐 위험" }
        : { outcome: "CAUGHT", reason: "악성 예시가 매칭되고 Block — 정탐(차단)" };
    case "Count":
      return { outcome: "COUNTED", reason: "매칭되지만 Action이 Count — 차단되지 않고 계측만" };
    case "Allow":
      return { outcome: "PASS", reason: "규칙에 매칭되고 Action이 Allow — 통과" };
    default:
      return { outcome: "UNKNOWN", reason: "매칭되지만 Action이 없어 차단 여부를 알 수 없음" };
  }
}
```

주의: 악성 예시가 안 걸린 경우(위 `!matched` && `!benign`) outcome은 `PASS`지만 reason이 "미탐"이다. 미탐 집계는 아래 `missed`로 별도 계산한다(악성인데 CAUGHT가 아닌 것).

(e) `testRule`의 rows 매핑과 집계·판정을 바꾼다:

```ts
  const rows: RuleTestRow[] = params.requests.map((req) => {
    const v = evalStatement(statement, req, ctx);
    const matched = v === "UNKNOWN" ? null : v;
    const { outcome, reason } = outcomeFor(matched, action, req.benign);
    return { requestId: req.id, matched, outcome, reason };
  });

  const count = (o: RuleTestRow["outcome"]): number => rows.filter((r) => r.outcome === o).length;
  const blocked = count("BLOCKED");
  const unknown = count("UNKNOWN");
  const caught = count("CAUGHT");
  const byId = new Map(params.requests.map((r) => [r.id, r]));
  const missed = rows.filter(
    (r) => byId.get(r.requestId)?.benign === false && r.outcome !== "CAUGHT" && r.outcome !== "UNKNOWN",
  ).length;
```

`notes`에 정탐/미탐 안내를 덧붙인다(기존 notes push 뒤):

```ts
  if (caught > 0) notes.push(`악성 예시 ${caught}건 차단(정탐)`);
  if (missed > 0) notes.push(`악성 예시 ${missed}건이 규칙을 통과함(미탐) — 규칙이 공격을 놓침`);
```

return 객체에 `caught`, `missed`를 추가하고, verdict는 그대로 `blocked`(=benign 차단) 기준을 유지한다:

```ts
  return {
    ruleName: name,
    action,
    unsupported: [...ctx.unsupported],
    rows,
    passed: count("PASS"),
    blocked,
    counted: count("COUNTED"),
    caught,
    missed,
    unknown,
    // Only a blocked *benign* request is a false positive; caught malicious
    // traffic is the goal, not a risk.
    verdict: blocked > 0 ? "FALSE_POSITIVE_RISK" : unknown > 0 ? "INCONCLUSIVE" : "SAFE",
    notes,
  };
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `pnpm test:rulesim`
Expected: 전부 `PASS`, `ALL PASS`. 특히 `a rule catching only malicious traffic stays SAFE`와 `blocking benign /v1 rows is a false-positive risk`가 통과해야 한다.

- [ ] **Step 6: 서버 액션 추가**

`src/app/actions/dashboard.ts`:

import 블록의 `rulesim` import에 `maliciousExampleRequests`를 추가하고, 액션을 추가한다:

```ts
export async function getMaliciousExampleRequestsAction(): Promise<ActionResult<TestRequest[]>> {
  try {
    return ok(maliciousExampleRequests());
  } catch (e) {
    return fail(e);
  }
}
```

- [ ] **Step 7: SandboxTab UI**

`src/app/dashboard/ui/SandboxTab.tsx`:

(a) import에 `getMaliciousExampleRequestsAction`를 추가한다.

(b) `addRow` 옆에 악성 예시 추가 핸들러를 만든다(중복 id 방지: 이미 있으면 skip):

```tsx
  const addMalicious = async (): Promise<void> => {
    const res = await getMaliciousExampleRequestsAction();
    if (!res.ok) { setError(res.error); return; }
    setRequests((prev) => {
      const have = new Set((prev ?? []).map((r) => r.id));
      return [...(prev ?? []), ...res.data.filter((r) => !have.has(r.id))];
    });
  };
```

(c) `정상 요청` Card의 `right`에 `+ 악성 예시` 버튼을 `+ 행 추가` 옆에 넣는다:

```tsx
<button
  type="button"
  onClick={() => void addMalicious()}
  className="rounded bg-red-950 px-2 py-0.5 text-[11px] text-red-300 hover:bg-red-900"
>
  + 악성 예시
</button>
```

(d) 편집 표에서 악성 행을 시각적으로 구분한다: `requests.map` 행의 `<tr>` className에 `r.benign === false ? "bg-red-950/30" : ""`를 더한다.

(e) `OUTCOME_STYLE`에 `CAUGHT`를 추가한다:

```tsx
  CAUGHT: { label: "정탐(차단)", cls: "text-emerald-400 font-bold" },
```

(f) 결과 요약 줄에 정탐/미탐을 추가한다(기존 통과/차단/카운트만/판정불가 옆):

```tsx
<span className="text-emerald-400">정탐 {result.caught}</span>
<span className="text-red-300">미탐 {result.missed}</span>
```

`RuleTestResult` 타입 변경으로 이 필드들은 항상 존재한다.

- [ ] **Step 8: 타입체크 + 전체 회귀**

Run: `npx tsc --noEmit`
Expected: 출력 없음

Run: `pnpm test`
Expected: 모든 suite `ALL PASS`

- [ ] **Step 9: 실제 확인**

```bash
pnpm dev
```

시험 탭에서:
- `+ 악성 예시` 클릭 시 악성 6행이 붉게 추가되는지
- placeholder의 `/wp-login` 차단 규칙 실행 → **안전**, 정탐 ≥1, 미탐/오탐 0
- `Statement`를 `{"ByteMatchStatement":{"SearchString":"/v1","FieldToMatch":{"UriPath":{}},"TextTransformations":[{"Priority":0,"Type":"NONE"}],"PositionalConstraint":"STARTS_WITH"}}` Block으로 → **오탐 위험**(정상 /v1 행 차단)
- GeoMatch 규칙 `{"GeoMatchStatement":{"CountryCodes":["CN","RU"]}}` Block 실행 → 악성 행(CN/RU) 정탐, 정상 행(KR) 통과

확인 후 dev 서버 종료.

- [ ] **Step 10: 커밋**

```bash
git add src/lib/types.ts src/lib/server/rulesim.ts scripts/rulesim.test.mjs src/app/actions/dashboard.ts src/app/dashboard/ui/SandboxTab.tsx
git commit -m "Add malicious example requests and true-positive scoring to the sandbox"
```

---

## Task 7: 마무리

- [ ] **Step 1: 전체 검증**

```bash
npx tsc --noEmit && pnpm test
```
Expected: 타입체크 무출력, 모든 suite(`ddos`·`applog`·`rulestatement`·`rulesim`·`threatsig`) `ALL PASS`

- [ ] **Step 2: 스펙 상태 갱신**

`docs/superpowers/specs/2026-08-10-waf-log-query-and-rule-sandbox-design.md`의 상태 줄을:

```markdown
상태: 파트 A · 파트 B · 파트 C(툴팁·평가기 확대·악성 클라이언트 탐지) 구현 완료
```

- [ ] **Step 3: 커밋 + 푸시**

```bash
git add docs/superpowers/specs/2026-08-10-waf-log-query-and-rule-sandbox-design.md
git commit -m "Mark part C complete in the design spec"
git push
```

---

## Self-Review

**스펙 커버리지**

| 요구 | 태스크 |
|---|---|
| 잘림 텍스트 반투명 툴팁, 뷰포트 클램프, 전역 | Task 5 |
| 평가기 로컬 판정 문법 최대 지원 (GeoMatch·transform) | Task 4 |
| Sqli/Xss/Managed/RateBased은 UNKNOWN 유지 | Task 4 (미지원 목록 불변) |
| 악성 UA 5분류(스캐너/정찰/스크래퍼/라이브러리/위조) | Task 1 (스캐너·정찰·위조 판정; 라이브러리/스크래퍼는 UA 단독 미차단 — 의도적 결정 1) |
| base64 난독 쿼리 탐지 | Task 1·2·3 |
| 이상 탐지 경보 반영 | Task 2 |
| WAF 추천 규칙 반영 | Task 3 |
| 샌드박스 악성 예시 행 (true-positive) | Task 6 |
| REQ-01 Go 바이패스 (툴 시그니처 우선) | Task 1 (`classifyUa`), Task 2·3 회귀 케이스 |
| REQ-02 ByteMatch·정적 403·rate-based 금지 | Task 3 (추천 문구·grep 회귀) |

**플레이스홀더 스캔:** TBD/TODO 없음. 순수 모듈(Task 1·4·6 로직)은 전체 코드 포함. UI/추천 태스크는 실제 코드 블록 + 통합 위치 명시.

**타입 일관성:** `TestRequest`는 Task 4에서 `country`, Task 6에서 `benign` 추가 — 두 태스크가 순서대로 `defaultTestRequests`/`maliciousExampleRequests`/테스트를 함께 갱신한다. `RuleTestOutcome`의 `CAUGHT`, `RuleTestResult.caught/missed`는 Task 6에서 타입·구현·UI를 한 번에 맞춘다. `classifyUa` 반환형은 Task 1에 정의되고 Task 2·3이 동일 시그니처로 소비한다. `ThreatCategory`는 Task 1에서만 정의된다. `push(...)`/`criteria`/`WafRecommendation` 필드명은 기존 파일 관례를 따르도록 각 태스크에 명시(발명 금지).

**회귀 안전성:** Go-http-client가 `classifyUa`에서 바이패스되므로 `ddos-policy`의 loadgen/scan 케이스 개수 불변. 신규 추천은 ByteMatch뿐이라 rate-based grep 통과. 기본 요청 6건 불변(악성 예시는 별도 함수·버튼).
