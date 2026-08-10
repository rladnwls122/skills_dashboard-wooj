# WAF 로그 조회 개편 (파트 A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** WAF 탭의 조회 영역을 상단으로 올리고, 샘플 표에 WAF 응답 코드 컬럼을 추가하고, 실제 HTTP 상태 코드로 요청을 조회하는 앱 요청 로그 패널을 만든다.

**Architecture:** 이 환경의 앱 로그는 구조화 JSON이고 `podlogs.ts`의 `PARSE_FIELDS`가 이미 `status`를 필드로 뽑아낸다. 따라서 상태 코드 조회는 CloudWatch Logs Insights에서 `filter status >= 400 and status < 500` 형태로 직접 처리한다. Insights는 스캔 바이트당 과금이므로 쿼리는 사용자 행위(마운트 1회 · 필터 변경 · 수동 새로고침)로만 발동하고 자동 폴링하지 않으며, 결과는 서버에서 30초 캐시한다. 쿼리 문자열 조립과 입력 검증은 AWS 의존이 전혀 없는 순수 모듈로 분리해 AWS 없이 단위 테스트한다.

**Tech Stack:** Next.js 15 App Router (Server Actions), React 19, TypeScript strict (`noUncheckedIndexedAccess`), Tailwind v4, `@aws-sdk/client-cloudwatch-logs`, `@aws-sdk/client-wafv2`. 테스트는 Node 24 내장 타입 스트리핑 + ESM resolve 훅 — **새 의존성 없음**.

## Global Constraints

- 브랜치: `feat/waf-log-query-and-rule-sandbox`. `main`에 직접 커밋 금지
- 스펙: `docs/superpowers/specs/2026-08-10-waf-log-query-and-rule-sandbox-design.md` — **파트 A만** 이번 범위. 파트 B(규칙 샌드박스)는 건드리지 않는다
- 새 npm 의존성 추가 금지 (dev 포함)
- 모든 서버 액션은 기존 `ok()` / `fail()` 패턴을 따르고 절대 throw하지 않는다
- Logs Insights 비용 정책: 성공 30초 캐시(`POLLING.logCacheTtlMs`), 실패 10초 캐시(`POLLING.logFailTtlMs`), 창 기본 60분·최대 4시간(`INSIGHTS_LIMITS`), 행 상한 200, **자동 폴링 없음**
- 사용자 입력 `pathContains`는 Insights 쿼리 문자열에 삽입된다. 허용 문자 `[A-Za-z0-9/_.-]`, 최대 120자
- 200행 상한에 걸리면 절단 사실을 UI에 표시한다. 조용한 절단 금지
- 각 태스크 종료 시 `npx tsc --noEmit`이 통과해야 한다
- 사용자 노출 문구는 한국어, 코드 주석은 영어 (기존 코드 관례)

---

## File Structure

| 파일 | 책임 |
|---|---|
| `scripts/testing/stub-hooks.mjs` (신규) | ESM resolve 훅 — `server-only`를 빈 모듈로, 확장자 없는 상대 임포트에 `.ts` 부착 |
| `scripts/testing/register.mjs` (신규) | 위 훅 등록 엔트리 |
| `scripts/ddos-policy.test.mjs` (신규) | 볼류메트릭 정책 회귀 테스트 (임시 위치에서 이관) |
| `scripts/applogquery.test.mjs` (신규) | 쿼리 조립 · 입력 검증 · 행 변환 단위 테스트 |
| `src/lib/server/logfields.ts` (신규, 순수) | `PARSE_FIELDS`, `toIso`, `hhmmss` — `podlogs.ts`에서 이관 |
| `src/lib/server/applogquery.ts` (신규, 순수) | `StatusClass`, `validatePathFilter`, `buildRequestLogQuery`, `toRequestLogRow`, `ROW_LIMIT` |
| `src/lib/server/applog.ts` (신규) | `fetchRequestLogRows` — Insights 실행 + 캐시 |
| `src/lib/server/podlogs.ts` (수정) | 로컬 `PARSE_FIELDS`/`toIso`/`hhmmss` 제거하고 `logfields.ts`에서 임포트 |
| `src/lib/server/waf.ts` (수정) | `toSampleRow()` 추출 + `responseCode` 채움 |
| `src/lib/types.ts` (수정) | `WafSampleRow.responseCode`, `RequestLogRow`, `RequestLogQueryResult` |
| `src/app/actions/dashboard.ts` (수정) | `getRequestLogRowsAction` |
| `src/app/dashboard/ui/RequestLogPanel.tsx` (신규) | 앱 요청 로그 패널 (상태 클래스 토글 · 경로 검색 · 표) |
| `src/app/dashboard/ui/WafTab.tsx` (수정) | 카드 순서 · 상태 컬럼 · 패널 삽입 |
| `package.json` (수정) | `test` 스크립트 |

`WafTab.tsx`가 489줄로 이미 크므로 새 패널은 별도 컴포넌트 파일로 만든다. 쿼리 조립을 `applogquery.ts`로 분리하는 이유는 순수 모듈이어야 AWS SDK 로드 없이 단위 테스트가 되기 때문이다.

**스펙과의 의도적 차이 1건:** 스펙 A3은 `pathContains`에 대해 문자셋 제한 *과* `"`/`\` 이스케이프를 모두 요구한다. 허용 문자셋이 `"`와 `\`를 애초에 배제하므로 이스케이프는 도달 불가한 죽은 코드가 된다. 문자셋 검증을 단일 보증으로 삼고, `"`와 `\`가 거부되는지를 테스트로 고정한다.

---

## Task 1: 테스트 하네스

프로젝트에 테스트 프레임워크가 없다. Node 24는 `.ts`를 기본으로 타입 스트리핑하지만, 소스가 `import "server-only"`(Next 전용 가드, Node에서 throw)를 쓰고 상대 임포트에 확장자가 없어 그대로는 불러올 수 없다. resolve 훅으로 두 문제를 해결한다.

**Files:**
- Create: `scripts/testing/stub-hooks.mjs`
- Create: `scripts/testing/register.mjs`
- Create: `scripts/ddos-policy.test.mjs`
- Modify: `package.json` (scripts)

**Interfaces:**
- Consumes: 없음
- Produces: `node --import ./scripts/testing/register.mjs <test.mjs>`로 실제 `.ts` 소스를 불러 실행 가능. 이후 모든 테스트 태스크가 이 진입점을 쓴다.

- [ ] **Step 1: resolve 훅 작성**

`scripts/testing/stub-hooks.mjs`:

```js
// Lets plain Node import the app's .ts server modules directly.
// - "server-only" is a Next build-time guard that throws outside a server
//   bundle; stub it to an empty module.
// - TS sources import siblings extensionless ("./config"); Node needs ".ts".
export function resolve(specifier, context, next) {
  if (specifier === "server-only") {
    return { url: "data:text/javascript,export{}", shortCircuit: true };
  }
  if (specifier.startsWith(".") && !/\.[cm]?[jt]s$/.test(specifier)) {
    try {
      return next(`${specifier}.ts`, context);
    } catch {
      // fall through to the unmodified specifier
    }
  }
  return next(specifier, context);
}
```

- [ ] **Step 2: 등록 엔트리 작성**

`scripts/testing/register.mjs`:

```js
import { register } from "node:module";

register("./stub-hooks.mjs", import.meta.url);
```

- [ ] **Step 3: 볼류메트릭 정책 회귀 테스트 작성**

`scripts/ddos-policy.test.mjs` — 이미 통과가 확인된 테스트를 정식 위치로 이관한다. 상대 경로는 리포지토리 루트 기준이다.

```js
// Locks in the competition directive: request volume against the served API
// surface is never a finding, traffic aimed outside it still is, and no
// rate-based (volumetric) WAF rule can be recommended.
import { readFile } from "node:fs/promises";

const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { isAppTrafficPath, APP_TRAFFIC_PATHS } = await import(`${SRC}config.ts`);
const { detectAnomalies } = await import(`${SRC}anomaly.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

console.log("APP_TRAFFIC_PATHS =", APP_TRAFFIC_PATHS.join(", "), "\n");

for (const p of ["/v1/user", "/v1/product", "/v1/stress", "/v1/image", "/v1/user/42", "/v1/image?id=3"]) {
  check(`isAppTrafficPath("${p}")`, isAppTrafficPath(p), true);
}
for (const p of ["/admin.php", "/v1", "/v1/userx", "/.env", "/wp-login.php"]) {
  check(`isAppTrafficPath("${p}")`, isAppTrafficPath(p), false);
}

const summary = (byPath, byUa) => ({
  totalSampled: 1000,
  windowLabel: "15m",
  source: "test",
  byPath,
  byIp: [{ key: "203.0.113.7", count: 990 }],
  byUa,
  byMethod: [],
  queryPatterns: [],
  headerPatterns: [],
  statusDist: null,
  detailedStatus: null,
});
const input = (httpSummary) => ({ metrics: [], httpSummary, pods: [], events: [], fingerprints: [] });
const traffic = (as) => as.filter((a) => a.type === "TRAFFIC_ANOMALY_SUSPECTED");

const loadGen = detectAnomalies(
  input(summary(
    [{ path: "/v1/user", count: 990, blocked: 0, lowPriority: false }],
    [{ key: "Go-http-client/2.0", count: 990 }],
  )),
);
check("load generator on /v1/user raises no traffic anomaly", traffic(loadGen).length, 0);

const scan = detectAnomalies(
  input(summary(
    [{ path: "/wp-login.php", count: 990, blocked: 0, lowPriority: false }],
    [{ key: "Go-http-client/2.0", count: 990 }],
  )),
);
check("off-surface scan still raises a traffic anomaly", traffic(scan).length, 1);
check(
  "off-surface finding cites no source IP",
  traffic(scan)[0]?.evidence.some((e) => e.includes("203.0.113.7")) ?? true,
  false,
);

const mixed = detectAnomalies(
  input(summary(
    [
      { path: "/v1/product", count: 960, blocked: 0, lowPriority: false },
      { path: "/.env", count: 40, blocked: 0, lowPriority: false },
    ],
    [{ key: "Mozilla/5.0", count: 800 }],
  )),
);
check("small probe under threshold stays quiet", traffic(mixed).length, 0);

const wafSrc = await readFile(new URL(`${SRC}waf.ts`), "utf8");
const genBody = wafSrc.slice(
  wafSrc.indexOf("export async function generateRecommendations"),
  wafSrc.indexOf("function hash(s: string)"),
);
check("generateRecommendations builds no RateBasedStatement", genBody.includes("RateBasedStatement:"), false);
check("generateRecommendations emits no RATE_BASED kind", genBody.includes('kind: "RATE_BASED"'), false);

const incSrc = await readFile(new URL(`${SRC}incident.ts`), "utf8");
check("buildSnapshot blanks byIp", incSrc.includes("byIp: []"), true);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
```

- [ ] **Step 4: package.json에 스크립트 추가**

`scripts` 블록에 두 줄을 넣는다. 기존 `typecheck` 항목은 그대로 둔다.

```json
    "test": "node --import ./scripts/testing/register.mjs scripts/ddos-policy.test.mjs",
    "test:ddos": "node --import ./scripts/testing/register.mjs scripts/ddos-policy.test.mjs",
```

- [ ] **Step 5: 테스트 실행 — 통과 확인**

Run: `pnpm test`
Expected: 19개 `PASS` 후 `ALL PASS`, exit 0. `MODULE_TYPELESS_PACKAGE_JSON` 경고는 무해하다 (프로젝트가 CommonJS `package.json`이라 Node가 ESM으로 재파싱).

- [ ] **Step 6: 훅이 실제로 필요한지 확인 (음성 대조)**

Run: `node scripts/ddos-policy.test.mjs`
Expected: FAIL — `server-only`가 throw하거나 `./config` 해석 실패. 훅 없이는 불가능함을 확인하는 단계다. 통과해 버리면 훅이 무의미하므로 조사한다.

- [ ] **Step 7: 커밋**

```bash
git add scripts/testing/stub-hooks.mjs scripts/testing/register.mjs scripts/ddos-policy.test.mjs package.json
git commit -m "Add a dependency-free test harness for server modules"
```

---

## Task 2: 샘플 표에 WAF 응답 코드 컬럼

`SampledHTTPRequest.ResponseCodeSent`(AWS SDK v3에 `number | undefined`로 존재)를 노출한다. 현재 `listSampleRows()`는 매핑을 인라인 화살표 함수로 하고 있어 테스트할 수 없다. 순수 함수 `toSampleRow()`로 추출해 테스트 가능하게 만든다.

**Files:**
- Modify: `src/lib/types.ts` (`WafSampleRow`)
- Modify: `src/lib/server/waf.ts` (`listSampleRows` 주변, 현재 561-577행)
- Modify: `src/app/dashboard/ui/WafTab.tsx` (표 헤더 442행, 본문 450-476행, 검색 해이스택 89행)

**Interfaces:**
- Consumes: Task 1의 테스트 진입점
- Produces: `WafSampleRow.responseCode: number | null`. `export function toSampleRow(s: SampledHTTPRequest): WafSampleRow`

- [ ] **Step 1: 타입에 필드 추가**

`src/lib/types.ts`의 `WafSampleRow`에 마지막 필드로 추가한다:

```ts
export interface WafSampleRow {
  ts: string;
  ip: string;
  country: string;
  method: string;
  path: string;
  query: string;
  userAgent: string;
  action: string;
  rule: string;
  // Only populated when WAF itself generated the response (Block with a custom
  // response, CAPTCHA, Challenge). null for ordinary ALLOW traffic.
  responseCode: number | null;
}
```

- [ ] **Step 2: 실패하는 테스트 작성**

`scripts/applogquery.test.mjs`를 만들고 우선 이 케이스만 넣는다 (Task 4에서 같은 파일에 쿼리 테스트를 추가한다).

```js
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { toSampleRow } = await import(`${SRC}waf.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const blocked = toSampleRow({
  Timestamp: new Date("2026-08-10T03:07:12.000Z"),
  Action: "BLOCK",
  RuleNameWithinRuleGroup: "dash-ua-match",
  ResponseCodeSent: 403,
  Request: {
    ClientIP: "203.0.113.7",
    Country: "KR",
    Method: "GET",
    URI: "/wp-login.php",
    Headers: [{ Name: "User-Agent", Value: "sqlmap/1.7" }],
  },
});
check("blocked sample keeps the WAF response code", blocked.responseCode, 403);
check("blocked sample action", blocked.action, "BLOCK");
check("blocked sample path", blocked.path, "/wp-login.php");

const allowed = toSampleRow({
  Timestamp: new Date("2026-08-10T03:07:13.000Z"),
  Action: "ALLOW",
  Request: { ClientIP: "10.0.2.88", Method: "GET", URI: "/v1/user" },
});
check("allowed sample with no code maps to null", allowed.responseCode, null);
check("missing rule maps to empty string", allowed.rule, "");
check("missing country maps to empty string", allowed.country, "");

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
```

`package.json`의 `test`를 두 파일 모두 돌리도록 바꾸고 `test:applog`를 추가한다:

```json
    "test": "pnpm test:ddos && pnpm test:applog",
    "test:ddos": "node --import ./scripts/testing/register.mjs scripts/ddos-policy.test.mjs",
    "test:applog": "node --import ./scripts/testing/register.mjs scripts/applogquery.test.mjs",
```

- [ ] **Step 3: 실패 확인**

Run: `pnpm test:applog`
Expected: FAIL — `toSampleRow is not a function` (아직 export되지 않음)

- [ ] **Step 4: `toSampleRow` 추출 + `responseCode` 채우기**

`src/lib/server/waf.ts`의 `listSampleRows`를 다음으로 교체한다. `samplePath` / `sampleQuery` / `sampleHeader`는 같은 파일의 기존 헬퍼다.

```ts
// Exported for unit tests — the mapping is pure, the fetch is not.
export function toSampleRow(s: SampledHTTPRequest): WafSampleRow {
  return {
    ts: s.Timestamp ? new Date(s.Timestamp).toISOString() : "",
    ip: s.Request?.ClientIP ?? "",
    country: s.Request?.Country ?? "",
    method: s.Request?.Method ?? "",
    path: samplePath(s),
    query: sampleQuery(s).slice(0, 120),
    userAgent: sampleHeader(s, "user-agent").slice(0, 80),
    action: s.Action ?? "",
    rule: s.RuleNameWithinRuleGroup ?? "",
    responseCode: s.ResponseCodeSent ?? null,
  };
}

// Raw sampled requests as table rows — lets the operator see the individual
// suspicious requests behind the aggregates (newest first, capped at 300).
export async function listSampleRows(): Promise<WafSampleRow[]> {
  const { samples } = await fetchSampledRequests();
  return samples
    .map(toSampleRow)
    .sort((a, b) => (a.ts < b.ts ? 1 : -1))
    .slice(0, 300);
}
```

`SampledHTTPRequest` 타입이 이미 `@aws-sdk/client-wafv2`에서 임포트되어 있는지 확인하고, 없으면 기존 import 블록에 추가한다.

- [ ] **Step 5: 테스트 통과 확인**

Run: `pnpm test:applog`
Expected: 6개 `PASS`, `ALL PASS`

- [ ] **Step 6: 표에 컬럼 추가**

`WafTab.tsx` 442행의 헤더 배열에서 `"판정"` 앞에 `"상태"`를 넣되, 툴팁을 달아야 하므로 헤더를 문자열 배열에서 객체 배열로 바꾼다:

```tsx
{(
  [
    { label: "시각" },
    { label: "IP" },
    { label: "국가" },
    { label: "메소드" },
    { label: "경로" },
    { label: "쿼리" },
    { label: "User-Agent" },
    { label: "상태", hint: "WAF가 직접 응답한 요청만 기록됨 (Block+커스텀 응답, CAPTCHA). 일반 ALLOW 요청은 비어 있음 — 실제 앱 상태 코드는 아래 앱 요청 로그 참고" },
    { label: "판정" },
    { label: "룰" },
  ] as const
).map((h) => (
  <th
    key={h.label}
    title={"hint" in h ? h.hint : undefined}
    className={`px-2 py-1 font-medium whitespace-nowrap ${"hint" in h ? "cursor-help underline decoration-dotted" : ""}`}
  >
    {h.label}
  </th>
))}
```

본문에서 `판정` 셀 바로 앞에 상태 셀을 넣는다:

```tsx
<td className="px-2 py-0.5 tabular-nums whitespace-nowrap">
  {s.responseCode === null ? (
    <span className="text-neutral-600">—</span>
  ) : (
    <span className={s.responseCode >= 500 ? "text-red-400" : s.responseCode >= 400 ? "text-amber-400" : "text-neutral-300"}>
      {s.responseCode}
    </span>
  )}
</td>
```

- [ ] **Step 7: 검색 해이스택에 코드 포함**

`WafTab.tsx` 89행을 바꿔 `403` 입력으로 걸러지게 한다:

```tsx
const hay = `${s.ip} ${s.path} ${s.query} ${s.userAgent} ${s.method} ${s.responseCode ?? ""}`.toLowerCase();
```

검색 입력의 placeholder도 `"IP/경로/UA/코드 검색"`으로 바꾼다.

- [ ] **Step 8: 타입체크 + 커밋**

Run: `npx tsc --noEmit`
Expected: 출력 없음, exit 0

```bash
git add src/lib/types.ts src/lib/server/waf.ts src/app/dashboard/ui/WafTab.tsx scripts/applogquery.test.mjs package.json
git commit -m "Show the WAF response code on the sample request table"
```

---

## Task 3: Insights 로그 필드 헬퍼 분리

`PARSE_FIELDS`, `toIso`, `hhmmss`는 현재 `podlogs.ts`의 모듈 로컬 상수/함수다. 새 앱 로그 조회도 같은 파싱이 필요하지만, `applog` 모듈이 파드 로그 모듈에 의존하는 것은 경계가 잘못된 것이다. AWS 의존이 없는 순수 모듈로 옮긴다.

**Files:**
- Create: `src/lib/server/logfields.ts`
- Modify: `src/lib/server/podlogs.ts` (34-52행의 로컬 정의 제거, 임포트 추가)

**Interfaces:**
- Consumes: 없음
- Produces: `PARSE_FIELDS: string`, `toIso(ts: string): string`, `hhmmss(iso: string): string`

- [ ] **Step 1: 순수 모듈 작성**

`src/lib/server/logfields.ts`:

```ts
import "server-only";

// The app logs structured JSON, so Insights can pull method/path/status/latency
// out as real fields — status is then filterable as a number. Shared by the pod
// log reader and the app request-log query.
export const PARSE_FIELDS =
  'parse log /"latency_ms":(?<latency_ms>[0-9.]+)/' +
  ' | parse log /"method":"(?<method>[A-Z]+)"/' +
  ' | parse log /"path":"(?<path>[^"]*)"/' +
  ' | parse log /"status":(?<status>[0-9]+)/';

// Converts "2026-08-10 03:07:12.727" (Insights @timestamp, UTC) to ISO.
export function toIso(ts: string): string {
  return `${ts.replace(" ", "T")}Z`;
}

export function hhmmss(iso: string): string {
  const m = iso.match(/T(\d{2}:\d{2}:\d{2})/);
  return m?.[1] ?? "";
}
```

- [ ] **Step 2: podlogs.ts에서 로컬 정의 제거**

`src/lib/server/podlogs.ts`에서 `PARSE_FIELDS` 상수와 `toIso`, `hhmmss` 함수 정의를 삭제하고 (현재 34-52행), 기존 import 블록에 추가한다:

```ts
import { PARSE_FIELDS, hhmmss, toIso } from "./logfields";
```

`assertName` / `podScope` / `NAME_RE`는 파드 전용이므로 `podlogs.ts`에 남긴다.

- [ ] **Step 3: 타입체크로 확인**

Run: `npx tsc --noEmit`
Expected: 출력 없음. 순수 이관이므로 동작 변화가 없어야 한다. `hhmmss`가 podlogs에서 실제로 쓰이지 않아 unused 오류가 나면 import에서 빼되 `logfields.ts`에는 남긴다 (Task 6의 UI가 쓴다).

- [ ] **Step 4: 기존 테스트로 회귀 확인**

Run: `pnpm test`
Expected: 두 테스트 파일 모두 `ALL PASS`

- [ ] **Step 5: 커밋**

```bash
git add src/lib/server/logfields.ts src/lib/server/podlogs.ts
git commit -m "Move shared Insights log-field helpers into their own module"
```

---

## Task 4: 쿼리 조립 + 입력 검증 (순수)

가장 위험한 부분이다. 사용자 입력이 Insights 쿼리 문자열에 들어가고, 잘못 조립하면 조용히 틀린 결과가 나온다. AWS 의존이 없는 순수 모듈로 만들어 전수 테스트한다.

**Files:**
- Create: `src/lib/server/applogquery.ts`
- Modify: `src/lib/types.ts` (`RequestLogRow`, `RequestLogQueryResult`)
- Modify: `scripts/applogquery.test.mjs` (케이스 추가)

**Interfaces:**
- Consumes: Task 3의 `PARSE_FIELDS`, `toIso`
- Produces:
  - `type StatusClass = "ALL" | "2xx" | "3xx" | "4xx" | "5xx"`
  - `ROW_LIMIT: number` (200), `PATH_FILTER_MAX: number` (120)
  - `validatePathFilter(raw: string): string` — 정규화된 값 반환, 위반 시 throw
  - `buildRequestLogQuery(params: { statusClass: StatusClass; pathContains: string }): string`
  - `toRequestLogRow(r: Record<string, string>): RequestLogRow`

- [ ] **Step 1: 타입 추가**

`src/lib/types.ts` 끝에 추가한다:

```ts
export interface RequestLogRow {
  // ISO timestamp
  ts: string;
  method: string;
  path: string;
  status: number;
  latencyMs: number;
}

export interface RequestLogQueryResult {
  rows: RequestLogRow[];
  // recordsMatched — how many matched in the window, beyond the row cap
  totalMatched: number;
  scannedBytes: number;
  windowLabel: string;
  // true when the row cap hid matches
  truncated: boolean;
}
```

- [ ] **Step 2: 실패하는 테스트 작성**

`scripts/applogquery.test.mjs`의 `toSampleRow` 케이스 아래에 추가한다. 파일 상단 import에 한 줄을 더한다:

```js
const {
  buildRequestLogQuery,
  validatePathFilter,
  toRequestLogRow,
  ROW_LIMIT,
  PATH_FILTER_MAX,
} = await import(`${SRC}applogquery.ts`);
```

케이스:

```js
const contains = (name, haystack, needle, expected = true) => {
  const ok = haystack.includes(needle) === expected;
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        ${expected ? "missing" : "unexpected"} ${JSON.stringify(needle)} in ${JSON.stringify(haystack)}`),
  );
};

// Status class ranges
const q4xx = buildRequestLogQuery({ statusClass: "4xx", pathContains: "" });
contains("4xx adds the right range", q4xx, "filter status >= 400 and status < 500");
const q5xx = buildRequestLogQuery({ statusClass: "5xx", pathContains: "" });
contains("5xx adds the right range", q5xx, "filter status >= 500 and status < 600");
const q2xx = buildRequestLogQuery({ statusClass: "2xx", pathContains: "" });
contains("2xx adds the right range", q2xx, "filter status >= 200 and status < 300");
const q3xx = buildRequestLogQuery({ statusClass: "3xx", pathContains: "" });
contains("3xx adds the right range", q3xx, "filter status >= 300 and status < 400");

// ALL adds no status range at all
const qAll = buildRequestLogQuery({ statusClass: "ALL", pathContains: "" });
contains("ALL adds no status range", qAll, "filter status >=", false);
contains("ALL still requires a parsed status", qAll, "filter ispresent(status)");

// Path filter
const qPath = buildRequestLogQuery({ statusClass: "ALL", pathContains: "/v1/user" });
contains("path filter is added", qPath, 'filter path like "/v1/user"');
contains("empty path adds no path filter", qAll, "filter path like", false);

// Structure
contains("query parses the JSON fields", qAll, 'parse log /"status":(?<status>[0-9]+)/');
contains("query selects the row fields", qAll, "fields @timestamp, method, path, status, latency_ms");
contains("query sorts newest first", qAll, "sort @timestamp desc");
contains("query caps rows", qAll, `limit ${ROW_LIMIT}`);
check("row cap is 200", ROW_LIMIT, 200);

// Rejected input — these would otherwise break out of the quoted string
const rejects = ['/v1/"', "/v1/\\", "/v1/user or 1=1", "/v1/*", "/v1/(a|b)", "/v1 user", "/v1/user;"];
for (const bad of rejects) {
  let threw = false;
  try {
    validatePathFilter(bad);
  } catch {
    threw = true;
  }
  check(`validatePathFilter rejects ${JSON.stringify(bad)}`, threw, true);
}
let tooLong = false;
try {
  validatePathFilter("/".repeat(PATH_FILTER_MAX + 1));
} catch {
  tooLong = true;
}
check("validatePathFilter rejects over-long input", tooLong, true);

// Accepted input
check("validatePathFilter trims", validatePathFilter("  /v1/user  "), "/v1/user");
check("validatePathFilter allows dots and dashes", validatePathFilter("/v1/a-b.c_d"), "/v1/a-b.c_d");
check("validatePathFilter allows empty", validatePathFilter(""), "");

// Row mapping
check(
  "toRequestLogRow converts types",
  toRequestLogRow({
    "@timestamp": "2026-08-10 03:07:12.727",
    method: "GET",
    path: "/v1/product",
    status: "500",
    latency_ms: "85.5",
  }),
  { ts: "2026-08-10T03:07:12.727Z", method: "GET", path: "/v1/product", status: 500, latencyMs: 85.5 },
);
check(
  "toRequestLogRow tolerates missing fields",
  toRequestLogRow({}),
  { ts: "Z", method: "", path: "", status: 0, latencyMs: 0 },
);
```

- [ ] **Step 3: 실패 확인**

Run: `pnpm test:applog`
Expected: FAIL — `applogquery.ts` 모듈 없음 (`ERR_MODULE_NOT_FOUND`)

- [ ] **Step 4: 순수 모듈 구현**

`src/lib/server/applogquery.ts`:

```ts
import "server-only";
import { PARSE_FIELDS, toIso } from "./logfields";
import type { RequestLogRow } from "@/lib/types";

export type StatusClass = "ALL" | "2xx" | "3xx" | "4xx" | "5xx";

const STATUS_RANGE: Record<Exclude<StatusClass, "ALL">, [number, number]> = {
  "2xx": [200, 300],
  "3xx": [300, 400],
  "4xx": [400, 500],
  "5xx": [500, 600],
};

export const ROW_LIMIT = 200;
export const PATH_FILTER_MAX = 120;

// The filter is interpolated into an Insights query string inside double
// quotes. The allowed set excludes both the quote and the backslash, so no
// escaping is reachable — this validation is the whole guarantee.
const PATH_FILTER_RE = /^[A-Za-z0-9/_.-]*$/;

export function validatePathFilter(raw: string): string {
  const v = raw.trim();
  if (v.length > PATH_FILTER_MAX) {
    throw new Error(`경로 검색어가 너무 김 (최대 ${PATH_FILTER_MAX}자)`);
  }
  if (!PATH_FILTER_RE.test(v)) {
    throw new Error("경로 검색어에 허용되지 않는 문자가 있음 (영문·숫자와 / _ . - 만 가능)");
  }
  return v;
}

export function buildRequestLogQuery(params: {
  statusClass: StatusClass;
  pathContains: string;
}): string {
  const parts: string[] = [PARSE_FIELDS, "filter ispresent(status)"];
  if (params.statusClass !== "ALL") {
    const [lo, hi] = STATUS_RANGE[params.statusClass];
    parts.push(`filter status >= ${lo} and status < ${hi}`);
  }
  const path = validatePathFilter(params.pathContains);
  if (path) parts.push(`filter path like "${path}"`);
  parts.push("fields @timestamp, method, path, status, latency_ms");
  parts.push("sort @timestamp desc");
  parts.push(`limit ${ROW_LIMIT}`);
  return parts.join(" | ");
}

export function toRequestLogRow(r: Record<string, string>): RequestLogRow {
  return {
    ts: toIso(r["@timestamp"] ?? ""),
    method: r["method"] ?? "",
    path: r["path"] ?? "",
    status: Number(r["status"] ?? "0"),
    latencyMs: Number(r["latency_ms"] ?? "0"),
  };
}
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `pnpm test:applog`
Expected: 전부 `PASS`, `ALL PASS`. 특히 거부 케이스 7건과 `ALL adds no status range`가 통과해야 한다.

- [ ] **Step 6: 타입체크 + 커밋**

Run: `npx tsc --noEmit`
Expected: 출력 없음

```bash
git add src/lib/server/applogquery.ts src/lib/types.ts scripts/applogquery.test.mjs
git commit -m "Add validated Insights query building for app request logs"
```

---

## Task 5: Insights 실행 + 서버 액션

**Files:**
- Create: `src/lib/server/applog.ts`
- Modify: `src/app/actions/dashboard.ts` (import 블록 + 새 액션)

**Interfaces:**
- Consumes: Task 4의 `buildRequestLogQuery`, `toRequestLogRow`, `ROW_LIMIT`, `StatusClass`; 기존 `runInsightsQuery`, `cached`, `ENV`, `POLLING`
- Produces:
  - `fetchRequestLogRows(params: { statusClass: StatusClass; pathContains: string; windowMs?: number }): Promise<RequestLogQueryResult>`
  - `getRequestLogRowsAction(params: { statusClass: StatusClass; pathContains: string }): Promise<ActionResult<RequestLogQueryResult>>`

- [ ] **Step 1: 페치 모듈 작성**

`src/lib/server/applog.ts`:

```ts
import "server-only";
import { cached } from "./cache";
import { ENV, POLLING } from "./config";
import { runInsightsQuery } from "./logsinsights";
import { ROW_LIMIT, buildRequestLogQuery, toRequestLogRow, type StatusClass } from "./applogquery";
import type { RequestLogQueryResult } from "@/lib/types";

// Logs Insights bills per byte scanned, so this never polls on a timer — it
// runs on mount, on a filter change, and on an explicit refresh. Results are
// cached per filter combination so toggling back and forth is free.
export async function fetchRequestLogRows(params: {
  statusClass: StatusClass;
  pathContains: string;
  windowMs?: number;
}): Promise<RequestLogQueryResult> {
  // Validation lives in the query builder and throws before anything is
  // cached — a rejected filter is a user error, not a cacheable result.
  const query = buildRequestLogQuery(params);
  const key = `applog:rows:${params.statusClass}:${params.pathContains}:${params.windowMs ?? "default"}`;
  return cached(
    key,
    POLLING.logCacheTtlMs,
    async () => {
      const res = await runInsightsQuery({
        logGroup: ENV.appLogGroup,
        query,
        windowMs: params.windowMs,
      });
      const rows = res.rows.map(toRequestLogRow);
      return {
        rows,
        totalMatched: res.recordsMatched,
        scannedBytes: res.bytesScanned,
        windowLabel: res.windowLabel,
        truncated: rows.length >= ROW_LIMIT,
      };
    },
    POLLING.logFailTtlMs,
  );
}
```

`runInsightsQuery`가 반환하는 `rows`는 `InsightsRow`(= `Record<string, string>`)이므로 `toRequestLogRow`에 그대로 들어간다. 타입이 맞지 않으면 `InsightsRow`의 실제 정의(`logsinsights.ts` 10-13행)를 확인한다.

- [ ] **Step 2: 서버 액션 추가**

`src/app/actions/dashboard.ts`의 import 블록에 추가한다:

```ts
import { fetchRequestLogRows } from "@/lib/server/applog";
import type { StatusClass } from "@/lib/server/applogquery";
```

`RequestLogQueryResult`를 기존 `@/lib/types` 타입 import 목록에 알파벳 순서로 넣는다. 그리고 WAF 액션 섹션 뒤에 추가한다:

```ts
// ---------------------------------------------------------------------------
// App request log — on-demand status-code query (no polling; Insights bills
// per byte scanned)
// ---------------------------------------------------------------------------

export async function getRequestLogRowsAction(params: {
  statusClass: StatusClass;
  pathContains: string;
}): Promise<ActionResult<RequestLogQueryResult>> {
  try {
    return ok(await fetchRequestLogRows(params));
  } catch (e) {
    return fail(e);
  }
}
```

- [ ] **Step 3: 타입체크**

Run: `npx tsc --noEmit`
Expected: 출력 없음

- [ ] **Step 4: 기존 테스트 회귀 확인**

Run: `pnpm test`
Expected: 두 파일 모두 `ALL PASS`

- [ ] **Step 5: 커밋**

```bash
git add src/lib/server/applog.ts src/app/actions/dashboard.ts
git commit -m "Add an on-demand app request-log query action"
```

---

## Task 6: 앱 요청 로그 패널 + WAF 탭 카드 순서

**Files:**
- Create: `src/app/dashboard/ui/RequestLogPanel.tsx`
- Modify: `src/app/dashboard/ui/WafTab.tsx` (JSX 카드 순서 + 패널 삽입)

**Interfaces:**
- Consumes: Task 5의 `getRequestLogRowsAction`; 기존 `Card`, `ErrorNote`, `fmtTs` (shared.tsx), `fmtBytes` (logsinsights.ts는 서버 모듈이므로 **클라이언트에서 임포트하면 안 된다** — 패널 안에 로컬 포맷터를 둔다)
- Produces: `<RequestLogPanel />` — props 없음. 자체 상태로 조회한다

- [ ] **Step 1: 패널 컴포넌트 작성**

`src/app/dashboard/ui/RequestLogPanel.tsx`:

```tsx
"use client";

import { useCallback, useEffect, useState } from "react";
import { getRequestLogRowsAction } from "@/app/actions/dashboard";
import type { RequestLogQueryResult } from "@/lib/types";
import { Card, ErrorNote, SectionLoading, fmtTs } from "./shared";

const CLASSES = ["ALL", "2xx", "3xx", "4xx", "5xx"] as const;
type StatusClass = (typeof CLASSES)[number];

const LABEL: Record<StatusClass, string> = {
  ALL: "전체",
  "2xx": "2xx",
  "3xx": "3xx",
  "4xx": "4xx",
  "5xx": "5xx",
};

// Local copy — fmtBytes lives in a server-only module.
function fmtBytes(n: number): string {
  if (n >= 1024 * 1024 * 1024) return `${(n / 1024 / 1024 / 1024).toFixed(2)}GB`;
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)}MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${n}B`;
}

function statusColor(status: number): string {
  if (status >= 500) return "text-red-400";
  if (status >= 400) return "text-amber-400";
  if (status >= 300) return "text-neutral-300";
  return "text-emerald-400";
}

export function RequestLogPanel() {
  const [statusClass, setStatusClass] = useState<StatusClass>("ALL");
  const [pathInput, setPathInput] = useState("");
  const [pathQuery, setPathQuery] = useState("");
  const [data, setData] = useState<RequestLogQueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Debounce the free-text path so typing does not fire one Insights query
  // per keystroke.
  useEffect(() => {
    const id = setTimeout(() => setPathQuery(pathInput), 400);
    return () => clearTimeout(id);
  }, [pathInput]);

  const run = useCallback(async (cls: StatusClass, path: string): Promise<void> => {
    setLoading(true);
    const res = await getRequestLogRowsAction({ statusClass: cls, pathContains: path });
    if (res.ok) {
      setData(res.data);
      setError(null);
    } else {
      setError(res.error);
    }
    setLoading(false);
  }, []);

  // Fires on mount and whenever a filter settles. Never on a timer.
  useEffect(() => {
    void run(statusClass, pathQuery);
  }, [run, statusClass, pathQuery]);

  const rows = data?.rows ?? [];

  return (
    <Card
      title={`앱 요청 로그 (${rows.length})`}
      right={
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <ErrorNote error={error} />
          {CLASSES.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => setStatusClass(c)}
              className={`rounded px-2 py-0.5 font-mono text-[10px] ${
                statusClass === c
                  ? "bg-neutral-200 text-neutral-900"
                  : "bg-neutral-800 text-neutral-400 hover:bg-neutral-700"
              }`}
            >
              {LABEL[c]}
            </button>
          ))}
          <input
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            placeholder="경로 검색"
            className="w-32 rounded border border-neutral-700 bg-neutral-900 px-2 py-0.5"
          />
          <button
            type="button"
            onClick={() => void run(statusClass, pathQuery)}
            className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
          >
            조회
          </button>
        </div>
      }
    >
      {data && (
        <div className="mb-2 font-mono text-[10px] text-neutral-500">
          창 {data.windowLabel} · 스캔 {fmtBytes(data.scannedBytes)} · 매칭 {data.totalMatched.toLocaleString()}건
          {data.truncated && (
            <span className="ml-1 text-amber-500">· 상위 {rows.length}건만 표시 (나머지 생략)</span>
          )}
        </div>
      )}
      {loading && rows.length === 0 ? (
        <SectionLoading />
      ) : (
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-left font-mono text-[10px]">
            <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
              <tr>
                {["시각", "메소드", "경로", "상태", "지연(ms)"].map((h) => (
                  <th key={h} className="px-2 py-1 font-medium whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-t border-neutral-800 text-neutral-300">
                  <td className="px-2 py-0.5 whitespace-nowrap text-neutral-500">{fmtTs(r.ts)}</td>
                  <td className="px-2 py-0.5">{r.method}</td>
                  <td className="max-w-64 truncate px-2 py-0.5" title={r.path}>
                    {r.path}
                  </td>
                  <td className={`px-2 py-0.5 font-bold tabular-nums ${statusColor(r.status)}`}>
                    {r.status}
                  </td>
                  <td className="px-2 py-0.5 tabular-nums text-neutral-500">{r.latencyMs}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && !error && (
            <div className="p-3 text-center text-[11px] text-neutral-500">
              {loading ? "조회 중…" : "조건에 맞는 요청 없음"}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
```

- [ ] **Step 2: WafTab에 패널 임포트**

`WafTab.tsx` 12행 아래에 추가한다:

```tsx
import { RequestLogPanel } from "./RequestLogPanel";
```

- [ ] **Step 3: 카드 순서 변경 + 패널 삽입**

`WafTab.tsx`의 `return (` 이후 JSX를 재배열한다. **카드 내용은 한 글자도 바꾸지 않고 순서만 옮긴다.** 목표 순서:

1. `message` 배너 (그대로 최상단)
2. `샘플 요청 원본` 카드 — 현재 파일 맨 끝(403-486행)에서 잘라 여기로
3. `<RequestLogPanel />` — 신규
4. `WAF 이상 요약` · `적용 이력 / 롤백`을 담은 `<div className="grid grid-cols-1 gap-3 lg:grid-cols-2">` (현재 140행)
5. `WAF 로그 통계` 카드 (현재 209행)
6. `추천 규칙` 카드 (현재 248행)

`confirmApply` 모달 등 카드 밖 요소가 있으면 원래 위치의 상대 순서를 유지한다.

- [ ] **Step 4: 타입체크**

Run: `npx tsc --noEmit`
Expected: 출력 없음

- [ ] **Step 5: 실제 앱에서 확인**

Insights 실행 경로는 AWS가 필요하므로 단위 테스트로 덮을 수 없다. 실제 앱에서 확인한다.

```bash
pnpm dev
```

브라우저에서 `http://localhost:3100/dashboard` → WAF 탭. 확인 항목:

- 카드 순서가 조회 → 요약/이력 → 로그 통계 → 추천 규칙인지
- `샘플 요청 원본`에 `상태` 컬럼이 있고, ALLOW 행은 `—`, BLOCK 행은 코드 또는 `—`인지
- 헤더 `상태`에 마우스를 올리면 툴팁이 뜨는지
- 검색창에 `403` 입력 시 필터가 걸리는지
- `앱 요청 로그` 패널이 마운트 시 1회 조회하는지
- `4xx` / `5xx` 토글이 실제로 행을 좁히는지
- 경로 검색에 `/v1/user` 입력 후 400ms 뒤 1회만 조회되는지 (dev 서버 로그의 `POST /dashboard` 횟수로 확인)
- 경로 검색에 `"` 입력 시 조용히 실패하지 않고 `조회 실패: 경로 검색어에 허용되지 않는 문자가 있음 …`이 뜨는지
- 카드 헤더에 `창 60m · 스캔 …MB · 매칭 …건`이 표시되는지
- **패널이 자동 갱신되지 않는지** — 1분간 방치하며 dev 서버 로그에 새 `POST`가 없어야 한다

`ENV.appLogGroup`이 비어 있거나 접근 권한이 없으면 `조회 실패: …`가 뜬다. 그 경우 이는 환경 문제이며 코드 결함이 아니다 — 오류 문구가 원인을 드러내는지만 확인한다.

- [ ] **Step 6: 커밋**

```bash
git add src/app/dashboard/ui/RequestLogPanel.tsx src/app/dashboard/ui/WafTab.tsx
git commit -m "Add an app request-log panel and move the query cards to the top"
```

---

## Task 7: 마무리

- [ ] **Step 1: 전체 검증**

```bash
npx tsc --noEmit && pnpm test
```
Expected: 타입체크 무출력, 두 테스트 파일 `ALL PASS`

- [ ] **Step 2: 푸시**

```bash
git push
```

- [ ] **Step 3: 스펙에 진행 상황 기록**

`docs/superpowers/specs/2026-08-10-waf-log-query-and-rule-sandbox-design.md`의 상태 줄을 다음으로 바꾼다:

```markdown
상태: 파트 A 구현 완료. 파트 B(규칙 샌드박스) 미착수
```

```bash
git add docs/superpowers/specs/2026-08-10-waf-log-query-and-rule-sandbox-design.md
git commit -m "Mark part A complete in the design spec"
git push
```

---

## Self-Review

**스펙 커버리지**

| 스펙 요구 | 태스크 |
|---|---|
| A1 카드 순서 | Task 6 Step 3 |
| A2 `WafSampleRow.responseCode` | Task 2 Step 1 |
| A2 `listSampleRows`가 `ResponseCodeSent` 읽기 | Task 2 Step 4 |
| A2 값 없으면 `—` | Task 2 Step 6 |
| A2 검색 해이스택에 코드 | Task 2 Step 7 |
| A2 컬럼 한계 툴팁 | Task 2 Step 6 |
| A3 `PARSE_FIELDS` 공유 | Task 3 (스펙은 podlogs export를 제안했으나 순수 모듈 `logfields.ts`로 이관 — 경계가 더 맞고 테스트가 AWS SDK를 로드하지 않는다) |
| A3 상태 클래스 Insights 필터 | Task 4 Step 4, 테스트 Step 2 |
| A3 경로 필터 + 검증 | Task 4 Step 4, 거부 케이스 7건 |
| A3 30초/10초 캐시, 창·행 상한 | Task 5 Step 1 |
| A3 자동 폴링 없음 | Task 6 Step 1 (타이머 없음), Step 5 마지막 확인 항목 |
| A3 서버 액션 | Task 5 Step 2 |
| A3 UI 토글·검색·컬럼·색 | Task 6 Step 1 |
| A3 출처 표기 + 절단 표시 | Task 6 Step 1 |
| 테스트 하네스 | Task 1 |

파트 B는 이 계획의 범위가 아니며 의도적으로 태스크가 없다.

**플레이스홀더 스캔:** TBD/TODO 없음. 모든 코드 단계에 실제 코드가 들어 있다. Task 6 Step 3은 코드 대신 순서 목록인데, 기존 JSX 블록을 옮기는 작업이라 원문을 복제하는 것이 오히려 오류를 부른다 — 대상 블록을 행 번호로 특정했다.

**타입 일관성:** `StatusClass`가 두 곳에 정의된다 — `applogquery.ts`(서버, Task 4)와 `RequestLogPanel.tsx`(클라이언트, Task 6). 클라이언트가 서버 모듈에서 타입을 임포트하면 `server-only` 가드에 걸리므로 의도된 중복이다. 두 정의의 멤버는 `"ALL" | "2xx" | "3xx" | "4xx" | "5xx"`로 동일하며, 서버 액션 경계에서 구조적으로 호환된다. 한쪽을 바꾸면 다른 쪽도 바꿔야 한다. `toRequestLogRow`는 Task 4에서 정의되고 Task 5에서만 쓰이며 이름이 일치한다. `ROW_LIMIT`은 Task 4에서 정의되고 Task 5의 `truncated` 계산에 쓰인다. `fmtBytes`는 Task 6에서 의도적으로 로컬 복제한다(원본은 서버 모듈).
