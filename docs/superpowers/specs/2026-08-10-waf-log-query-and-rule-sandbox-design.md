# WAF 로그 조회 개편 + 규칙 시험 샌드박스

날짜: 2026-08-10
상태: 파트 A 구현 완료. 파트 B(규칙 샌드박스) 미착수

## 배경

대회용 AWS + Kubernetes 트러블슈팅 콘솔의 WAF 탭에 두 가지가 없다.

1. 요청을 **응답 코드로 조회**할 수단. 샘플 요청 원본 표에는 상태 코드 컬럼이 없고, 조회 칸 자체가 탭 맨 아래에 있어 판단 흐름과 순서가 맞지 않는다.
2. 규칙을 **적용 전에 시험**할 수단. 기존 `simulateRecommendation()`은 대시보드가 *생성한* 추천 규칙만 평가한다. 운영자가 직접 쓴 규칙이나 Amazon Q가 돌려준 수정안은 시험할 방법이 없어, 검증 없이 적용하거나 감으로 판단해야 한다.

두 기능은 서로 의존하지 않는다. 파트 A를 먼저 구현한다.

## 선행 제약 — 볼류메트릭 탐지 비활성

같은 날 적용된 대회 규칙이 이 설계의 전제다. 단일 IP에서 들어오는 대량 요청은 시나리오 자체의 부하 생성기이므로 탐지·차단 대상이 아니다. `RateBasedStatement` 추천은 생성되지 않고, 출처 IP 순위는 Incident 산출물에서 제거되며, 트래픽 이상 판정은 `APP_TRAFFIC_PATHS`(`/v1/user`, `/v1/product`, `/v1/stress`, `/v1/image`) 밖을 향한 요청만 대상으로 한다.

이 설계는 그 정책을 되돌리지 않는다. 파트 B의 기본 정상 요청 집합은 `APP_TRAFFIC_PATHS`에서 파생시켜 정책과 자동으로 동기화한다.

---

# 파트 A — WAF 로그 조회 개편

## A1. 카드 순서

`WafTab.tsx`의 카드 순서를 바꾼다. 로직 변경 없이 JSX 순서만 조정한다.

| 순서 | 카드 |
|---|---|
| 1 | **조회** — 샘플 요청 원본 (WAF) + 앱 요청 로그 (상태 코드) |
| 2 | WAF 이상 요약 · 적용 이력/롤백 (2열) |
| 3 | WAF 로그 통계 (경로/쿼리/헤더/메소드/차단) |
| 4 | 추천 규칙 |

탭을 열자마자 원시 요청을 보며 판단하는 흐름에 맞춘다.

## A2. 샘플 요청 원본에 `상태` 컬럼

`SampledHTTPRequest.ResponseCodeSent`(AWS SDK에 `number | undefined`로 존재함을 확인)를 읽어 표에 노출한다.

- `WafSampleRow`에 `responseCode: number | null` 추가
- `listSampleRows()`가 `s.ResponseCodeSent ?? null`을 채운다
- 값이 없으면 `—` 표시
- 기존 자유 검색어 해이스택에 코드 문자열을 포함시켜 `403` 입력으로 걸러진다

**이 컬럼의 한계를 UI에 명시한다.** `ResponseCodeSent`는 WAF가 직접 응답을 생성한 경우(Block + 커스텀 응답, CAPTCHA, Challenge)에만 채워진다. ALLOW된 정상 요청은 대개 빈 값이다. 컬럼 헤더에 "WAF가 직접 응답한 요청만 기록됨" 툴팁을 달아 빈 칸이 버그로 읽히지 않게 한다. 진짜 요청별 상태 코드는 A3이 담당한다.

## A3. 새 패널 — 앱 요청 로그 (진짜 상태 코드)

### 데이터 출처

이 환경의 앱 로그는 **구조화 JSON**이다. `podlogs.ts`의 `PARSE_FIELDS`가 `log` 필드에서 `method` / `path` / `status` / `latency_ms`를 이미 뽑아내고 있다. 따라서 상태 코드는 Logs Insights에서 **숫자 필드로 직접 필터**할 수 있다.

`requestlog.ts`의 Gin 정규식 파서는 쓰지 않는다. 그것은 k8s API 폴백 경로(`fetchPodLogsKube`) 전용이다.

### 신규 모듈 `src/lib/server/applog.ts`

```ts
export interface RequestLogRow {
  ts: string;        // ISO
  method: string;
  path: string;
  status: number;
  latencyMs: number;
}

export type StatusClass = "ALL" | "2xx" | "3xx" | "4xx" | "5xx";

export interface RequestLogQueryResult {
  rows: RequestLogRow[];
  // recordsMatched — 200행 상한 너머 실제 매칭 건수
  totalMatched: number;
  scannedBytes: number;
  windowLabel: string;
}

export async function fetchRequestLogRows(params: {
  statusClass: StatusClass;
  pathContains: string;
  windowMs?: number;
}): Promise<RequestLogQueryResult>;
```

기존 `runInsightsQuery()`(logsinsights.ts)를 그대로 재사용한다. 동시성 게이트(`maxConcurrent: 2`), 하드 데드라인 + `StopQuery`, 창 클램프(`maxWindowMs` 4시간), `bytesScanned` 수집이 이미 그 안에 있다.

쿼리 형태:

```
<PARSE_FIELDS>
| filter ispresent(status)
[ | filter status >= 400 and status < 500 ]   # statusClass가 ALL이 아닐 때
[ | filter path like "<escaped>" ]            # pathContains가 비어있지 않을 때
| fields @timestamp, method, path, status, latency_ms
| sort @timestamp desc
| limit 200
```

`PARSE_FIELDS`는 `podlogs.ts`에서 export하도록 바꿔 공유한다(현재 모듈 로컬 상수). 파드 스코프는 붙이지 않는다 — 앱 전체를 대상으로 조회한다.

### 입력 검증

`pathContains`는 Insights 쿼리 문자열에 삽입되므로 다음을 강제한다.

- 길이 상한 120자
- 허용 문자 `[A-Za-z0-9/_.\-]`만. 그 외 문자가 있으면 평가하지 않고 `허용되지 않는 문자` 오류를 반환한다
- 통과한 값도 `\`와 `"`를 이스케이프해 삽입한다

허용 문자셋이 경로 검색에 충분하므로 정규식 이스케이프 없이 `path like "substring"` 평문 매칭을 쓴다.

### 비용 정책 준수

기존 Logs Insights 정책을 그대로 따른다.

- 성공 결과 30초 캐시 (`POLLING.logCacheTtlMs`), 실패 10초 캐시 (`POLLING.logFailTtlMs`)
- 캐시 키에 필터를 포함: `applog:rows:${statusClass}:${pathContains}:${windowMs}`
- 창 기본 60분, 최대 4시간 (`INSIGHTS_LIMITS`)
- 행 상한 200
- **자동 폴링하지 않는다.** 마운트 시 1회 + 필터 변경 시 + 수동 새로고침 버튼. 경로 입력은 400ms 디바운스. Insights는 스캔 바이트당 과금이므로 조회는 사용자 행위로만 발동한다

### 서버 액션

```ts
getRequestLogRowsAction(params: {
  statusClass: StatusClass;
  pathContains: string;
}): Promise<ActionResult<RequestLogQueryResult>>
```

`src/app/actions/dashboard.ts`에 기존 `ok()` / `fail()` 패턴으로 추가한다.

### UI — `src/app/dashboard/ui/RequestLogPanel.tsx` (신규)

WafTab.tsx가 이미 489줄이므로 별도 컴포넌트 파일로 분리한다.

- 상태 클래스 토글: `[전체] [2xx] [3xx] [4xx] [5xx]`
- 경로 검색 입력 (디바운스)
- 컬럼: 시각 · 메소드 · 경로 · 상태 · 지연(ms)
- 상태 코드는 클래스별 색: 2xx 녹색, 3xx 중립, 4xx 황색, 5xx 적색
- 카드 헤더 우측에 출처 표기: `창 60m · 스캔 12.4MB · 매칭 1,204건 (상위 200건 표시)` — `fmtBytes()` 재사용
- 200행 상한에 걸리면 잘렸다는 사실을 명시한다 (조용한 절단 금지)

### 배치에 대한 메모

앱 요청 로그는 엄밀히 WAF 데이터가 아니다. WAF 탭 상단 "조회" 그룹에 두는 것은 조회 작업 흐름에 맞춘 의도적 배치다. 기능적 문제는 없다.

---

# 파트 B — 규칙 시험 샌드박스

## B1. 입력

- **규칙**: WAFv2 Rule JSON 붙여넣기 (textarea). 대시보드가 생성하는 `ruleJson`과 동일 포맷이며 WAF 콘솔 JSON 에디터, Amazon Q 수정안과 호환된다. 추천 규칙 목록에서 불러오는 셀렉트를 함께 둔다
- **요청**: 편집 가능한 정상 요청 집합. 기본값은 `APP_TRAFFIC_PATHS`에서 파생 (`/v1/user`, `/v1/product`, `/v1/stress`, `/v1/image?id=3`) + `/healthcheck` 1행. method / path / query / userAgent / ip 편집, 행 추가·삭제

## B2. 평가기 `src/lib/server/rulesim.ts` (신규)

AWS 의존 0. 순수 함수라 AWS 없이 단위 테스트된다.

핵심은 **3값 논리** — `true` / `false` / `UNKNOWN`. 평가할 수 없는 문법을 절대 "통과"로 접지 않는 것이 이 도구의 존재 이유다. 틀린 답을 주는 시험 도구는 없는 것보다 나쁘다.

```
And:  하나라도 false → false;  아니면 UNKNOWN 있으면 → UNKNOWN;  else true
Or:   하나라도 true  → true;   아니면 UNKNOWN 있으면 → UNKNOWN;  else false
Not:  뒤집되 UNKNOWN은 UNKNOWN 유지
```

### 평가 가능

| 항목 | 범위 |
|---|---|
| `ByteMatchStatement` | `SearchString` 평문·base64 양쪽 수용, PositionalConstraint 5종 (EXACTLY / STARTS_WITH / ENDS_WITH / CONTAINS / CONTAINS_WORD) |
| `RegexMatchStatement` | `RegexString`. 컴파일 실패 시 UNKNOWN + 이유 |
| `SizeConstraintStatement` | 바이트 길이 비교 6종 (EQ / NE / LE / LT / GE / GT) |
| `AndStatement` / `OrStatement` / `NotStatement` | 재귀 조합 |
| `FieldToMatch` | UriPath, QueryString, SingleHeader, Method, AllQueryArguments |
| `TextTransformations` | Priority 순서대로 NONE, LOWERCASE, URL_DECODE, TRIM, COMPRESS_WHITE_SPACE, HTML_ENTITY_DECODE |

### UNKNOWN 으로 보고 (통과로 간주하지 않음)

`IPSetReferenceStatement`(ARN 참조), `RegexPatternSetReferenceStatement`(ARN 참조), `ManagedRuleGroupStatement`(AWS 내부 로직), `LabelMatchStatement`(생성된 라벨 필요), `RateBasedStatement`(요청량 기반), `SqliMatchStatement` / `XssMatchStatement`(AWS 독자 토크나이징).

마주친 미지원 문법의 종류를 결과에 나열한다.

## B3. 판정 semantics

| 매칭 | 규칙 Action | 결과 |
|---|---|---|
| 매칭 안 됨 | — | `통과` |
| 매칭 | `Block` | `차단` — 정상 요청이면 오탐 |
| 매칭 | `Count` | `카운트만` (차단 아님) |
| UNKNOWN | — | `판정 불가` |

전체 verdict는 다음 우선순위로 하나만 정해진다. 차단과 UNKNOWN이 동시에 있으면 차단이 이긴다 — 조치 가능한 사실이 먼저 보여야 한다.

1. 차단 1건 이상 → `오탐 위험`
2. 아니고 UNKNOWN 1건 이상 → `판정 불가`
3. 아니면 → `SAFE`

## B4. 서버 액션 / UI

- `testRuleJsonAction({ ruleJson, requests }): Promise<ActionResult<RuleTestResult>>` — 캐시 없음 (순수 + 즉시)
- `DashboardClient.tsx`의 `TABS`에 `{ id: "Sandbox", ko: "시험" }` 추가
- 신규 `src/app/dashboard/ui/SandboxTab.tsx` — 카드 3개 (규칙 JSON / 정상 요청 표 / 결과 표)

## B5. 입력 상한 (ReDoS 방어)

사용자 정규식이 서버 액션에서 실행되는 구조다. 상한을 강제한다.

- `ruleJson` 20KB
- `RegexString` 200자
- 요청 행 50개
- 요청 필드별 500자

## B6. 오류 처리

JSON 파싱 실패와 `Statement` 누락은 평가 없이 이유를 표시한다. 미지원 문법은 종류를 나열하고 해당 행을 `판정 불가`, 전체 verdict를 `판정 불가`로 만든다. 요청 목록이 비면 그 사실을 명시한다.

---

# 테스트

프로젝트에 테스트 프레임워크가 없다. 새 의존성을 넣지 않고, Node 24의 타입 스트리핑 + `server-only` 스텁 resolve 훅으로 실제 소스를 그대로 불러 검증한다. 이 방식은 같은 날 볼류메트릭 정책 변경을 검증하는 데 이미 사용했다.

- `scripts/testing/stub-hooks.mjs` — `server-only`를 빈 모듈로, 확장자 없는 상대 임포트에 `.ts`를 붙이는 resolve 훅
- `package.json`에 스크립트 추가. 새 devDependency 없음

## 파트 A 테스트

`applog.ts`의 쿼리 조립과 검증은 AWS 없이 검사 가능한 순수 부분이다.

- 상태 클래스별로 올바른 `filter status >= N and status < M`이 생성되는지
- `statusClass: "ALL"`일 때 상태 필터가 아예 붙지 않는지
- `pathContains`가 비면 경로 필터가 붙지 않는지
- 허용되지 않는 문자(`"`, 백슬래시, 공백, 정규식 메타문자)가 오류로 거부되는지
- 길이 상한 초과가 거부되는지
- Insights 행 → `RequestLogRow` 변환이 `status`/`latencyMs`를 숫자로, `@timestamp`를 ISO로 옮기는지

## 파트 B 테스트

- PositionalConstraint 5종 각각
- TextTransformations 체인이 Priority 순서대로 적용되는지
- And / Or / Not의 UNKNOWN 전파 (특히 `And`에 false + UNKNOWN이 섞이면 false)
- base64 `SearchString`과 평문 `SearchString` 모두 동일 결과
- `SizeConstraintStatement` 비교 6종
- Block과 Count가 서로 다른 결과를 내는지
- **미지원 문법이 `통과`로 새지 않는지** — 가장 중요한 케이스
- 기본 정상 요청 집합이 대시보드 자체 생성 UA 규칙에 대해 전부 `통과`인지

---

# 구현 순서

1. 파트 A — A1 카드 순서 → A2 상태 컬럼 → A3 앱 요청 로그 패널
2. 파트 B — 평가기 + 테스트 먼저, 그 다음 액션과 UI

파트 A 완료 후 실제 앱에서 확인한 뒤 파트 B로 넘어간다.
