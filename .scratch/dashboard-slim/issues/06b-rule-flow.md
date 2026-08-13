# 06b — 차단 흐름 구현

Type: task
Status: open
Blocked by: 04, 06a, 07
Parent: ../map.md

## Question

여기서 결정은 없다. `04`가 정한 상태 모델을 코드로 만든다. **신규 구현이다** —
`01`이 확인한 대로 승격·롤백 기계가 코드에 한 줄도 없다(`UpdateWebACLCommand`가 import만 되고 호출 0건).

### 만든다

| 무엇 | 자리 | 내용 |
|---|---|---|
| `setRuleAction(ruleJson, action \| null)` | `server/waf.ts` | `GetWebACL` → `LockToken` → 규칙 배열 갱신 → `UpdateWebACL`. **적용·승격·내리기가 전부 이 함수 하나.** `action: null`이 제거. `WAFOptimisticLockException`이면 재조회 후 1회 재시도 |
| 스코프다운 검사기 | `server/ruleassemble.ts` | 최상위가 `AndStatement`이고 자식 중 하나가 제공 API 경로 매칭이 아니면 거부. **조립 경로와 붙여넣기 경로가 같은 함수를 통과한다** |
| `updateWafRuleAction` | `actions/dashboard.ts` | 서버 액션 1개. 성공 시 `insertWafHistory`에 **채점 키 8줄 스냅샷**을 동봉 |
| COUNT 실측 병합 | 신규 모듈 | `07`의 2단 쿼리. WAF 로그에서 `nonTerminatingMatchingRules` 매칭분의 `requestid` 목록 → 앱 로그 2차 쿼리 → 코드에서 병합. **SQLi 규칙 하나를 위한 것** |
| 오탐 이상 규칙 | `server/anomaly.ts` | `detectAnomalies()`에 규칙 1개 추가 + 입력에 `waf_history`. 적용 후 5분 내 어느 채점 키든 스냅샷 대비 −1%p → `CRITICAL` |
| 규칙 행 UI | `AiTab` | 상태 배지 + 전이 버튼. 상태는 로컬 저장 없이 `GetWebACL` 응답에서 매번 파생 |

### 규칙 종류마다 다르다

- **UA**: `추천됨` → `BLOCK` → `내려감`. 버튼 2개. 승격 게이트 없음.
- **SQLi**: `추천됨` → `COUNT` → `BLOCK` → `내려감`. 버튼 3개. COUNT 상태에서만 실측 표가 펼쳐진다.

실측 표에는 `매칭 n건 (정상 a · 비정상 b · 조인 불가 c)`를 나란히 적는다.
**조인 불가를 비정상에 합치지 않는다** — `07`대로 POST/PUT은 양쪽 다 `requestid`가 없다.
매칭 20건 미만이면 `표본 부족` 회색 문구를 붙이되 버튼은 막지 않는다.

### 지운다

- `assembleRule("path", …)`과 `01`의 #63(`의심 경로` 규칙 조립) 카드, 딸린 테스트.
  미지정 경로는 ALB가 404를 내므로 WAF가 손댈 이유가 없다(`04`).
- `TrafficTab` 경로 통계의 `규칙 만들기` 버튼은 처음부터 만들지 않는다.
  대신 **UA 목록(`httpSummary.byUa`)을 여기서 처음 노출**하고 거기에 버튼을 단다.

### 절차로 못박을 것

UA 규칙은 COUNT를 안 거치므로 **올린 직후 프로브 1회**가 유일한 즉시 확인선이다.
`AiTab`이 규칙을 올린 뒤 프로브 카드를 자동으로 펼치고, 정상 비율이 100%가 아니면
`내리기` 버튼을 강조한다.

**정지 조건**: 실제 WebACL에 규칙 하나를 올렸다가 내리는 것까지 확인. 스코프다운 없는 JSON이
거부되는 것도 확인.

## Answer

main 세션이 실행했고, `07`의 COUNT 실측 병합만 wayfinder 세션이 미리 만들어 넘겼다.

### 만든 것

| 무엇 | 자리 | 상태 |
|---|---|---|
| `setRuleAction` | `waf.ts:536` | 적용·승격·내리기가 이 함수 하나 |
| `scopeDownRefusal(rule)` | `ruleassemble.ts:224` | 조립 경로와 붙여넣기 경로가 같은 검사를 통과한다 |
| `pathScopeStatement()` | `ruleassemble.ts:181` | `APP_TRAFFIC_PATHS`에 대한 `STARTS_WITH` Or. 조립기가 항상 이걸 AND로 묶는다 |
| `updateWafRuleAction` | `actions/dashboard.ts:331` | `setRuleAction` 진입 직전에 `scopeDownRefusal`이 걸린다 |
| `countEvidence` | `wafcountevidence.ts` (신규, wayfinder) | 07의 2단 쿼리 + 병합 |
| 오탐 이상 규칙 | `anomaly.ts:311` | `오탐 의심 — 규칙 … 적용 후 채점 키 하락` |
| 규칙 행 UI | `AiTab.tsx:100 move()` | `"COUNT" \| "BLOCK" \| null` 하나로 세 전이를 다 처리 |

`AssembleKind`가 `"ua" | "sqli"`로 줄었다 — **경로 규칙은 삭제됐다.**

### 결정대로 지킨 것

- **UA는 `Block`, SQLi는 `Count`로 조립된다.** 테스트가 그걸 고정한다
  (`sqli counts rather than blocks`, `ua rule blocks`).
- **스코프다운은 강제다.** `isPathScope`가 `UriPath`에 대한 `ByteMatch`만 인정하고,
  그것도 **실제로 제공하는 경로여야** 한다 — `/admin`으로 좁힌 규칙은 스코프다운이 아니라
  그냥 다른 규칙이라 거부된다. `RegexPatternSetReference`는 세트 내용이 AWS에 있어 액면가로 받는다.
- **COUNT 실측은 3분해로 나온다.** 조인 불가를 비정상에 합치지 않는다는 주석이 코드에 남아 있다.

### 검증

`scopeDownRefusal`에 테스트가 하나도 없어서 wayfinder 세션이 13건을 추가했다
(`scripts/ruleassemble.test.mjs`의 `--- scope-down ---` 절). 실패가 조용하고 비싼 검사라
빈칸으로 둘 수 없었다. 잡는 것: 제공 경로/Or/패턴셋 통과, `AndStatement` 없음·경로 조건 없음·
**제공하지 않는 경로로 좁힌 경우**·`UriPath`가 아닌 필드에 건 ByteMatch·한 팔짜리 And·
Statement 없음·문자열·null 거부.

`countEvidence`는 27건(`scripts/wafcountevidence.test.mjs`). `action = "COUNT"`로 거르면
아무것도 안 잡힌다는 것과, 조인 키 없는 건이 비정상으로 새지 않는다는 것이 핵심 검사다.

**실제 WebACL에 대고는 확인하지 못했다** — 조사 시점에 Web ACL과 WAF 로그 그룹이 계정에 존재하지
않았다(`07` 검증 조건). `UpdateWebACL` 왕복과 낙관적 락 재시도는 대회 당일 첫 실행이 첫 검증이 된다.
`08` 런북이 "규칙을 올린 직후 프로브 1회"를 절차로 못박은 이유이기도 하다.
