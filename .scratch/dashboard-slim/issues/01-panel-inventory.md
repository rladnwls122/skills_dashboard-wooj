# 01 — 현재 화면 전수 인벤토리

Type: task
Status: resolved
Blocked by: —
Parent: ../map.md

## Question

지금 8개 탭(`요약/성능/방화벽/로그/점검/시험/규칙생성/설정`)에 있는 **모든 카드와 지표를 하나도 빼지 않고**
나열하고, 각각에 대해 다음을 채운다.

| 항목 | 어느 탭 | 데이터 출처 | 조회 비용 | 대회 중 이 값을 보고 무엇을 결정하는가 | 판정 |
|---|---|---|---|---|---|

- **데이터 출처**: CloudWatch / Logs Insights / k8s API / WAF API / SQLite 이력 / 로컬 계산 중 무엇인지.
- **조회 비용**: Logs Insights 스캔처럼 돈이나 지연이 붙는 것을 표시. 자동 새로고침 주기와 곱해지는 값이다.
- **결정**: "이 숫자가 X를 넘으면 Y를 한다"를 한 줄로 못 쓰면 그 카드는 감시용이 아니다.
- **판정**: `성능` / `트래픽` / `규칙 생성` / `설정 모달` / `삭제` 중 어디로 가는가.
  탭은 이 셋으로 확정됐다(map Notes) — `요약` 탭은 없어지고 상시 감시는 `성능`이 맡는다.

동시에 **죽은 코드**를 식별한다. 확인된 것: `src/app/dashboard/ui/ActionTab.tsx`(12.9KB)는 어디서도 import되지
않는다. `IncidentTab`은 독립 탭이 아니라 `AiTab` 안에 중첩돼 있다. 그 외에 도달 불가능한 컴포넌트,
호출되지 않는 `src/lib/server/*` 모듈이 더 있는지 전수 확인한다.

이건 결정이 아니라 조사다 — 판정 열은 제안이고, 확정은 `03`에서 사람이 한다.

산출물은 이 파일의 `## Answer`에 표로 남긴다.

## Answer

전체 인벤토리: [research/01-panel-inventory.md](../research/01-panel-inventory.md)

- **75개 지표 / 36장 카드**를 전수 나열했다 (8탭 + 화면 크롬). 출처는 CloudWatch 메트릭명·Insights 쿼리·
  k8s API·WAF API·SQLite 단위로 특정했고, 비용은 `$ Insights` / `WAF API` / `metrics-server` 3종으로 표시.
- **삭제 제안 22행.** 판단선("X 넘으면 Y")을 못 쓴 카드: Correlation, Incident Timeline, Incident Context,
  Header 패턴, Method, 채점 키 개수 등.
- **죽은 코드 약 191KB** (소스 142 + 테스트 49) — `src/`+`scripts/`의 약 1/3.
- **중복 Top 3**: ① WAF 차단 건수가 **4곳**에, 그것도 출처 2가지(CloudWatch vs Insights 전수 —
  코드가 스스로 "다를 수 있다"고 적어놓았다) ② 4XX/5XX가 **5가지 형태** ③ Pod 건강이 **4개 카드**.

### 이 티켓의 전제 두 개가 틀렸다 — 정정

1. **`ActionTab.tsx`는 죽은 코드가 아니다.** `PerformanceTab.tsx:13`에서 import되고 `:559`에서 렌더된다.
   (직접 확인함.) 이 파일에 적혀 있던 "어디서도 import되지 않는다"는 틀렸다.
2. **`규칙 생성`의 승격·롤백 기계가 코드에 아예 없다.** `UpdateWebACLCommand`는 `waf.ts:7`에서
   **import만 되고 호출되는 곳이 없다**(직접 확인함). `applyHistory()`/`waf_history`도 화면에 안 그려진다.
   README가 "적용·롤백"을 말하지만 실제로는 **미구현**이다 — `04`는 기존 기능 정리가 아니라
   **신규 구현**으로 잡아야 한다.

### 버그 1건

`상태코드 추이` 차트는 2XX/3XX 선을 그릴 수 없다 — `VISIBLE_METRICS`(`src/app/actions/dashboard.ts:114`)에
`http2xx`/`http3xx`가 없어서 UI까지 데이터가 오지 않는다. `06`에서 고친다.

### 동시 작업 경고

조사 중 **다른 세션이 같은 워크트리에서 작업하고 있었다.** `git status` 확인 결과:
`시험`(Sandbox) 탭 폐기가 이미 진행 중이고(`SandboxTab.tsx`, `rulesim.ts`, `rulestatement.ts`,
`ruletransform.ts`, `rulejson.ts`, `rulemanaged.ts`, `rulerequest.ts`, `ruleinjection.ts` 삭제 staged),
`logfields.ts`의 `PARSE_FIELDS`에 **`requestid`/`uuid` 추출이 이미 추가됐다**.
`06`에서 그 항목들은 이미 끝난 것으로 보고 중복 작업하지 말 것.
