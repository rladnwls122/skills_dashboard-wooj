# 06a — 삭제와 탭 재편

Type: task
Status: open
Blocked by: 01, 03
Parent: ../map.md

## Question

여기서 결정은 없다. `01`이 찾아낸 죽은 코드를 지우고 `03`의 배분안대로 화면을 다시 짠다.
신규 기계는 만들지 않는다 — 그건 `06b`·`06c`다.

**착수 전 `git status` 확인 필수.** 다른 세션이 `시험`(Sandbox) 탭 폐기를 이미 실행했다
(Sandbox 트리 8모듈 + 테스트 2개 삭제 staged, `logfields.ts`의 `requestid`/`uuid` 추출 추가 완료).
중복 작업하지 말 것.

### 지운다

- `요약` 탭 계열: `OverviewTab.tsx`, `correlation.ts`, `incident.ts`, `gateway.ts`,
  `IncidentTab.tsx`, `scripts/gateway.test.mjs`, 딸린 타입 4개.
- `WafTab.tsx` — 내용은 아래 `옮긴다`로 분산되고 파일은 사라진다.
- `CheckTab.tsx` — 프로브 UI는 `AiTab`으로 옮기고 `probe.ts`는 **남긴다**.
- 상단 상태등 6칸(#69)과 `DashboardClient.tsx`의 `buildSegments`.
- 도달 불가능한 것들: `getWafHistoryAction`, `getDeploymentAction`, `previewPatchAction`,
  `wafJson()`, `logsinsights.ts`의 `fmtBytes()`, `probeTimeoutMs()`, 죽은 타입 6개,
  `CheckCapacityCommand` import.
- `03`이 버리기로 한 카드 22행 — 목록은 `01` 전수표의 `판정` 열.

**지우지 않는 것 (헷갈리기 쉬움):**

| 대상 | 왜 남기나 |
|---|---|
| `ActionTab.tsx` | 살아 있다(`PerformanceTab.tsx:559`). `03`이 `성능` 탭 맨 아래 조치 도구로 유지 |
| `waf_history` 테이블, `insertWafHistory`/`getWafHistory`/`applyHistory()` | 지금은 죽어 있지만 `06b`가 여기에 연결한다 |
| `UpdateWebACLCommand` import | 같은 이유 |
| `probe.ts` | `규칙 생성` 탭의 롤백 판단에 쓴다(`04`) |
| `ruleassemble.ts`, `threatsig.ts` | UA·SQLi 조립이 여기 있다 |

### 옮긴다

| 무엇 | 어디서 | 어디로 |
|---|---|---|
| 경로·쿼리스트링 통계 (#47·#50) | `WafTab` | `TrafficTab` |
| WAF Blocked/Allowed 추이 (#6·#7) | `WafTab` | `TrafficTab` |
| 규칙 목록 + WCU (#45·#46) | `WafTab` | `AiTab` |
| 샘플 요청 원본 (#42) | `WafTab` | `AiTab` |
| 프로브 (#58·#59) | `CheckTab` | `AiTab` 하단 |
| 환경 설정 (#67·#68) | `SettingsTab` (탭) | 톱니 모달 — **컴포넌트는 손대지 않는다** |

`LogTab.tsx` → `TrafficTab.tsx` 이름 변경. **신규 탭 파일은 만들지 않는다.**
`DashboardClient.tsx`의 `TABS`가 8 → 3(`성능`/`트래픽`/`규칙 생성`)으로 줄고 import 4줄이 사라진다.

### 다시 짠다

`03`의 와이어프레임대로. above the fold = 채점 키 8줄 + 노드 대수 자리(빈 채로 두고 `06c`가 채운다)
→ TRT/4XX/5XX/RDS 4타일 → Node·Pod 개수 → 이상 목록.

- 카드 부제와 `조회 구간 …` 반복 표기를 전부 제거하고 창 정보는 WindowBar 한 곳에만 둔다.
- 차트는 꺾은선으로 통일, 툴팁은 시각(`HH:MM`)과 측정값을 분리 표기.
- 중복 제거: WAF 차단 건수 4곳 → 1곳(출처를 Insights 전수로 통일), 4XX/5XX 5형태 → 2개,
  Pod 건강 4카드 → 1카드. `01`의 중복 절 D1~D14 참조.
- 채점 키 8줄은 5분 자동 + 수동 `⟳`(`03`).
- 드릴다운은 탭 이동으로 통일하고 카드 확대(`⤢`)를 제거한다. 컨텍스트는 시간창만 따라간다.

### 버그

- `상태코드 추이`(#37)를 **삭제하므로 `VISIBLE_METRICS`의 `http2xx`/`http3xx` 누락 버그는 같이 사라진다.**
  메트릭을 추가하지 말고 차트를 지운다.
- `requestCount`는 CloudWatch에서 받아오는데 화면에 안 나온다 — `03`의 와이어프레임에도 없으므로
  `fetchCoreMetrics` 쿼리에서 뺀다. CW 호출이 그만큼 줄어든다.
- `fmtBytes`가 3벌인 문제(D14)는 `ui/shared.tsx`의 것 하나로 통일한다.

**정지 조건**: `mise run build-clean` 통과 + 대시보드를 띄워 `성능` 탭에 실제 값이 보이는 것.
이 단계만 끝나도 대회에서 상시 감시 화면으로 쓸 수 있어야 한다.

## Answer

main 세션이 실행했다. 결과를 wayfinder 세션이 확인한 것만 적는다.

- **탭 8장 → 3장.** `DashboardClient.tsx`의 `TABS`가 `성능`/`트래픽`/`규칙 생성`이다.
- 파일 이동은 계획대로다: `LogTab.tsx` → `TrafficTab.tsx`, `CheckTab.tsx` → `ProbePanel.tsx`
  (프로브를 살려 `규칙 생성`으로 옮기기 위한 이름 변경). **신규 탭 파일 0개.**
- 삭제: `OverviewTab`, `WafTab`, `IncidentTab`, `correlation.ts`, `gateway.ts`, `incident.ts`,
  `scripts/gateway.test.mjs`. Sandbox 트리는 착수 전에 이미 삭제되어 있었다.
- `ActionTab.tsx`는 남았다(계획대로).
- `VISIBLE_METRICS`가 4타일 + WAF 2종으로 줄었다. **`http2xx`/`http3xx`를 추가하지 않고 차트를
  지우는 쪽**으로 갔다 — 코드 주석이 그렇게 적혀 있다. `rdsDatabaseConnections`도 빠졌다.
- 카드 부제(`basis`) 제거가 진행됐다.
- `pnpm typecheck` 통과.

### 계획과 달랐던 것

`test:gateway`가 테스트 체인에서 빠졌다 — `gateway.ts`를 지웠으니 당연한 결과이고,
`06a` 문서에 명시돼 있지 않았을 뿐이다.
