# 06c — 비용 패널 구현

Type: task
Status: open
Blocked by: 02, 05, 06a
Parent: ../map.md

## Question

여기서 결정은 없다. `05`가 정한 패널을 만든다. 자리는 `06a`가 `성능` 탭 최상단에 비워둔다.

### 만든다

| 무엇 | 내용 |
|---|---|
| 노드 대수 폴링 | `describe-instances` 30초 주기, **서버사이드 `--filters` 필수**(페이지 버킷 100/20). 결과를 SQLite `metric_samples`에 적재 |
| CloudTrail backfill | 대시보드 기동 시 **자동 1회**. `RunInstances`/`TerminateInstances`로 채점 창 전 구간 재구성. 버튼을 두지 않는다 |
| 경기 시작 시각 | 설정 모달에 한 줄 추가. 채점 창은 `T+1h ~ T+3h`로 파생 |
| 패널 렌더 | `최종 평균` 크게, `1대 증감` 그 아래, `누적 평균`·경과/남은 시간은 부제. 규격 외 인스턴스는 **0이 아닐 때만** 나타난다 |

계산은 시간가중이다. 창 길이 `W`(120분), 경과 `e`, 지금까지의 시간가중 평균 `A`, 현재 대수 `n`:

```
최종 평균 = (A × e + n × (W − e)) / W
1대 증감  = (W − e) / W
```

### 규격 외 판정

`describe-instances` 응답 하나로 끝난다 — `t3.medium`이 아니거나, `ap-northeast-2`가 아니거나,
어떤 노드로도 클러스터에 붙어 있지 않은 인스턴스.

### 하지 않는다

- **`AWS/AutoScaling` 그룹 메트릭을 쓰지 않는다.** Karpenter 노드가 어떤 ASG에도 속하지 않아
  채점 대상을 통째로 놓친다(`02`).
- **ContainerInsights를 2차 소스로 붙이지 않는다.** add-on 의존이 생기는데 얻는 건 해상도뿐이고,
  규격 외 판정은 어차피 `describe-instances`가 필요하다(`05`).
- **경기 시작 시각이 없으면 잠정값을 만들지 않는다.** `— 경기 시작 시각 미설정`을 적고 현재 대수와
  규격 외 목록만 보여준다.
- **점수를 만들지 않는다.** 색 판정·목표선·`ESTIMATED SCORE`류 표현 없음. 유일한 빨강은 규격 외
  인스턴스이며 그건 추정이 아니라 대조 결과다. 패널 하단에 한 줄 고정:
  `채점식은 비공개다. 이 패널은 채점기 입력값(대수)만 세고 점수를 만들지 않는다.`

### 문서

README에서 "`cost ratio`는 관측 불가" 서술을 새 사실로 교체한다 — 대수는 셀 수 있고, 셀 수 없는 건
대수에서 점수로 가는 비공개 계산식이다.

**정지 조건**: 설정 모달에 경기 시작 시각을 넣으면 `최종 평균`과 `1대 증감`이 실제 값으로 나오는 것.
대시보드를 껐다 켜면 backfill이 창 전 구간을 메우는 것.

## Answer

구현 완료. 서버 계층과 UI 배선을 wayfinder 세션이 맡았다(main 세션은 같은 시각 `06a`/`06b`를 하고 있었다).

### 만든 것

| 파일 | 내용 |
|---|---|
| `src/lib/server/nodecount.ts` (신규) | 진입점 `nodeCountPanel(nowMs)` 하나. `describe-instances` 조회 → `metric_samples` 적재 → 시간가중 평균/한계 효과 계산 → 규격 외 판정까지 한 번에 끝난다 |
| `scripts/nodecount.test.mjs` (신규) | 32건 통과. 산술과 backfill 역산이 검증 대상 |
| `src/app/dashboard/ui/NodeCostPanel.tsx` (신규) | `성능` 탭 최상단, `GradingCard` 바로 아래. 30초 폴링 |
| `src/app/actions/dashboard.ts` | `getNodeCostAction` 1개 추가. 캐시 없음 |
| `src/lib/server/aws.ts` | `ec2Client()` / `cloudTrailClient()` + `resetAwsClients()` 연결 |
| `src/lib/server/settings.ts` | `MATCH_START` 키. 설정 모달에 한 줄 자동 추가 |
| `README.md` | `cost ratio` 절을 실제로 붙은 패널 설명으로 교체 |

의존성 2개 추가: `@aws-sdk/client-ec2`, `@aws-sdk/client-cloudtrail`.

### 결정대로 지킨 것

- **소스는 `describe-instances` 단일.** ContainerInsights를 섞지 않았다 — 규격 외 판정에 어차피
  같은 호출이 필요하고, 섞으면 코드 경로만 둘이 된다.
- **backfill은 기동 시 자동 1회.** 버튼이 아니다. 모듈 안의 `backfillOnce` 가드가 프로세스당 한 번만
  돌리고, 실패하면 재시도 대신 패널 `notes`에 이유를 적는다(대개 권한 문제라 30초마다 재시도해봐야 낭비다).
- **경기 시작 시각이 없으면 평균을 만들지 않는다.** `finalAvg`/`marginalPerInstance`가 `null`로 나가고
  화면은 `—`와 `경기 시작 시각 미설정`을 적는다. 잠정값 없음.
- **색 판정 없음.** 숫자는 전부 중립색이고 유일한 빨강은 규격 외 목록이다. 목표선도 `ESTIMATED SCORE`류
  표현도 없다. 패널 하단에 `채점식은 비공개입니다…` 한 줄 고정.
- **규격 외는 0일 때 나타나지 않는다.**
- ASG 그룹 메트릭은 쓰지 않았다.

### 남긴 `ponytail:` 두 건

- `saveMetricSamples`가 6시간보다 오래된 행을 지운다. 3시간 대회는 덮지만, 그보다 오래된 창은
  backfill이 불가능하다. 대회 밖에서 쓰려면 보존 기한을 올려야 한다.
- `LookupEvents`를 순차로 2회 부른다. 2 TPS 제약이 있고 이벤트가 수십 건이라 병렬화하지 않았다.

### 검증

`pnpm typecheck` 통과, `pnpm test:nodecount` 32건 전부 통과.
실제 AWS 계정에 대고는 확인하지 않았다 — 조사 시점에 클러스터가 이미 삭제되어 있었다(`02` 참조).
`describe-instances`/`LookupEvents` 응답 파싱은 단위 테스트로만 검증했다.
