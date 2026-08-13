# 01 — 현재 화면 전수 인벤토리 (조사 결과)

조사 대상: `src/app/dashboard/ui/*` 16개 파일 전부, `src/app/actions/dashboard.ts`,
`src/lib/server/*` 39개 모듈, `scripts/*.test.mjs` 15개.
**소스는 한 줄도 고치지 않았다.** `판정` 열은 제안이고 확정은 `03`이 한다.

> ⚠️ **조사 중 작업트리가 바뀌었다.** 이 인벤토리는 조사 시작 시점(=8탭 원본) 기준이다.
> 조사가 끝나갈 무렵 `git status`에 `시험` 탭 폐기 작업이 나타났다 —
> `SandboxTab.tsx` + `rulesim/rulestatement/rulemanaged/rulerequest/ruleinjection/ruletransform/rulejson`
> 7개 모듈 + 테스트 2개가 삭제(staged)되고, `AiTab.tsx`에서 `onSendToSandbox`,
> `types.ts`에서 Sandbox 타입, `package.json`에서 테스트 2항목이 제거되는 중이다.
> **이 세션이 한 일이 아니다**(조사는 읽기 전용으로 수행했다). 다른 세션이 아래 `죽은 코드 C`와
> 정확히 같은 집합을 이미 실행하고 있는 것으로 보이며, 되돌리지 않았다.
> 이 표의 #60~#62(시험 탭 3행)는 그래서 이미 과거형이다.
>
> 티켓의 전제 하나를 먼저 정정한다. **`ActionTab.tsx`는 죽은 코드가 아니다.**
> `src/app/dashboard/ui/PerformanceTab.tsx:13`에서 import 되고 `:559`에서
> `<ActionTab kube={kube} />`로 렌더된다. 즉 지금 `성능` 탭 맨 아래에 Deployment
> 패치 UI가 통째로 붙어 있다. 진짜 도달 불가능한 것들은 아래 `죽은 코드` 절에 따로 적었다.

---

## Answer — 카드/지표 전수표

`탭` 약칭: 요약=OverviewTab, 성능=PerformanceTab, 방화벽=WafTab, 로그=LogTab,
점검=CheckTab, 시험=SandboxTab, 규칙생성=AiTab, 설정=SettingsTab, 크롬=DashboardClient/WindowBar.

`조회 비용` 약칭:
- **무료** — 순수 로컬 계산 또는 SQLite 읽기
- **싸다(k8s)** — Kubernetes API, TTL 2.5s, 폴링 5s
- **싸다(CW)** — CloudWatch `GetMetricData`, TTL 25s. API 호출당 과금이지만 배치 1회
- **비쌈(metrics-server)** — `metrics.k8s.io`, 없으면 통째로 실패
- **비쌈(WAF API)** — `GetSampledRequests`, 규칙 metric 수 × 1회 호출, TTL 30s
- **비쌈($ Insights)** — CloudWatch Logs Insights, **스캔 바이트당 과금**

| # | 카드/지표 | 현재 탭 | 데이터 출처 | 조회 비용 | 이 값을 보고 무엇을 결정하는가 | 판정 |
|---|---|---|---|---|---|---|
| 1 | Infrastructure Health — `TargetResponseTime` 타일 (현재값·직전값·Δ·스파크라인) | 요약 | CloudWatch `AWS/ApplicationELB TargetResponseTime` Average, dim `LoadBalancer` · `server/cloudwatch.ts fetchCoreMetrics` | 싸다(CW) | **0.5s를 넘으면 성능 탭에서 Pod/노드 CPU를 보고 replica를 올린다. 2.0s + 200%면 즉시 스케일업.** (`THRESHOLDS.targetResponseTime`) | 성능 |
| 2 | Infrastructure Health — `Target 4XX` 타일 | 요약 | CloudWatch `AWS/ApplicationELB HTTPCode_Target_4XX_Count` Sum → 분당 환산 | 싸다(CW) | **50/min을 넘으면 트래픽 탭에서 경로 분포를 보고 미지정 경로(404)인지 차단(403)인지 가른다.** 채점의 Exception Handling 항목과 직결 | 성능 |
| 3 | Infrastructure Health — `Target 5XX` 타일 | 요약 | CloudWatch `AWS/ApplicationELB HTTPCode_Target_5XX_Count` Sum | 싸다(CW) | **20/min을 넘으면 앱 장애다. 로그 → Pod 상태 → replica 순으로 본다.** 가용성 점수를 직접 깎는 유일한 지표 | 성능 |
| 4 | Infrastructure Health — `RDS Proxy Client Conn` 타일 | 요약 | CloudWatch `AWS/RDS ClientConnections` Average, dim `ProxyName=ENV.rdsProxyName` | 싸다(CW) | **80을 넘으면서 TRT도 같이 오르면 DB 병목 — Pod를 늘려도 안 낫는다는 판단 근거.** | 성능 |
| 5 | Infrastructure Health — `RDS Proxy DB Conn` 타일 | 요약 | CloudWatch `AWS/RDS DatabaseConnections` Average | 싸다(CW) | Client Conn과 거의 항상 같이 움직인다. **단독으로 쓰는 판단선을 쓸 수 없다** — Client Conn 하나면 충분 | 삭제 |
| 6 | Infrastructure Health — `WAF BlockedRequests` 타일 | 요약 | CloudWatch `AWS/WAFV2 BlockedRequests` Sum, dim `WebACL`+`Rule=ALL`(+`Region`) · CLOUDFRONT scope면 us-east-1 | 싸다(CW) | **규칙을 COUNT→BLOCK으로 올린 직후 이 값이 0에서 뜨는지로 규칙이 실제로 물렸는지 확인한다.** 반대로 정상 트래픽 시간대에 급증하면 오탐 → 롤백 | 트래픽 |
| 7 | Infrastructure Health — `WAF AllowedRequests` 타일 | 요약 | CloudWatch `AWS/WAFV2 AllowedRequests` Sum | 싸다(CW) | **Blocked와 짝으로 봐야 의미가 있다(차단률).** 단독 판단선 없음. Blocked 타일의 sub로 접어야 함 | 트래픽 |
| 8 | Pod Health — `노드 n/m Ready` | 요약 | k8s `CoreV1Api.listNode` → `server/k8s.ts countReadyNodes` | 싸다(k8s) | **Ready < Total이면 노드 하나가 죽은 것 — 채점 창의 노드 대수 산정에도 영향.** | 성능 |
| 9 | Pod Health — `정상 Pod n/m` | 요약 | k8s `listNamespacedPod` → `server/resources.ts summarizePodStatus` | 싸다(k8s) | **running < total이면 성능 탭 Pod 테이블로 내려간다.** 성능 탭 `Pod 상태 분포`와 같은 값 | 삭제(중복) |
| 10 | Pod Health — 이상 Pod 목록 (클릭 → 로그) | 요약 | 위와 동일, `statusLabel !== "Running"` 필터 | 싸다(k8s) | **한 줄이라도 뜨면 그 Pod 로그를 연다.** | 성능 |
| 11 | Pod Health — 재시작 증가 Pod 목록 | 요약 | k8s + SQLite `pod_restarts` 테이블 (`server/db.ts trackRestarts`) | 싸다(k8s) | **`재시작 +n`이 뜨면 OOM/CrashLoop이다 — Memory Limit 상향 판단.** | 성능 |
| 12 | Warning Events (상위 8건, 클릭 → 상세 모달) | 요약 | k8s `listNamespacedEvent(fieldSelector: type=Warning)` | 싸다(k8s) | **`FailedScheduling`이 뜨면 노드가 모자란 것, `Unhealthy`면 프로브 실패.** 다만 성능 탭 Warning Event Board와 같은 배열의 잘린 버전 | 삭제(중복) |
| 13 | Anomalies (카운트 + 제목/타입 목록) | 요약 | 순수 로컬 계산 `server/anomaly.ts detectAnomalies` — 입력은 메트릭·httpSummary·pods·events·fingerprints | 무료 | **CRITICAL이 하나라도 뜨면 그 항목의 근거를 읽고 조치한다.** 5초 판단에 가장 맞는 카드 | 성능 |
| 14 | 이상 상세 (근거 포함 — detail + evidence 리스트) | 요약 | 위와 동일한 `anomalies` 배열의 전체 필드 | 무료 | **#13에서 뜬 항목의 근거를 읽는 용도.** 같은 배열을 두 카드로 나눠 그린 것 | 트래픽 (#13에 접기) |
| 15 | Correlation (추정 원인 — 확정 아님) | 요약 | 순수 로컬 `server/correlation.ts correlate` — anomalies 조합 규칙 4개 | 무료 | **판단선을 쓸 수 없다.** anomalies 2개 이상이 동시에 뜰 때 그 둘을 문장으로 이어 붙일 뿐, 새 정보가 없다 → 장식 | 삭제 |
| 16 | Incident Timeline (최근 30줄) | 요약 | 로컬 `server/correlation.ts buildTimeline` + SQLite (`pod_restarts`, `deploy_history`, `waf_history`) | 무료 | **판단선 없음.** 이미 화면에 있는 이벤트·이상·이력을 시간순으로 다시 나열. 사후 리포트용이지 감시용이 아니다 | 삭제 |
| 17 | 채점 지표 정렬 — `Insights 스캔량` | 성능 | 이 조회 1건의 `bytesScanned` (`server/logsinsights.ts` 통계) | 무료(표시만) | **이 카드를 몇 번 눌렀는지 = 얼마 썼는지.** 비용 자체를 1급 숫자로 올린 것 — 유지 | 성능 |
| 18 | 채점 지표 정렬 — `집계 구간` | 성능 | `server/window.ts resolveWindow` | 무료 | WindowBar가 이미 같은 값을 더 크게 표시 | 삭제(중복) |
| 19 | 채점 지표 정렬 — `관측 요청` (건) | 성능 | Insights `stats count(*) ... by path` 합계 (`server/grading.ts buildGradingQuery`) | 비쌈($ Insights) | **0건이면 로그 그룹 설정이 틀렸거나 트래픽이 아직 안 온 것.** 아래 표 전부의 신뢰도 판정 | 성능 |
| 20 | 채점 지표 정렬 — `채점 키` 개수 | 성능 | 상수 (`GRADING_APIS` × 2 + 2 = 8) | 무료 | **판단선 없음.** 항상 8 | 삭제 |
| 21 | 채점 지표 정렬 — `(user/product/stress) availability` 3줄 | 성능 | Insights over `ENV.appLogGroup`: `sum(status 2xx and latency_ms <= 5000)/count(*)` by path → `server/grading.ts` | 비쌈($ Insights) | **90% 아래로 떨어지면 그 API의 Pod/replica를 먼저 본다.** 채점기의 availability 키와 같은 정의 | 성능 |
| 22 | 채점 지표 정렬 — `(user/product/stress) performance` 3줄 | 성능 | 같은 쿼리, SLO 컬럼(user·product 200ms / stress 1000ms) | 비쌈($ Insights) | **availability는 100%인데 performance만 낮으면 스케일이 아니라 지연 문제 — 캐시·인덱스·limit을 본다.** | 성능 |
| 23 | 채점 지표 정렬 — `image download` | 성능 | 같은 쿼리, `path startsWith /images/` 분기 | 비쌈($ Insights) | **100% 미만이면 정적 자산 경로가 깨진 것.** 별도 채점 키 | 성능 |
| 24 | 채점 지표 정렬 — `Exception Handling` | 성능 | 같은 쿼리, 서비스 경로 밖 요청 중 `status = 404 or 403` 비율 | 비쌈($ Insights) | **100% 미만 = 미지정 경로가 404/403이 아닌 다른 코드로 나가고 있다 — 게이트웨이 설정을 고친다.** 도메인상 가장 중요한 한 줄 | 성능 |
| 25 | Pod 상태 분포 (Running/Pending/CrashLoop/OOM/Failed/기타) | 성능 | k8s `listNamespacedPod` → `summarizePodStatus` | 싸다(k8s) | **CrashLoop 또는 OOM이 1 이상이면 즉시 그 Pod 로그.** Running < total이면 롤아웃 중 | 성능 |
| 26 | Pod 개수 (최소/현재/최대) + source | 성능 | k8s `AutoscalingV2Api.listNamespacedHorizontalPodAutoscaler` → `server/resources.ts getPodScaling` | 싸다(k8s) | **current가 max에 붙어 있으면 HPA 상한이 병목 — max를 올린다.** `HPA 없음`이면 고정 replica라는 뜻 | 성능 |
| 27 | Node 개수 (최소/현재/최대) + `전체 노드 N개` | 성능 | AWS EKS `DescribeNodegroup`(`server/aws.ts discoverNodeGroupScaling`) + k8s `listNode` 개수 | 싸다(CW/k8s) | **채점 입력값 그 자체.** 노드가 채점 창 내내 몇 대였는지가 점수. current가 max면 노드 상한이 병목 | 성능 |
| 28 | Pod Health 테이블 (Pod·상태·Ready·재시작·CPU req/lim·Mem req/lim·IP·Node·로그버튼) | 성능 | k8s `listNamespacedPod` + SQLite 재시작 이력 | 싸다(k8s) | **`재시작 +n`이 붙은 행 → 그 Pod 로그. limit이 `-`인 행 → 사용률이 안 나오는 원인.** | 성능 |
| 29 | Pod 리소스 사용률 — CPU/Memory 시계열 차트 | 성능 | SQLite `metric_samples` (`res:pod:cpu:*`) — kube 폴링이 적재, `server/reshistory.ts loadResourceHistory` | 무료 (적재는 metrics-server) | **80%를 계속 넘으면 replica를 올린다. 스파이크 한 번이면 그냥 둔다.** 막대 대신 선인 이유 | 성능 |
| 30 | Pod 리소스 현재값 리스트 (`n core · nMi · CPU x% · Mem y%`) | 성능 | k8s `metrics.k8s.io getPodMetrics` (`server/resources.ts getPodResourceUsage`) | 비쌈(metrics-server) | **90% 빨강이면 limit 상향 또는 스케일아웃.** `limit 없음`이면 manifest를 고쳐야 비율이 나온다 | 성능 |
| 31 | Node 리소스 사용률 — CPU/Memory 시계열 차트 | 성능 | SQLite `metric_samples` (`res:node:*`) | 무료 | **노드 CPU가 80%대에서 평평하면 Pod를 늘려도 안 늘어난다 — 노드를 늘린다.** | 성능 |
| 32 | Node 리소스 현재값 리스트 (capacity 대비) | 성능 | k8s `metrics.k8s.io getNodeMetrics` + `listNode.status.allocatable` | 비쌈(metrics-server) | 위와 같은 판단. **차트와 완전 중복** — 차트 마지막 점이 곧 현재값 | 성능 (접기) |
| 33 | Target Group별 지표 테이블 (TG·경로·TRT·4XX·5XX) | 성능 | CloudWatch `AWS/ApplicationELB` dim `[LoadBalancer, TargetGroup]` × 3 metric · `fetchTargetGroupMetrics`, 경로는 ALB listener rule에서(`discoverAlb`) | 싸다(CW) | **어느 API가 느린지 가른다 — /v1/stress만 느리면 전체 스케일이 아니라 그 Deployment만 손댄다.** #1~#3의 전체 합을 쪼갠 것 | 성능 |
| 34 | TargetResponseTime 차트 (TG별 선) | 성능 | #33과 동일 배열의 `points` (재조회 없음) | 무료 | **언제부터 느려졌는지.** 표 옆에 붙는 게 맞다 | 성능 |
| 35 | 4XX·5XX 차트 (TG별 선) | 성능 | #33과 동일 배열 | 무료 | **5XX만 오르면 앱 장애, 4XX만 오르면 트래픽 성격 변화, 둘 다면 과부하.** | 성능 |
| 36 | Status Code 분포 막대 (2xx/3xx/4xx/5xx + %) | 성능 | `statusDist` = CloudWatch `HTTPCode_Target_{2,3,4,5}XX_Count`의 current값 조합 (`actions/dashboard.ts:199`) | 싸다(CW) | **5xx 비율이 1%를 넘으면 장애.** 다만 #2·#3 타일과 #33 표와 같은 숫자의 세 번째 표현 | 삭제(중복) |
| 37 | 상태코드 추이 차트 (2XX/3XX/4XX/5XX 선) | 성능 | `metrics.metrics`에서 `http2xx/3xx/4xx/5xx` 조회 | 무료 | **⚠ 지금 이 차트는 2XX·3XX 선을 절대 못 그린다.** `VISIBLE_METRICS`(`actions/dashboard.ts:114`)에 `http2xx`/`http3xx`가 없어 `metrics.metrics`에 실려오지 않는다 → `find()` undefined → points [] → 필터로 제거. 실제로는 4XX/5XX 2선짜리이고 #35와 중복 | 삭제 (또는 VISIBLE_METRICS 수정 후 #35와 통합) |
| 38 | Warning Event Board (시각·대상·사유·메시지·횟수·로그버튼, 전체) | 성능 | k8s `listNamespacedEvent` — #12와 **완전히 같은 배열** | 싸다(k8s) | **`FailedScheduling` → 노드 부족, `Unhealthy` → 프로브, `OOMKilling` → limit.** | 성능 |
| 39 | ActionTab — Deployment 조정 폼 (replicas / CPU limit / Mem limit + 변경 전후 비교 + 2단 확인) | 성능 | k8s `AppsV1Api.patchNamespacedDeployment` (JSON Patch) · `server/k8s.ts patchDeployment`+`validatePatch` | 싸다(k8s), 쓰기 | **#26/#30에서 상한에 붙었다고 판단했을 때 여기서 누른다.** 감시가 아니라 조치 도구 | 성능 (하단 고정) |
| 40 | ActionTab — 현재 Deployment 구성 (ready n/m, image, req/lim) | 성능 | k8s `listNamespacedDeployment` | 싸다(k8s) | **ready < replicas가 오래 지속되면 롤아웃 실패.** #28 Pod 테이블과 정보가 겹친다 | 삭제(중복) |
| 41 | ActionTab — 변경 이력 + 사후 검증 (verdict IMPROVED/DEGRADED/…) | 성능 | SQLite `deploy_history` + 2분 뒤 CloudWatch 재조회 비교 (`verifyActionAction`) | 무료 + 싸다(CW) | **DEGRADED가 뜨면 방금 바꾼 걸 되돌린다.** 2시간 안에 몇 번 안 쓰지만 되돌림 판단에는 필요 | 성능 (접기) |
| 42 | 샘플 요청 원본 테이블 (시각·IP·국가·메소드·경로·쿼리·UA·상태·판정·룰, 최신 300건 + ALL/BLOCK/ALLOW/COUNT 필터 + 검색) | 방화벽 | WAF `GetSampledRequests` (WebACL + 각 룰 metric마다 1회, MaxItems 500, 최근 15분) · `server/waf.ts listSampleRows` | **비쌈(WAF API)** — 룰 수만큼 호출, TTL 30s | **COUNT로 올린 규칙이 어떤 요청을 잡았는지 원문으로 확인 → BLOCK 승격 여부 결정.** 규칙 일생의 핵심 증거 | 트래픽 (COUNT 실측은 규칙 생성) |
| 43 | WAF 이상 요약 — `BlockedRequests: prev → cur/min (status)` | 방화벽 | `metrics.metrics` 에서 `wafBlocked` 재조회 — **#6과 완전히 같은 값** | 무료 | #6과 동일 | 삭제(중복) |
| 44 | WAF 이상 요약 — `AllowedRequests: prev → cur/min` | 방화벽 | #7과 같은 값 | 무료 | #7과 동일 | 삭제(중복) |
| 45 | WAF 이상 요약 — WebACL 이름·scope·규칙 수·WCU | 방화벽 | WAF `ListWebACLs` + `GetWebACL` · `server/waf.ts getAclInfo` | 싸다 (TTL 25s) | **WCU가 5000(기본 쿼터)에 가까우면 규칙을 더 못 넣는다.** 규칙 만들기 전에 봐야 하는 값 | 규칙 생성 |
| 46 | WAF 이상 요약 — 규칙 목록 (`이름 · p우선순위 · BLOCK/COUNT/ALLOW/GROUP`) | 방화벽 | 같은 `GetWebACL` 응답 | 싸다 | **내가 만든 규칙이 지금 COUNT인지 BLOCK인지 여기서만 확인된다.** 규칙 일생 화면의 상태 표시기 | 규칙 생성 |
| 47 | WAF 로그 통계 — Path (상위 20, `의심`/`헬스체크` 배지, 경로별 차단 건수) | 방화벽 | `ENV.wafLogGroup` 있으면 Insights `stats count(*) by httpRequest.uri, action`; 없으면 `GetSampledRequests` 집계 · `server/waf.ts buildHttpSummary` | **비쌈($ Insights ×5 쿼리 / TTL 120s)** 또는 비쌈(WAF API) | **`의심` 배지가 붙은 경로가 규칙생성 탭 `의심 경로` 규칙의 입력이다.** 서비스 경로 밖 + 30건↑ + 점유율 50%↑ | 트래픽 |
| 48 | WAF 로그 통계 — IP (상위 10, 점유율 30%↑ 강조) | 방화벽 | 같은 Insights 배치, `by httpRequest.clientIp, action` | 위 배치에 포함 | **⚠ 판단선을 쓰면 안 된다.** 이 환경은 채점 부하생성기가 단일 IP에서 때린다 — 집중 IP는 정상이다(`config.ts` 주석·`anomaly.ts:129`). 규칙 근거로 쓰면 채점 트래픽을 막는다 | 삭제 |
| 49 | WAF 로그 통계 — Method (상위 8) | 방화벽 | 같은 배치, `by httpRequest.httpMethod` | 위 배치에 포함 | **판단선 없음.** GET/POST 비율이 규칙을 바꾸지 않는다 | 삭제 |
| 50 | WAF 로그 통계 — QueryString 패턴 (상위 10) | 방화벽 | 같은 배치, `filter httpRequest.args != '' \| stats by args` | 위 배치에 포함 | **SQLi/base64 난독 쿼리가 보이면 규칙생성 탭 SQLi 규칙을 조립한다.** `anomaly.ts queryHasBase64Blob`의 입력 | 트래픽 |
| 51 | WAF 로그 통계 — Header 패턴 (상위 10) | 방화벽 | **샘플 모드에서만** 채워짐 (`GetSampledRequests`의 Request.Headers). Insights 모드에서는 항상 빈 배열 + 안내문 | 비쌈(WAF API) | **판단선 없음** — 그리고 WAF_LOG_GROUP을 설정한 정상 구성에서는 영구히 비어 있다 | 삭제 |
| 52 | Log Terminal (Pod/컨테이너 선택, tail 100~1000, Previous, 자동갱신 30s, 문제만, 시간 숨김, 검색, 색상 하이라이트, 스캔 바이트 표시) | 로그 | Insights `fields @timestamp, log \| filter kubernetes.pod_name=... \| limit tail` over `ENV.appLogGroup`; 실패/Previous면 k8s `readNamespacedPodLog` 폴백 · `server/podlogs.ts` | **비쌈($ Insights ×4 쿼리)** — 자동갱신 켜면 30초마다 반복 | **5XX가 떴을 때 원인 문자열을 찾는다.** 조치가 아니라 진단 | 트래픽 |
| 53 | 요청 로그 분석 — 경로별 (건수·avg/max latency·non-2xx) | 로그 | 같은 Insights 배치의 `stats count(*), avg(latency_ms), max(latency_ms), sum(status>=300) by path` | 위 배치에 포함 | **어느 경로가 느린지.** 하지만 #33 TG별 지표와 #21~#24 채점표가 이미 같은 질문에 답한다 | 삭제(중복) |
| 54 | 요청 로그 분석 — 200/201 이외 응답 목록 (최근 100) | 로그 | 같은 배치의 `filter status >= 300 \| display ... limit 100` | 위 배치에 포함 | **4xx가 미지정 경로 404인지 앱 오류인지 눈으로 가른다.** #57과 같은 질문 | 삭제(중복, #57로 통합) |
| 55 | 요청 로그 분석 — Error/Warn 로그 (최근 100) | 로그 | 같은 배치의 `filter log like /(?i)(error\|warn)/` | 위 배치에 포함 | **5XX의 원인 문자열.** #52 터미널의 `문제만` 체크박스와 같은 결과 | 삭제(중복) |
| 56 | Top Errors / Fingerprints (반복 상위 20, 횟수·최초/최종·Pod) | 로그 | 로컬 계산 `server/fingerprint.ts aggregateFingerprints` — #52가 가져온 줄에서 집계 | 무료 | **같은 예외가 ×5 이상 반복되면 `APPLICATION_FAILURE_SUSPECTED` 이상으로 승격된다(anomaly.ts:54).** #13의 입력이므로 값은 살아 있어야 함 | 트래픽 |
| 57 | 앱 요청 로그 (RequestLogPanel) — 시각·메소드·경로·상태·지연, ALL/2xx/3xx/4xx/5xx 필터 + 경로 검색 + 전체/조회/표시 3분리 + 스캔량 | 로그 | Insights `server/applogquery.ts buildRequestLogQuery` over `ENV.appLogGroup`, ROW_LIMIT 200 · `server/applog.ts fetchRequestLogRows` | **비쌈($ Insights)** — 마운트 시 + 필터 변경 시 (타이머 없음) | **4xx만 걸어서 미지정 경로 404 목록을 뽑는다 — 그게 곧 WAF 규칙 후보 경로.** 지금 화면에서 `트래픽` 탭의 핵심 도구 | 트래픽 |
| 58 | 점검 대상 — 단발 GET (주소·기대 코드·지금 점검·반복 5/10/30초) + 판정/상태/소요/리다이렉트 | 점검 | 대시보드 서버가 직접 `fetch` (`server/probe.ts probe`), UA `skills-dashboard/traffic-check` | 무료 (외부 1회 요청) | **CloudWatch가 비었을 때 "트래픽이 없는 것"과 "아직 게시 안 된 것"을 가른다.** 규칙 승격 직후 정상 경로가 아직 200인지 확인하는 용도로도 유일 | 규칙 생성 (롤백 판단용) |
| 59 | 최근 N회 — 정상 비율 / 평균 응답 / 최대 응답 / 실패 + 이력 테이블 (메모리, 최대 30회) | 점검 | #58 결과의 로컬 집계 (영속 없음) | 무료 | **정상 비율이 100%가 아니면 방금 올린 규칙이 정상 요청을 막고 있다 → 롤백.** | 규칙 생성 |
| 60 | 시험 — 규칙 JSON 편집기 (Rule 1개/배열/WebACL 전체/`{…}{…}` 이어붙이기/주석 허용) | 시험 | 로컬 파서 `server/rulejson.ts parseJsonDocuments` | 무료 | **map Out of scope: "로컬 WAF 시뮬레이터 유지·수리 — 동작하지 않았고 COUNT 실측이 더 정확".** 폐기 확정 | 삭제 |
| 61 | 시험 — 정상/악성 요청 세트 (행 추가·악성 예시·헤더/바디/국가/라벨 편집) | 시험 | `server/rulesim.ts defaultTestRequests / maliciousExampleRequests` (하드코딩) | 무료 | 위와 동일 | 삭제 |
| 62 | 시험 — 결과 (SAFE / FALSE_POSITIVE_RISK / INCONCLUSIVE + 통과·차단·카운트·정탐·미탐·판정불가 + 행별 결정 규칙/이유 + 근사 평가 경고) | 시험 | 로컬 평가기 `server/rulestatement.ts evalStatement` (+ rulemanaged/ruletransform/ruleinjection/rulerequest) | 무료 | 위와 동일. **`근사 평가` 경고가 스스로 "COUNT로 확인하라"고 말한다** — 그 COUNT가 정답이면 이 화면은 중간 단계일 뿐 | 삭제 |
| 63 | 규칙 조립 — `의심 경로` (RegexPatternSet 패턴 + 생성 CLI + Rule JSON + ARN 붙여넣기 + 근거 + 판단 기준) | 규칙생성 | `server/ruleassemble.ts assembleRule("path", httpSummary)` — 입력은 #47의 `byPath` | 조립 자체는 무료, 입력은 비쌈($ Insights) | **`의심` 배지 경로가 있으면 여기서 규칙을 만들어 COUNT로 올린다.** 규칙 일생의 1단계 | 규칙 생성 |
| 64 | 규칙 조립 — `의심 User-Agent` | 규칙생성 | `assembleRule("ua", …)` — 입력은 `httpSummary.byUa` + `server/threatsig.ts classifyUa` | 위와 동일 | **스캐너/정찰 툴 UA가 관측되면 UA 규칙.** ⚠ **`byUa`는 Insights 모드에서만 채워진다** — 샘플 0건이면 이 카드는 영구히 조립 불가(화면이 그렇게 경고함) | 규칙 생성 |
| 65 | 규칙 조립 — `SQL 인젝션` | 규칙생성 | `assembleRule("sqli", EMPTY_SUMMARY)` — **관측 무관, 고정 시그니처 세트** | 무료 (AWS 호출 0) | **관측이 없어도 미리 만들어 둘 수 있는 유일한 규칙.** 대회 시작 전에 뽑아두는 용도 | 규칙 생성 |
| 66 | Incident Context (Amazon Q용) — qPrompt/Markdown/JSON 3형식, 글자수 카운터, 복사, 다운로드 | 규칙생성(AiTab 중첩) | 로컬 조립 `server/incident.ts buildSnapshot/toQPrompt` — 캐시된 metrics·kube·fingerprints·최근 로그·검증 이력 + `server/gateway.ts` 게이트웨이 계약 문구, `server/mask.ts`로 마스킹 | 무료 (캐시만 읽음, 단 `getMetricsPanelAction`/`getKubePanelAction` 재호출) | **판단선 없음.** 2시간 감시 중 Amazon Q에 붙여넣을 시간이 없다. 사후 분석 도구 | 삭제 (또는 규칙 생성 최하단 접기) |
| 67 | 환경 설정 10행 (AWS_REGION / WAF_SCOPE / WAF_WEB_ACL_NAME / WAF_LOG_GROUP / ALB_NAME / EKS_CLUSTER_NAME / RDS_PROXY_NAME / APP_LOG_GROUP / TARGET_NAMESPACE / MAX_REPLICAS) — 각 행에 출처 배지(화면설정/.env/기본값), 자동 탐색 버튼, 해제 버튼 | 설정 | SQLite `settings` 테이블 (`server/settings.ts`), 자동 탐색은 `server/discover.ts` → AWS `ListWebACLs`/`DescribeLoadBalancers`/`ListClusters`/`DescribeDBProxies`/`DescribeLogGroups` | 무료 / 탐색 시 싸다 | **패널이 비면 이름이 틀린 것 — 여기서 자동 탐색으로 고른다.** 평소엔 볼 이유가 없다 | 설정 모달 |
| 68 | `.env 로 고정하기` (붙여넣을 텍스트 + 복사) | 설정 | `settingsView().envText` | 무료 | **판단선 없음** (대회 중엔 쓸 일 없음). 다만 3줄이라 남겨도 무해 | 설정 모달 |
| 69 | Annunciator — ALB / RDS / WAF / K8S / PODS / ANOM 6칸 (NORMAL/WARNING/CRITICAL/NODATA) | 크롬 | 로컬 계산 `DashboardClient.tsx buildSegments` — metrics·kube에서 파생 | 무료 | **빨간 칸이 하나라도 뜨면 그 도메인의 카드로 내려간다. 5초 판단 그 자체.** 지금 화면에서 목적에 가장 정확히 부합하는 유일한 요소 | 성능 (최상단) |
| 70 | Clock (HH:MM:SS) | 크롬 | 브라우저 `Date` | 무료 | **채점 창 시각 대조.** 2시간 트래픽 구간에서 "지금 몇 분 지났나"는 실제로 쓰인다 | 성능 |
| 71 | 사이드바 갱신 시각 3줄 (K8S / CW / WAF) + `구간` | 크롬 | `usePoll.lastUpdated` | 무료 | **한 줄이 멈추면 그 소스가 죽은 것.** 단 WindowBar의 `LastUpdated`와 중복 | 성능 (1줄로 통합) |
| 72 | 탭 배지 (요약=이상 n건 빨강 / 성능=Warning 이벤트 n건 노랑) | 크롬 | `metrics.anomalies.length`, `kube.events.length` | 무료 | 탭이 3장이 되면 배지의 의미가 달라진다. **Warning 이벤트 개수는 상시 0이 아니라 항상 몇 건씩 있어 배지가 늘 켜져 있다 → 신호가 아니다** | 삭제 (이상 배지만 유지) |
| 73 | WindowBar — 조회 기간 15/30/60/120/240m + 간격 1/5/10/60분 | 크롬 | 로컬 상태 → `server/window.ts resolveWindow`가 서버에서 검증·보정 | 무료 (단 **모든 Insights 비용의 곱셈 인자**) | **240m를 고르면 Insights 스캔이 4배가 된다.** 대회 중엔 60m 고정이 맞다 | 성능 (기본값 고정, 축소) |
| 74 | WindowBar — 갱신 주기 5~30초 + `⟳ 새로고침` + `LastUpdated` | 크롬 | 로컬 상태 | 무료 (곱셈 인자) | **채점 플랫폼 반영이 최대 1분 지연되므로 우리 화면은 그보다 빨라야 한다.** 다만 5초는 CloudWatch TTL 25s에 막혀 실효 없음 | 성능 |
| 75 | WindowBar — 해석된 창 경계 `MM.DD. HH:MM:SS ~ … · N초 버킷 · M개` | 크롬 | `ResolvedWindow` (서버가 버킷 경계로 내림) | 무료 | **로그와 화면을 대조할 때 필요.** #18·사이드바 `구간`과 3중 표시 | 성능 (1곳만) |

**합계 75행** (카드 단위로 세면 36장, 지표 단위로 세면 75개).
`삭제` 제안 **22행**, `설정 모달` 2행, `규칙 생성` 9행, `트래픽` 9행, `성능` 33행.

---

## 죽은 코드

### A. 티켓 전제 정정

| 항목 | 티켓 주장 | 실제 |
|---|---|---|
| `ui/ActionTab.tsx` (12.9KB) | "어디서도 import되지 않는다" | **틀렸다.** `PerformanceTab.tsx:13` import, `:559` 렌더. 살아 있고 실제로 클러스터를 패치한다 |
| `ui/IncidentTab.tsx` (5.3KB) | "`AiTab` 안에 중첩" | 맞다. `AiTab.tsx:7,236` |

### B. 지금 당장 도달 불가능한 것 (아무것도 안 지워도 죽어 있음)

| 대상 | 파일 | 크기 | 증거 |
|---|---|---|---|
| `getWafHistoryAction()` | `src/app/actions/dashboard.ts:344-350` | ~7줄 | `grep -rn "getWafHistoryAction" src/` → 정의 1건뿐, UI 호출 0 |
| `getDeploymentAction()` | `src/app/actions/dashboard.ts:455-464` | ~10줄 | 정의 1건뿐. `ActionTab`은 `patchDeploymentAction`/`verifyActionAction`만 씀 |
| `previewPatchAction()` | `src/app/actions/dashboard.ts:466-475` | ~10줄 | 정의 1건뿐. UI는 클라이언트에서 직접 before/after 표를 그림 |
| `WafPanel.history` 필드 | `actions/dashboard.ts:334` (`applyHistory()`) | — | **UI 어디에서도 `waf.data.history`를 렌더하지 않는다.** `grep -rn "history" src/app/dashboard/ui/*.tsx` → ActionTab의 deploy history, PerformanceTab의 resource history뿐 |
| `applyHistory()` + `waf_history` 테이블 | `src/lib/server/waf.ts:539-549`, `db.ts` | — | 유일한 소비처는 위 죽은 필드와 `correlation.ts buildTimeline`(#16, 삭제 제안) |
| `wafJson()` | `src/lib/server/waf.ts:48-57` | ~10줄 | `grep -rn "wafJson"` → 정의 1건뿐 |
| `insertWafHistory` / `getWafHistory` | `db.ts:170,191`, waf.ts:28에서 import만 | ~30줄 | import는 되지만 `waf.ts` 본문에서 호출되지 않음. **WAF 규칙을 실제로 적용/롤백하는 코드가 존재하지 않는다** |
| `UpdateWebACLCommand`, `CheckCapacityCommand` import | `src/lib/server/waf.ts:3,7` | 2줄 | import 후 미사용. 위와 같은 원인 |
| `fmtBytes()` | `src/lib/server/logsinsights.ts:128-133` | 6줄 | 호출처 0. **같은 함수가 3벌 존재한다** — `waf.ts:108`(private), `ui/shared.tsx:329`(UI용). logsinsights 것만 완전한 사구 |
| `probeTimeoutMs()` | `src/lib/server/probe.ts:40` | 3줄 | `TIMEOUT_MS`를 그대로 반환, 호출처 0 |

> `getDeploymentAction`/`previewPatchAction`을 지워도 `k8s.getDeployment`·`k8s.validatePatch`는
> 살아 있다 — 전자는 `verifyActionAction`(`dashboard.ts:571`)과 `validatePatch`(`k8s.ts:240`)가,
> 후자는 `patchDeployment`(`k8s.ts:272`)가 쓴다.

**죽은 타입** (`src/lib/types.ts`, 16.9KB 중):
`Confidence`, `RiskLevel`, `RegexSetSpec`, `WafRuleKind`, `WafCriteria`, `DeploymentContainerInfo`
— 6개는 **선언 외 참조가 0건**이다. 여기에 Sandbox 제거로 죽는
`RuleTestAction`, `RuleTestOutcome`, `RuleTestRow`, `RuleTestResult`, `TestRequest` 5개가 더해진다
(이 5개는 이미 다른 세션이 제거 중). 나머지 57개 타입은 실소비처가 있다.

**과잉 export** (지워도 되는 코드는 아니고 `export` 키워드만 떼면 되는 것):
`aws.ts`·`cloudwatch.ts`·`config.ts`·`db.ts`·`fingerprint.ts`·`gateway.ts`·`grading.ts`·
`logsinsights.ts`·`mask.ts`·`podlogs.ts`·`probe.ts`·`reshistory.ts`·`resources.ts`·
`ruleassemble.ts`·`settings.ts`·`threatsig.ts`·`waf.ts`·`waflogagg.ts`·`window.ts` 19개 모듈에
걸쳐 60개 이상. 대부분 "테스트에서만 쓰는 export"라 실제 문제는 아니다. **단 하나 예외는 `window.ts`**
— 아래 중복 `D13` 참조.

| `emptySampleNotes` 안내문 | `waf.ts:330` | — | 살아 있음(호출됨). 참고로만 |

> **중요한 함의**: 지도가 `규칙 생성` 탭에 요구하는 "COUNT → BLOCK 승격 → 롤백"의
> **승격·롤백 기계가 코드에 없다.** `UpdateWebACL`을 부르는 코드가 한 줄도 없고,
> `waf_history` 테이블·`applyHistory()`·`ApplyHistoryEntry` 타입은 그 기능이 있었거나
> 있을 예정이었던 흔적만 남은 상태다. `04` 티켓이 흐름을 정할 때 이건 "합치기"가 아니라
> **신규 구현**이다.

### C. `시험`(Sandbox) 탭을 지우면 같이 죽는 것

`SandboxTab`이 쓰는 서버 액션은 `getDefaultTestRequestsAction` /
`getMaliciousExampleRequestsAction` / `testRuleJsonAction` 셋이고 전부 `rulesim.ts`로 간다.
`rulesim.ts`의 import를 전이적으로 따라가면 **닫힌 부분 그래프**가 나온다 —
`ruleassemble.ts`(규칙생성 탭)는 이 중 **아무것도 쓰지 않는다**(`config.ts`, `threatsig.ts`만 씀).

```
SandboxTab.tsx
└ rulesim.ts ─┬ rulejson.ts
              ├ rulerequest.ts
              └ rulestatement.ts ─┬ ruleinjection.ts
                                  ├ rulemanaged.ts ─┬ ruleinjection.ts
                                  │                 └ rulerequest.ts
                                  ├ rulerequest.ts
                                  └ ruletransform.ts
```

| 파일 | 크기 | 판정 | 증거 |
|---|---|---|---|
| `src/app/dashboard/ui/SandboxTab.tsx` | 19.0KB | 죽음 | `DashboardClient.tsx:340`이 유일한 렌더 |
| `src/lib/server/rulesim.ts` | 17.2KB | 죽음 | `grep -rn "rulesim" src/` → `actions/dashboard.ts:19` 하나 |
| `src/lib/server/rulestatement.ts` | 24.4KB | 죽음 | import 하는 곳: `rulesim.ts:5`뿐 |
| `src/lib/server/rulemanaged.ts` | 11.2KB | 죽음 | import 하는 곳: `rulestatement.ts:3`뿐 |
| `src/lib/server/rulerequest.ts` | 7.2KB | 죽음 | `rulesim.ts:4`, `rulestatement.ts:4`, `rulemanaged.ts:3` — 전부 트리 내부 |
| `src/lib/server/ruleinjection.ts` | 3.5KB | 죽음 | `rulestatement.ts:2`, `rulemanaged.ts:2` — 트리 내부 |
| `src/lib/server/ruletransform.ts` | 7.0KB | 죽음 | `rulestatement.ts:5`가 유일 |
| `src/lib/server/rulejson.ts` | 4.6KB | 죽음 | `rulesim.ts:3`가 유일 |
| `scripts/rulesim.test.mjs` | 17.5KB | 죽음 | `rulesim.ts`만 import |
| `scripts/rulestatement.test.mjs` | 20.0KB | 죽음 | `rulestatement.ts`, `rulerequest.ts`만 import |
| `package.json` `test:rulesim`, `test:rulestatement` 스크립트 + `test` 체인 2항목 | — | 같이 제거 | `package.json:13,20-21` |
| `types.ts`: `RuleTestResult`, `RuleTestRow`, `TestRequest` (및 `AiTab`이 안 쓰는 `sandboxRuleJson` 필드) | — | 같이 제거 | 소비처가 Sandbox 경로뿐 |

**살아남는 것**: `ruleassemble.ts`(17.9KB)와 `threatsig.ts`(8.0KB)는 `규칙 생성` 탭이 쓰므로
남는다. `scripts/ruleassemble.test.mjs`(16.9KB)·`scripts/threatsig.test.mjs`(6.9KB)도 남는다.

**시험 탭 제거 소계: 소스 93.1KB + 테스트 37.5KB = 130.6KB**

### D. `요약` 탭 삭제 + 위 표의 `삭제` 판정을 반영하면 같이 죽는 것

| 대상 | 크기 | 조건 |
|---|---|---|
| `src/app/dashboard/ui/OverviewTab.tsx` | 11.0KB | 확정 (map Notes) |
| `src/lib/server/correlation.ts` | 4.5KB | #15 Correlation + #16 Timeline을 모두 지우면 소비처 0 (`actions/dashboard.ts:39`가 유일) |
| `src/lib/server/incident.ts` | 13.8KB | #66 Incident Context를 지우면 |
| `src/lib/server/gateway.ts` | 8.5KB | `incident.ts:22`가 **유일한** 소비처 — incident와 운명을 같이 함 |
| `scripts/gateway.test.mjs` | 11.6KB | `gateway.ts` + `incident.ts`만 import |
| `src/app/dashboard/ui/IncidentTab.tsx` | 5.3KB | #66과 함께 |
| `types.ts`: `CorrelationResult`, `TimelineEntry`, `IncidentContextResult`, `QSection` | — | 위와 함께 |

**요약/Incident 계열 소계: 소스 43.1KB + 테스트 11.6KB = 54.7KB**

### E. 위험도 낮은 나머지

- `src/lib/server/probe.ts`(5.4KB) + `ui/CheckTab.tsx`(10.9KB): `점검` 탭이 사라져도
  #58·#59는 `규칙 생성`의 롤백 판단에 쓸모가 있어 **살리는 쪽을 제안**했다.
  버리기로 하면 `scripts/probe.test.mjs`(2.6KB)도 같이 간다.
- `HttpSummary.detailedStatus` — 두 경로 모두 항상 `null`. 렌더도 안 됨. 필드째 제거 가능.
- `HttpSummary.byUa` — 서버는 채우지만 **UI 어디에서도 표시하지 않는다**
  (`grep -rn "byUa" src/app/dashboard/ui/` → 0건). `anomaly.ts`·`ruleassemble.ts`·`incident.ts`가
  소비하므로 필드는 살아야 하지만, "WAF 로그 통계"에 UA 목록이 없는 건 실수로 보인다.
- `requestCount` 메트릭 — `fetchCoreMetrics`가 CloudWatch에서 `AWS/ApplicationELB RequestCount`를
  받아오지만 `VISIBLE_METRICS`에 없어 **화면에 절대 나오지 않는다**. 쿼리에서 빼면 CW 호출이 줄고,
  아니면 타일로 노출해야 한다(총 요청 수는 5초 판단에 쓸모 있다).
- `http2xx` / `http3xx` — 위와 같은 이유로 #37 차트가 2XX·3XX 선을 못 그린다(표의 #37 참조).

### 총계

| 묶음 | 소스 | 테스트 | 소계 |
|---|---|---|---|
| C. 시험 탭 트리 (이미 다른 세션이 실행 중) | 93.1KB | 37.5KB | **130.6KB** |
| D. 요약 탭 + Incident/Correlation/gateway 계열 | 43.1KB | 11.6KB | **54.7KB** |
| B. 지금도 도달 불가능한 함수·필드·액션 | ~4KB | — | **~4KB** |
| E. 죽은 타입 11개 + 사구 함수 3개 | ~2KB | — | **~2KB** |
| **합계** | **~142KB** | **~49KB** | **≈ 191KB** |

현재 `src/` + `scripts/`의 TS/TSX/MJS 총량 대비 **대략 3분의 1**이다.
(`점검` 탭까지 버리기로 하면 `probe.ts` 5.4KB + `CheckTab.tsx` 10.9KB + 테스트 2.6KB = 18.9KB 추가.)

---

## 중복

같은 숫자가 두 군데 이상 있거나, 두 카드가 같은 질문에 답하는 것. **화면이 어수선한 진짜 원인은
카드 수가 아니라 이 목록이다.**

| # | 무엇이 중복인가 | 어디에 | 왜 문제인가 |
|---|---|---|---|
| **D1** | **Pod 건강** — 같은 `kube.pods` 배열을 4번 그린다 | 요약 `Pod Health`(#9·#10·#11), 성능 `Pod 상태 분포`(#25), 성능 `Pod Health 테이블`(#28), 성능 `현재 Deployment 구성`(#40) | 네 카드가 같은 폴링 결과의 다른 잘림. 운영자는 "정상 Pod 3/3"을 세 번 읽고 넘어간다 |
| **D2** | **WAF 차단 건수 — 값이 4곳, 출처가 2가지** | #6 `wafBlocked`(CloudWatch), #43 같은 값 재표시, #47 `blockedTotal`(WAF 로그 Insights 전수), #24 GradingCard notes의 `wafBlocked` | **두 숫자는 원리적으로 다르다** — CloudWatch는 집계 지연 + `Rule=ALL` 차원, Insights는 로그 전수. `WafTab.tsx:250`의 `SourceNote`가 "값이 다르게 보일 수 있습니다"라고 스스로 실토한다. 한 화면에 둘 다 두면 어느 쪽을 믿을지 매번 판단해야 한다 |
| **D3** | **4XX/5XX — 같은 CloudWatch 메트릭을 5가지 형태로** | #2·#3 타일, #33 TG 테이블, #35 TG별 차트, #36 Status Code 막대, #37 상태코드 추이 차트 | 전부 `HTTPCode_Target_{4,5}XX_Count`. #36과 #37은 #33/#35의 완전한 부분집합이고, #37은 그나마 2XX/3XX가 안 나와 반쪽이다 |
| **D4** | **Warning 이벤트** — 같은 배열을 잘라서 두 번 | 요약 `Warning Events` 상위 8건(#12), 성능 `Warning Event Board` 전체(#38) | 같은 `listNamespacedEvent` 결과. 상세 모달까지 같은 컴포넌트(`WarningEventDetailModal`) |
| **D5** | **이상(Anomaly) 배열을 4개 카드로** | #13 목록, #14 근거 상세, #15 Correlation, #16 Timeline | `detectAnomalies()` 하나의 반환값을 제목만/근거까지/문장으로 이어서/시간순으로 — 네 번 그린다. 판단은 #13 한 번으로 끝난다 |
| **D6** | **비-2xx 응답 목록** — 같은 앱 로그, 별개의 Insights 쿼리 2개 | #54 `요청 로그 분석 non-2xx`(선택 Pod 한정), #57 `앱 요청 로그` 4xx/5xx 필터(전체) | **같은 로그 그룹을 두 번 스캔해 돈을 두 번 낸다.** #57이 상위 집합 |
| **D7** | **Error/Warn 로그 줄** | #55 카드, #52 터미널의 `문제만` 체크박스 | 같은 로그를 서버 쿼리와 브라우저 필터로 두 번. #52의 체크박스가 더 빠르고 공짜 |
| **D8** | **경로별 통계 — 로그 그룹이 다른 3개 목록** | #47 WAF 로그 Path, #53 앱 로그 경로별, #21~#24 채점표의 path 집계 | 셋 다 "어느 경로에 뭐가 오나". WAF 로그는 차단 전 관점, 앱 로그는 차단 후 관점 — **구분이 필요한 건 맞지만 세 카드로 나눌 필요는 없다** |
| **D9** | **노드 대수** — 4곳 | #27 `Node 개수` current, 그 아래 `전체 노드 N개`(kube.nodesTotal), #8 `노드 n/m Ready`, #69 Annunciator `K8S` | `getNodeScaling`의 current는 EKS Managed Nodegroup의 `desiredSize`, `nodesTotal`은 k8s가 세는 실제 노드 — **Karpenter 노드가 있으면 두 값이 다르다**(map의 `02` 결론과 직결). 지금은 한 카드 안에서 두 정의가 나란히 있고 어느 쪽이 채점 기준인지 화면이 말하지 않는다 |
| **D10** | **갱신 시각 / 조회 구간** | #71 사이드바 4줄, #74 WindowBar `LastUpdated`, #75 창 경계, #18 GradingCard `집계 구간`, 그리고 거의 모든 `Card`의 `basis="조회 구간 …"` | 같은 두 값이 한 화면에 6번 이상 |
| **D11** | **리소스 사용률 현재값** | #29/#31 차트의 마지막 점, #30/#32 `현재값` 리스트 | 차트가 이미 현재값을 그린다. 리스트가 추가로 주는 건 `n core · nMi` 원시 수치와 `limit 없음` 표시뿐 |
| **D12** | **Incident Timeline vs 변경 이력** | #16 Timeline이 `deploy_history`·`waf_history`를 읽어 다시 나열, #41 `변경 이력 + 사후 검증`이 같은 테이블을 읽음 | 같은 SQLite 테이블 두 번 |
| **D13** | **창 선택지 목록과 간격 계산이 서버·클라이언트에 2벌** | `server/window.ts`의 `WINDOW_CHOICES_MIN = [15,30,60,120,240]` + `validIntervals()` ↔ `ui/WindowBar.tsx:16`의 `WINDOW_CHOICES` + `:23`의 `intervalsFor()` | **테스트가 검증하는 쪽(`window.ts`)은 UI가 안 쓰고, UI가 쓰는 쪽(`WindowBar.tsx`)은 테스트가 없다.** `WindowBar.tsx:20` 주석이 "Mirrors server/window.ts"라고 자백한다. 진실의 원천이 둘 |
| **D14** | **`fmtBytes` 함수가 3벌** | `server/logsinsights.ts:128`(호출처 0), `server/waf.ts:108`(private), `ui/shared.tsx:329` | 세 벌이 표기 규칙이 조금씩 다르다 (`GB` vs ` GB`, 소수 자릿수) — 같은 스캔량이 카드마다 다르게 보인다 |

---

## 추천 판정 요약

### `성능` — 2시간 띄워두는 화면 (위에서부터)

**Above the fold (스크롤 없이, 5초 판단):**

1. **Annunciator 6칸** (#69) — ALB/RDS/WAF/K8S/PODS/ANOM.
   유일하게 "이상 유무"를 색 하나로 답한다. 이미 만들어져 있고 헤더에 있다. **크게 키운다.**
2. **채점 키 8줄** (#21~#24) — availability ×3 / performance ×3 / image / Exception Handling.
   **화면이 존재하는 이유.** 점수를 계산하지 않고 채점기 입력값만 센다는 원칙과도 맞는다.
   비용 때문에 지금은 수동 조회지만, `성능` 탭 최상단이면 **자동 1분 주기로 올릴 값**을 `05`에서 정해야 한다.
3. **TargetResponseTime / 4XX / 5XX 3타일** (#1·#2·#3) — 스파크라인 포함.
   #4 RDS Client Conn을 네 번째로. (#5 RDS DB Conn, #7 WAF Allowed는 접거나 삭제)
4. **Node 개수 (min/현재/max)** (#27) — **채점 입력값.** 단, `desiredSize`(EKS)와
   `nodesTotal`(k8s)이 다를 수 있다는 걸 화면이 말해야 한다(D9).
5. **Pod 개수 (min/현재/max)** (#26) — HPA 상한에 붙었는지.
6. **이상(Anomaly) 목록** (#13) — 근거는 클릭해서 펼친다(#14를 접어 넣는다).

**Below the fold (문제가 있을 때 내려가는 곳):**

7. Pod 상태 분포 + Pod Health 테이블 (#25 + #28) — 두 개를 하나로 합친다(D1)
8. Pod / Node 리소스 사용률 차트 (#29·#31), 현재값은 차트 안으로 접는다(D11)
9. Target Group별 지표 + TRT 차트 + 4XX/5XX 차트 (#33·#34·#35) — #36·#37은 버린다(D3)
10. Warning Event Board (#38)
11. **ActionTab — Deployment 조정 + 변경 이력** (#39·#41) — 화면 맨 아래 고정.
    감시가 아니라 조치라 위로 올라오면 안 된다. #40(현재 Deployment 구성)은 #28과 합친다

**크롬**: Clock(#70) + 갱신 시각 1줄(#71을 통합) + WindowBar 축소(#73·#74, 60m/1m 기본 고정).

### `트래픽` — 지금 뭐가 들어오고 있나

WAF 로그 통계 Path(#47) · QueryString(#50) → 앱 요청 로그(#57, 4xx 필터가 기본) →
Log Terminal(#52) + Fingerprints(#56) → WAF Blocked/Allowed 추이(#6·#7).
**#48 IP·#49 Method·#51 Header는 버린다** — 앞의 둘은 채점 부하생성기 때문에 판단선을 쓸 수 없고,
Header는 정상 구성(WAF_LOG_GROUP 설정)에서 영구히 비어 있다.
#53·#54·#55는 #57·#52와 중복이라 버린다(D6·D7).

### `규칙 생성` — 한 규칙의 일생

규칙 조립 3종(#63·#64·#65) → WebACL 규칙 목록 + WCU(#45·#46, **지금 COUNT인지 BLOCK인지 보여주는
유일한 곳**) → 샘플 요청 원본(#42, COUNT 실측 증거) → 정상 경로 프로브(#58·#59, 롤백 판단).
**승격·롤백 버튼은 아직 코드에 없다(죽은 코드 B 참조) — `04`에서 신규 구현으로 잡아야 한다.**

### `설정 모달`

#67 환경 설정 10행 + #68 `.env 고정`. 톱니로 뺀다.

### 삭제

`요약` 탭 전체(#9·#12·#14·#15·#16), `시험` 탭 전체(#60·#61·#62), Incident Context(#66),
Correlation·Timeline, Status Code 분포·상태코드 추이(#36·#37), WAF 이상 요약의 메트릭 재표시(#43·#44),
WAF 로그 통계 IP/Method/Header(#48·#49·#51), 현재 Deployment 구성(#40),
요청 로그 분석 3분할(#53·#54·#55), RDS DB Conn(#5), 채점 키 개수·집계 구간(#18·#20), 탭 배지(#72).
