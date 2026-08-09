# skills-dashboard

국가기능경기대회 클라우드컴퓨팅 트러블슈팅용 통합 대시보드.
CloudWatch(ALB/RDS Proxy/WAF) 메트릭, WAFv2 규칙 추천·시뮬레이션·적용·롤백,
Kubernetes Pod/Event/로그 추적, Deployment 리소스 조정, 사후 검증,
Amazon Q용 Incident Context 생성을 하나의 화면에서 수행한다.

대상 환경 (task-3): `skills-eks`(ap-northeast-2) · `skills-alb`(LBC Ingress) ·
`skills-db-proxy`(MySQL 8.0) · `skills-waf`(CLOUDFRONT scope, us-east-1) ·
`skills-cdn` · namespace `default`의 `user`/`product`/`stress` Deployment.

로컬 실행 전용 — 대시보드 자체에는 접속 인증이 없다. 클러스터/AWS 인증은
로컬에 이미 있는 kubeconfig·AWS 자격증명을 그대로 사용한다.

---

## 빠른 시작

### 1. 사전 준비

- [mise](https://mise.jdx.dev) 설치 (Node 20 버전은 `mise.toml`이 자동으로 맞춰줌)
- AWS 자격증명 설정: `aws configure` 또는 `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` 환경변수
- Kubernetes 클러스터 접근 가능한 `~/.kube/config` (`aws eks update-kubeconfig --name skills-eks --region ap-northeast-2`)

### 2. 설치 및 설정

```bash
git clone https://github.com/rladnwls122/skills_dashboard-wooj.git
cd skills_dashboard-wooj
mise run install          # pnpm install (better-sqlite3 네이티브 빌드 포함)
cp .env.example .env       # 필요시 값 수정 (리소스 이름을 비우면 자동 탐색)
```

### 3. 실행

```bash
mise run dev               # http://localhost:3100/dashboard (개발 모드)
# 또는
mise run build && mise run start   # production 빌드로 실행
```

브라우저에서 `http://localhost:3100/dashboard` 접속. 별도 로그인 없음.

### 4. 종료

터미널에서 `Ctrl+C`. (백그라운드 실행 시 `mise run start` PID를 kill)

---

## 화면 사용법

좌측 상단 배너 6칸(ALB/RDS/WAF/K8S/PODS/ANOM)은 서브시스템별 실시간 상태등 —
빨간색이 점멸하면 해당 영역에 문제가 있다는 뜻. 탭은 좌측 레일(모바일은 상단
가로 스크롤)에서 전환한다.

1. **요약 (Overview)** — 핵심 메트릭 카드, Pod 상태, Warning 이벤트, 감지된
   이상 목록을 한 화면에 모아 보여줌. 장애 발생 시 가장 먼저 보는 탭.
2. **조사 (Investigation)** — Pod 상세 상태·리소스 사용률, Node 리소스 사용률,
   Pod/Node 개수(min/current/max), Target Group별 지표, Warning Event Board,
   Pod 로그 터미널(검색·Previous 로그·자동갱신 지원), 요청 로그 분석
   (latency/비정상 응답/Error·Warn), HTTP Path·상태코드 분포, Incident
   Timeline이 모여 있다. Overview나 Warning Event Board에서 "보기"/"로그"
   버튼을 누르면 해당 Pod 로그로 바로 이동한다.
3. **방화벽 (WAF)** — WAF 이상 요약, 경로/쿼리/헤더/메소드별 통계, 규칙 추천
   목록. 규칙 카드에서 **시뮬레이션 → COUNT 적용(승인 필요) → BLOCK 승격
   (COUNT 검증 이력 필요)** 순서로만 진행된다. 적용 이력에서 롤백 가능.
4. **조치 (Action)** — Deployment의 Replicas/CPU/Memory Limit을 변경. 값을
   입력하면 변경 전/후 비교표가 뜨고, 승인 버튼을 눌러야 실제로 적용된다.
   적용 후 약 2분 뒤 자동으로(또는 "지금 검증" 버튼으로) 효과를 검증해
   IMPROVED/NO_CHANGE/DEGRADED/INCONCLUSIVE 중 하나로 표시.
5. **보고 (Incident)** — "Generate Incident Context" 버튼으로 현재까지 수집된
   모든 정보(메트릭/로그/이벤트/조치이력)를 마스킹된 Markdown/JSON으로 생성.
   Amazon Q나 팀원에게 상황을 공유할 때 복사/다운로드해서 사용.

**원칙**: 자동 차단·자동 정책 변경 없음. WAF/Deployment 변경은 항상 사람의
명시적 승인을 거친다.

---

## 수집 항목

- Pod 로그 기반 latency / 200·201 이외 응답 / Error·Warn 로그
- WAF 로그 통계: 헤더/경로/쿼리스트링/메소드별, 차단 요청
- Target Group별 TargetResponseTime · 4XX · 5XX (리스너 규칙으로 경로 라벨링)
- Pod/Node 리소스 사용률 CPU·Memory (metrics-server 필요)
- Pod 개수(HPA min/current/max) · Node 개수(EKS Managed Nodegroup min/current/max)
- Pod 상태 분포 (Running/Pending/CrashLoopBackOff/OOMKilled/Failed/기타)
- RDS Proxy ClientConnections/DatabaseConnections
- WAF BlockedRequests/AllowedRequests

---

## 환경 변수

`.env.example` 참고. 주요 항목:

| 변수 | 기본값 | 설명 |
|---|---|---|
| `AWS_REGION` | `ap-northeast-2` | 워크로드 리전 |
| `WAF_SCOPE` | `CLOUDFRONT` | `CLOUDFRONT`면 WAF API/메트릭은 자동으로 us-east-1 사용 |
| `WAF_WEB_ACL_NAME` | `skills-waf` | |
| `ALB_NAME` | `skills-alb` | 비우면 첫 ALB 자동 탐색 |
| `RDS_PROXY_NAME` | `skills-db-proxy` | |
| `EKS_CLUSTER_NAME` | `skills-eks` | Nodegroup min/max 조회용 |
| `TARGET_NAMESPACE` | `default` | |
| `MAX_REPLICAS` | `20` | Deployment 패치 시 허용 상한 |
| `DB_PATH` | `./data/dashboard.db` | 이력 SQLite 경로 |

리소스 이름을 비우면 자동 탐색 (ALB는 LBC가 TargetGroup 이름을 자동 생성하므로
자동 탐색이 기본 경로).

## 필요 권한

- AWS IAM: `cloudwatch:GetMetricData`, `elasticloadbalancing:Describe*`,
  `wafv2:Get*`/`List*`/`UpdateWebACL`/`CheckCapacity`, `rds:Describe*`(선택),
  `eks:ListNodegroups`/`DescribeNodegroup`, (선택) `logs:StartQuery`/`GetQueryResults`.
- Kubernetes: 로컬 kubeconfig 사용자에 `pods`/`pods/log`/`events`/`deployments`/
  `deployments/scale`/`nodes`/`horizontalpodautoscalers` read, `deployments` patch 권한.
  Pod/Node 리소스 사용률은 클러스터에 **metrics-server**가 설치돼 있어야 값이 채워짐
  (task-3는 eksctl addon으로 포함).

`k8s-dashboard-rbac.yaml` 은 스펙 산출물 요구사항 충족용 참고 매니페스트로만
보관 — 실제 적용 대상 아님 (로컬 kubeconfig 권한을 그대로 사용하므로 불필요).

---

## 문제 해결

- **"ALB not found"** — `.env`의 `ALB_NAME` 확인, 또는 해당 리전에 ALB가 실제
  존재하는지 확인.
- **"WebACL not found"** — `WAF_SCOPE`/`WAF_WEB_ACL_NAME` 확인. CLOUDFRONT
  scope인데 리전을 us-east-1로 착각하고 다른 값 넣지 않았는지 체크(자동 처리됨,
  수동 설정 불필요).
- **Kubernetes 조회 실패 (HTTP protocol is not allowed 등)** — `~/.kube/config`
  컨텍스트가 올바른 클러스터를 가리키는지 `kubectl config current-context`로 확인.
- **Pod/Node 리소스 사용률이 항상 비어있음** — 클러스터에 metrics-server가
  설치되어 있는지 `kubectl top nodes`로 확인.

---

## 프로젝트 구조

```
src/app/actions/dashboard.ts   # 모든 서버 액션 (AWS/K8s 접근은 전부 서버)
src/app/dashboard/page.tsx     # 대시보드 페이지
src/app/dashboard/ui/          # 클라이언트 컴포넌트 (탭 5개)
src/lib/server/                # server-only 모듈
  config.ts     # env + 임계치 설정 객체
  aws.ts        # SDK 클라이언트, ALB/TG/리스너규칙 자동 탐색, EKS 노드그룹 스케일링
  cloudwatch.ts # GetMetricData, current/previous/delta/%/status, TG별 지표
  waf.ts        # 샘플 수집, HTTP 요약, 규칙 추천/시뮬/적용/롤백
  k8s.ts        # Pod/Event/Deployment/로그, JSON Patch + 검증
  resources.ts  # Pod/Node 리소스 사용률(metrics.k8s.io), HPA/Nodegroup 스케일링, 상태 분포
  requestlog.ts # Gin 액세스로그 파싱 → latency/상태코드/에러·경고
  anomaly.ts    # 이상 감지 (오탐 방지 규칙 포함)
  correlation.ts# 상관 분석 + 타임라인
  fingerprint.ts# 오류 정규화·핑거프린트
  incident.ts   # 스냅샷 + Markdown/JSON 컨텍스트
  mask.ts       # 민감정보 마스킹
  db.ts         # SQLite (이력/baseline/스냅샷)
  cache.ts      # TTL + in-flight dedup 캐시
k8s-dashboard-rbac.yaml        # 스펙 필수 산출물 (참고용, 미적용)
```

## 동작 원칙

- WAF 변경은 항상 추천 → 시뮬레이션 → 승인 → COUNT 적용 → 검증 → (재승인 후) BLOCK.
  BLOCK 전환은 동일 규칙의 COUNT 성공 이력이 서버에서 확인돼야 허용.
- 적용 전 WebACL 규칙 스냅샷을 SQLite에 저장 — 언제든 롤백 가능.
- 자동 차단·자동 정책 변경 없음. Deployment 패치도 명시적 승인 후에만 실행.
- 단일 메트릭만으로 CRITICAL 판정 없음. `/healthcheck` 등 헬스체크 경로는
  이상 판정에서 저순위 처리.
- 폴링 계층: K8s 3초 / 로그 5초(자동갱신 시) / CloudWatch·WAF 30초.
  서버 캐시가 in-flight 중복과 과도한 API 호출을 차단.
- 서브시스템 장애는 영역별로 격리 — 한 곳이 죽어도 화면 전체는 유지.

## 스택

Next.js 15 App Router · React 19 · TypeScript strict · Tailwind CSS v4 ·
AWS SDK v3 (cloudwatch, wafv2, elbv2, cloudwatch-logs, eks) · @kubernetes/client-node 1.x ·
better-sqlite3 (이력·baseline 저장) · pnpm · mise
