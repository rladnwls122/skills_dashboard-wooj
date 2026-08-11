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
mise run env               # task-3 런북 값(skills-eks/skills-alb/skills-db-proxy/
                            # skills-waf 등)으로 .env 생성 + AWS/kubeconfig 상태 점검
```

`mise run env`는 `scripts/generate-env.sh`를 실행 — task-3 런북에 고정된 리소스
이름을 자동으로 채우고, AWS 자격증명/kubeconfig 컨텍스트가 잡혀 있는지
`aws sts get-caller-identity`/`kubectl config current-context`로 확인해서
알려준다. **비밀키는 파일에 쓰지 않음** — 이미 설정된 AWS CLI 체인을 그대로 씀.
직접 값을 바꾸고 싶으면 생성된 `.env`를 열어 수정하면 된다 (재실행 시 기존
파일은 타임스탬프 백업 후 덮어씀).

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
   Pod 로그 터미널(검색·Previous 로그·자동갱신, **"문제만"**으로 Error/Warn
   라인만 필터, **"시간 숨김"**으로 타임스탬프 접기), 요청 로그 분석
   (latency/비정상 응답/Error·Warn), HTTP Path·상태코드 분포(경로 집중은 "의심"
   배지), Incident Timeline이 모여 있다. Overview나 Warning Event Board에서
   "보기"/"로그" 버튼을 누르면 해당 Pod 로그로 바로 이동한다.
3. **방화벽 (WAF)** — WAF 이상 요약, 경로/IP/쿼리/헤더/메소드별 통계(IP 점유율
   30%↑ 강조), **샘플 요청 원본 테이블**(개별 요청을 행 단위로 — IP/경로/UA/판정,
   BLOCK/ALLOW/COUNT 필터·검색). 규칙 추천 카드에서 **시뮬레이션 → COUNT
   적용(승인 필요) → BLOCK 승격(COUNT 검증 이력 필요)** 순서로만 진행된다.
   각 추천 카드의 **"룰 JSON"** 버튼으로 WAF 콘솔에 그대로 붙여넣을 수 있는
   Rule JSON을 보고 복사할 수 있고, **"Q 프롬프트 복사"** 버튼은 현재 WebACL 룰
   JSON + 추천 룰 JSON + 시뮬 결과 + 검토 질문을 한 덩어리로 만들어 클립보드에
   넣어준다 — Amazon Q 채팅에 그대로 붙여넣으면 됨. 적용 이력에서 롤백 가능.
4. **조치 (Action)** — Deployment의 Replicas/CPU/Memory Limit을 변경. 값을
   입력하면 변경 전/후 비교표가 뜨고, 승인 버튼을 눌러야 실제로 적용된다.
   적용 후 약 2분 뒤 자동으로(또는 "지금 검증" 버튼으로) 효과를 검증해
   IMPROVED/NO_CHANGE/DEGRADED/INCONCLUSIVE 중 하나로 표시.
5. **보고 (Incident)** — "Generate Incident Context" 버튼으로 현재까지 수집된
   모든 정보(메트릭/로그/이벤트/조치이력)를 마스킹해서 세 가지 형식으로 생성.
   Amazon Q나 팀원에게 상황을 공유할 때 복사/다운로드해서 사용.
   - **Amazon Q 프롬프트** (기본값) — Q의 프롬프트 입력 한도인 10,000자에 맞춰
     `[A]`~`[J]` 카테고리로 나눠 담는다. 맨 앞 `[A]`가 게이트웨이 기대 동작
     (아래 참고)이라 Q가 404/403 증가를 장애로 오판하지 않는다. 규칙 JSON
     본문·Pod 로그 원문·전체 타임라인은 빠지며, 잘린 항목은 말미에 이름으로
     남는다. 글자 수는 셀렉트 옆에 표시되고 한도를 넘으면 빨간색.
   - **Markdown (전체)** — 위 항목을 포함한 전체 보고서.
   - **JSON** — 스냅샷 원본.

   **게이트웨이 기대 동작**: 이 환경의 게이트웨이는 미지정 경로 → `404`
   (엔드포인트가 없는 것처럼 보이게 해 스캐닝 차단), 지정 경로 + 정상 요청 →
   `200`, 지정 경로 + 비정상 요청(SQLi/XSS/Body 포맷 오류/차단 IP/rate limit
   초과) → `403`으로 응답한다. 따라서 404·403 자체는 장애가 아니라 정책이
   동작한 결과이며, **5XX와 "미지정 경로가 통과된 것"만이 계약 위반**이다.
   보고서는 관측된 트래픽을 이 기준에 대고 `[정상]`/`[편차]`로 갈라 적고,
   WAF 추천 규칙마다 Block 시 돌려줄 응답 코드(미지정 경로면 CustomResponse
   404)를 함께 제안한다.
6. **시험 (Sandbox)** — WAF 규칙을 적용 전에 **로컬에서만** 돌려보는 탭.
   AWS로 아무것도 보내지 않고 WebACL도 건드리지 않는다. 자세한 내용은 아래
   "규칙 시험 샌드박스" 참고.

**원칙**: 자동 차단·자동 정책 변경 없음. WAF/Deployment 변경은 항상 사람의
명시적 승인을 거친다.

### 규칙 시험 샌드박스 (시험 탭)

붙여넣은 WAF 규칙을 합성 요청 목록에 대해 로컬에서 평가한다. 네트워크 호출이
없으므로 AWS 자격증명 없이도 동작한다.

**붙여넣을 수 있는 형태** — 넷 다 그대로 인식한다.

- WAFv2 Rule 하나 (`{"Name":…,"Statement":…,"Action":…}`)
- Rule 배열 (`[{…},{…}]`)
- WebACL JSON 전체 (`aws wafv2 get-web-acl` 출력 그대로, `WebACL` 래퍼 포함 가능)
- Statement 본문만 (`{"ByteMatchStatement":{…}}`)
- 위 형태를 **여러 개 그냥 이어붙인 것** — 콘솔에서 규칙을 하나씩 복사해
  `{…}{…}` 로 붙여넣어도 되고, 사이에 쉼표가 있어도 된다.
  손으로 남긴 주석(`//`, `/* */`)과 마지막 쉼표도 허용한다.

규칙이 여러 개면 **Priority 오름차순**으로 평가하고, Block/Allow/CAPTCHA/Challenge
에서 멈춘다(Count는 계속 진행). 결과 표의 "결정 규칙" 열이 어느 규칙이 그 요청을
결정했는지 보여주고, 앞선 규칙의 `RuleLabels`는 뒤 규칙의 `LabelMatchStatement`가
그대로 본다.

**요청 편집** — 각 행 왼쪽 `▸`를 누르면 헤더(한 줄에 `이름: 값`), 바디, 국가 코드,
라벨을 넣을 수 있다. 요청에 없는 헤더는 "판정 불가"가 아니라 **미매칭**으로
평가된다. Cookie 헤더는 `Cookies` 필드로, 바디는 `Body`/`JsonBody` 필드로 자동
파싱된다.

**IP 세트·정규식 세트 참조** — ARN만으로는 내용을 알 수 없으므로, 붙여넣는 JSON
최상위에 내용을 같이 넣으면 평가된다 (세트 이름이나 ARN 어느 쪽으로 키를 잡아도 됨):

```json
{
  "IPSets": { "office-ips": ["10.0.2.0/24"] },
  "RegexPatternSets": { "bad-ua": ["sqlmap", "gobuster"] },
  "Rules": [ … ]
}
```

**근사 평가되는 항목** — 결과 화면에 노란 배지로 표시된다. 로컬 판정이 실제 WAF와
다를 수 있으므로 **COUNT 검증은 여전히 필수**다.

| 항목 | 로컬 처리 |
|---|---|
| `ManagedRuleGroupStatement` | CommonRuleSet·KnownBadInputs·SQLi·Linux/Unix·Windows·PHP·WordPress·AdminProtection·BotControl을 공개된 규칙 의도대로 근사. 매칭 시 라벨도 발행 |
| `SqliMatchStatement` / `XssMatchStatement` | AWS 내부 토크나이저 대신 시그니처 탐지 (`SensitivityLevel` 반영) |
| `RateBasedStatement` | 스코프다운 조건만 평가 — 요청량 임계치는 합성 요청으로 재현 불가 |
| `RuleGroupReferenceStatement` | 문장 안에 `"Rules": […]`를 넣으면 평가 |

**여전히 판정 불가로 남는 것** — 로컬에 정답이 없는 것만 남긴다. IP 평판/익명 IP
목록(공인 IP일 때. 사설 IP는 미매칭으로 확정), ATP/ACFP 규칙 그룹, 서드파티
마켓플레이스 규칙 그룹, `ASNMatchStatement`, TLS 핑거프린트 필드, `MD5`
TextTransformation, 내용을 못 준 IP/정규식 세트 참조. 이때도 통과가 아니라
**판정 불가**로 표시되고 어떤 문법 때문인지 이름이 나온다.

TextTransformation은 `MD5`를 뺀 WAFv2 전 종류(`URL_DECODE_UNI`, `HEX_DECODE`,
`SQL_HEX_DECODE`, `REPLACE_COMMENTS`, `ESCAPE_SEQ_DECODE`, `CSS_DECODE`,
`JS_DECODE`, `NORMALIZE_PATH_WIN`, `BASE64_DECODE_EXT`, `UTF8_TO_UNICODE` 등)를
지원한다.

### 대회 전 리허설 (선택)

실제 공격 없이 탐지→추천→시뮬→적용 흐름을 검증하려면 리허설 트래픽 생성기를
쓴다. **본인 소유 대상에만** 사용:

```bash
mise run attack-sim -- --target https://<대시보드가 보는 ALB/CloudFront 호스트> --dry
# 실제 전송:
mise run attack-sim -- --target https://<host> --scenario mixed --duration 60 --rps 20
```

시나리오: `normal` / `ip-flood` / `path-flood` / `bad-ua` / `sqli` / `mixed`.
지정한 대상에 HTTP 요청만 보내며 AWS/K8s는 건드리지 않는다. 실행 후 WAF 탭의
샘플 요청·추천 규칙에서 결과 확인 (WAF 샘플 반영까지 수 분 소요될 수 있음).

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
  rulesim.ts    # 규칙 시험 샌드박스: 입력 파싱(Rule/배열/WebACL/Statement) + 다중 규칙 평가
  rulejson.ts      # 연속 붙여넣기({…}{…})·주석·트레일링 콤마를 받는 관대한 JSON 리더
  rulestatement.ts # WAFv2 Statement 평가기 (3값 논리: true/false/UNKNOWN)
  rulerequest.ts   # 합성 요청 정규화(헤더/쿠키/쿼리인자/바디) + CIDR 매칭
  ruletransform.ts # TextTransformation 구현 (MD5 제외 전 종류)
  ruleinjection.ts # SQLi/XSS 로컬 시그니처 탐지
  rulemanaged.ts   # AWS 관리형 규칙 그룹 근사 + 라벨 발행
  anomaly.ts    # 이상 감지 (오탐 방지 규칙 포함)
  correlation.ts# 상관 분석 + 타임라인
  fingerprint.ts# 오류 정규화·핑거프린트
  incident.ts   # 스냅샷 + Markdown/JSON/Q 프롬프트 컨텍스트
  gateway.ts    # 게이트웨이 응답 계약(404/200/403) 판정 + Q 프롬프트 길이 패킹
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
