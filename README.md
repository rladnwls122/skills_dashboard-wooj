# skills-dashboard

국가기능경기대회 클라우드컴퓨팅 트러블슈팅용 통합 대시보드.
CloudWatch(ALB/RDS Proxy/WAF) 메트릭, WAFv2 규칙 조립·COUNT 적용·BLOCK 승격·내리기,
Kubernetes Pod/Event/로그 추적, Deployment 리소스 조정, 사후 검증,
채점기 입력값 집계를 하나의 화면에서 수행한다.

대상 환경 (task-3): `skills-eks`(ap-northeast-2) · `skills-alb`(LBC Ingress) ·
`skills-db-proxy`(MySQL 8.0) · `skills-waf`(CLOUDFRONT scope, us-east-1) ·
`skills-cdn` · namespace `default`의 `user`/`product`/`stress` Deployment.

로컬 실행 전용 — 대시보드 자체에는 접속 인증이 없다. 클러스터/AWS 인증은
로컬에 이미 있는 kubeconfig·AWS 자격증명을 그대로 사용한다.

그래서 서버는 **`127.0.0.1`에만 바인딩한다**(`-H 127.0.0.1`). 인증이 없는데
`0.0.0.0`에 열면 같은 네트워크의 누구나 이 화면으로 Deployment를 패치하고 WAF
규칙을 적용할 수 있다. 다른 기기에서 봐야 하면 SSH 포트 포워딩을 쓰고, 바인딩
주소를 넓히지 않는다.

**대회 당일에 읽을 문서는 이게 아니라 [`docs/RUNBOOK.md`](docs/RUNBOOK.md)다** —
무엇을 보고 무엇을 누르는지 한 장으로 적혀 있다. 이 README는 그 화면이 어떻게
만들어졌는지를 적는다.

---

## 빠른 시작

### 1. 사전 준비

- [mise](https://mise.jdx.dev) 설치 (Node 20 버전은 `mise.toml`이 자동으로 맞춰줌)
- AWS 자격증명: `aws configure` / `aws sso login` 으로 로컬 세션만 있으면 된다. 화면(톱니 → `AWS 자격증명` → `aws CLI 세션 불러오기`)에서 그 세션을 그대로 주입하며, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` 환경변수나 `.env` 도 그대로 쓰인다
- Kubernetes 클러스터 접근 가능한 `~/.kube/config` (`aws eks update-kubeconfig --name skills-eks --region ap-northeast-2`)

### 2. 설치 및 설정

```bash
winget install jdx.mise --source winget
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
mise run build-clean && mise run start   # 캐시 삭제 후 production 빌드로 실행
```

브라우저에서 `http://localhost:3100/dashboard` 접속. 별도 로그인 없음.

**빌드 전에는 캐시를 지운다.** `mise run build-clean`(= `pnpm build:clean`)은
`.next`를 지우고 빌드한다. 캐시를 남긴 채 빌드하면 소스가 정상인데도
`Cannot find module for page: /` 처럼 컴파일은 성공하고 페이지 수집만 실패하는
일이 있다 — 탭을 추가·삭제하거나 파일을 옮긴 뒤에 특히 그렇다. 캐시만 지우려면
`mise run clean`.

### 4. 종료

터미널에서 `Ctrl+C`. (백그라운드 실행 시 `mise run start` PID를 kill)

---

## 화면 사용법

탭은 **`성능` / `트래픽` / `규칙 생성`** 3장이고 **상단바**에서 전환한다. 좌측
레일을 없앤 이유는 폭이다 — 버튼 세 개를 담자고 모든 화면에서 176px을 가져갔고,
그 폭은 Target Group 표와 로그 테이블이 훨씬 잘 쓴다. 소스별 갱신 시각(K8S·CW·WAF)도
같은 줄 오른쪽으로 옮겼다. 상단 상태등 6칸은 없앴다 — 바로 아래 타일과 같은 값을 두 번
읽게 했다. 이상 유무는 `성능` 탭의 채점 키 8줄과 이상 목록이 직접 답한다.

**설정은 탭이 아니라 헤더 우측 톱니(⚙)**다. 리소스 이름·로그 그룹은 자동 탐색이
기본이고 설정 화면은 그 값이 틀렸을 때 사람이 덮어쓰는 안전장치라, 평소 감시
화면에 자리를 차지할 이유가 없다. ESC나 배경 클릭으로 닫는다.

그 모달 맨 위가 **AWS 자격증명**이다. 리소스 이름이 틀리면 패널 하나가 비지만
키가 틀리거나 만료되면 전부 한꺼번에 비므로, 가장 먼저 확인할 것을 가장 위에 뒀다.
`aws CLI 세션 불러오기`는 로컬에 로그인된 세션(`aws sso login` 포함)의 임시 키와
session token 을 읽어 주입하고, **만료가 가까워지면 스스로 다시 읽는다** — 대회 중에
세션이 끊겨 모든 패널이 죽는 상황을 없애기 위한 것이다. CLI 가 없으면 `키 직접 입력`
에 통째로 붙여넣으면 된다(`export …` 블록, `.env`, `[profile]` 섹션, CLI JSON 모두
인식). 주입한 키는 기본적으로 **프로세스 메모리에만** 남고, 체크박스를 켤 때만
SQLite 에 저장된다(평문). 화면에는 언제나 마스킹된 값만 돌아온다.

**구간 막대**(헤더 아래 줄)는 화면 전체가 공유하는 하나의 시간 창이다.
`15m / 30m / 1h / 2h / 4h` 버튼은 열지 않아도 현재 값이 보이고, 옆에 `갱신
23:09:44 · 7초 전`과 **절대 시각**(`08.12. 22:00:00 ~ 08.12. 23:00:00 · 60초 버킷
· 60개`)이 같이 찍힌다. "1h"는 창이 얼마나 넓은지만 말하지 어디에 있는지는
말하지 않기 때문이다. 4시간이 상한인 이유는 Logs Insights가 스캔 바이트로
과금하기 때문이고, 그래서 한도를 서버 에러가 아니라 컨트롤에 적어 뒀다.

**숫자마다 근거가 붙는다.** 각 타일 아래 작은 글씨는 그 값이 무엇을 집계한
것인지 — CloudWatch 지표 이름·집계함수·기간까지 — 적는다
(`AWS/WAFV2 BlockedRequests (WebACL=skills-waf, Rule=ALL) Sum · 최근 3버킷(3분)
합계를 분당으로 환산`). 화면에 뜨는 이름(`WAF BlockedRequests`)은 우리가 붙인
말이고, 콘솔에서 찾아 확인하려면 지표의 실제 이름이 필요하다. 값을 클릭하면
클립보드로 복사된다. 목록은 **전체 / 조회 / 표시** 세 숫자를 따로 적는다 —
한도에 걸려 잘린 배열 길이를 전체 건수로 읽는 일을 막기 위해서다.

1. **성능 (Performance)** — 대회 2시간 동안 띄워 두는 화면. 스크롤 없이 보이는
   범위가 "지금 이상이 있는가"에 답한다.
   - 맨 위 **채점기 입력값** — 채점기(skills-grader)가 쓰는 키에 관측 트래픽을 맞춘
     8줄. `(user|product|stress) availability` / `performance`, `image download`,
     `Exception Handling`. **점수는 매기지 않는다** — 점수는 채점기 실행 결과가
     정하고, 이 표는 그 값이 왜 그렇게 나오는지 보라고 있다. 앱 로그 Logs Insights
     집계라 **5분마다 자동**이고, 지금 보려면 `⟳`. (규칙을 올린 직후가 그 경우다.)
   - 그 옆이 **노드 대수** 패널, 아래가 **TRT / 4XX / 5XX / RDS Conn** 4타일.
     제목 옆 회색 숫자가 판단선이다 (`5XX 20/min` = 넘으면 앱 장애를 의심).
   - **이상 목록** — 상태등을 없앴으므로 이 카드가 유일한 경보다. 각 줄을 펼치면
     근거가 나온다.
   - 아래로 Pod Health(상태 분포 포함), Pod/Node 리소스 사용률, Target Group별
     지표, Warning Event Board, 맨 아래 **Deployment 조정**(Replicas/CPU/Memory
     Limit 변경 → 승인 → 약 2분 뒤 IMPROVED/NO_CHANGE/DEGRADED/INCONCLUSIVE).
2. **트래픽 (Traffic)** — 지금 무엇이 들어오고 있나. 경로별 요청·차단, User-Agent,
   QueryString 패턴, 앱 요청 로그(상태코드 필터·경로 검색), WAF Blocked/Allowed
   추이, Pod 로그 터미널과 반복 오류 지문.

   앱 요청 로그에는 **User-Agent 열**이 있고, 행을 클릭하면 **로그 원문**이 열린다.
   파싱한 열은 어떤 필드가 중요한지에 대한 우리 쪽 추측이라, 앱이 예상 밖의 이름으로
   남긴 헤더는 원문에서만 보인다. 앱이 UA 를 아예 안 남기면 열은 `—` 로 비며 그것도
   정상적인 답이다. 원문은 다른 로그와 같은 마스킹(`server/mask.ts`)을 거친다.

   **경로 목록에는 규칙 만들기 버튼이 없다.** 미지정 경로는 ALB가 이미 404를 내므로
   WAF가 손댈 이유가 없다 — `의심` 배지는 "규칙을 만들라"가 아니라 "그 경로가 진짜
   404로 끝났는지 `Exception Handling`과 대조하라"는 신호다. 규칙으로 가는 통로는
   **User-Agent 목록**뿐이다.
3. **규칙 생성 (AI)** — 한 규칙의 일생이 이 한 화면에서 끝난다.
   - **① 패턴 세트** — 세트에 넣을 정규식과 `aws wafv2 create-regex-pattern-set`
     명령. 세트를 먼저 만들어 ARN을 받는다.
   - **② 규칙 JSON** — ①의 세트를 **ARN으로 참조**한다. 자리표시자가 남아 있으면
     전이 버튼이 비활성이다 (세트 이름을 ARN 자리에 넣으면 AWS가 거부한다).
   - **③ 전이 버튼** — 상태는 `GetWebACL`에서 매번 파생한다. 로컬 상태 테이블이
     없으므로 누가 콘솔에서 직접 바꿔도 화면이 거짓말하지 않는다.
     **UA 규칙은 `추천됨 → BLOCK`**(버튼 2개), **SQLi 규칙은 `추천됨 → COUNT →
     BLOCK`**(버튼 3개). UA는 관측된 문자열에서 조립되어 무엇을 막는지 이미 눈으로
     확인한 상태라 COUNT를 거치지 않고, SQLi는 고정 시그니처라 우리 정상 쿼리가
     걸리는지 실측해야 한다. `내리기`는 어느 상태에서든 같은 버튼이다.
   - **COUNT 실측** — SQLi 규칙이 COUNT일 때만 열린다. `매칭 34건 (정상 0 ·
     비정상 21 · 조인 불가 13)` 형태로 셋을 나란히 적는다. **조인 불가를 비정상에
     합치지 않는다** — POST/PUT은 양쪽 로그에 `requestid`가 없어 조인이 불가능하고,
     그걸 비정상으로 세면 없는 근거를 지어내는 것이 된다.
   - **정상 경로 프로브** — 규칙을 올린 직후 정상 경로가 아직 200인지 확인한다.
     UA 규칙은 COUNT를 안 거치므로 **이 확인이 절차다.**
   - 같은 탭에서 WebACL 규칙 목록과 WCU를 본다.

**경로 스코프다운은 강제다.** 조립되는 UA·SQLi 규칙은 `AND(제공 API 경로, 탐지 조건)`
형태로만 나오고, 손으로 붙여넣은 JSON도 같은 검사를 통과해야 올라간다. WAF는 ALB
**앞**에 있어서, 스코프다운이 없으면 미지정 경로로 들어온 악성 요청이 ALB의 404에
닿기 전에 403으로 잘린다 — 요구사항은 404다.

**오탐 경보** — 규칙을 올리는 순간 채점 키 8줄을 스냅샷으로 남기고, 5분 안에 어느
키든 1%p 이상 떨어지면 `성능` 탭 이상 목록에 CRITICAL로 뜬다.

**규칙 조립이 지키는 표준** — 패턴은 한 줄에 하나(패턴 세트는 줄 단위로 독립
평가), 전부 소문자(LOWERCASE 변환이 먼저 적용되므로 대문자는 영영 매칭되지
않음), 리터럴의 메타문자는 이스케이프, POSIX 클래스 없이 RE2 문법만. 인코딩
우회는 URL_DECODE·HTML_ENTITY_DECODE·NORMALIZE_PATH·COMPRESS_WHITE_SPACE로
먼저 정규화한 뒤 매칭한다. AWS 고정 한도(세트당 정규식 10개, 패턴 200자)도
지키며, 패턴이 10개를 넘으면 **버리지 않고 세트를 나눠** OrStatement로 묶고
콘솔에서 몇 개를 만들어야 하는지 알려준다. 이 규약들은 테스트가 산출되는 모든
패턴에 대해 검사한다.

**드릴다운은 탭 이동 하나로 통일했다.** 카드 확대(`⤢`)는 없앴다 — 같은 카드를 크게
보여줄 뿐 다음 행동을 주지 않았다. 시간창은 전역이라 탭을 옮겨도 그대로 따라간다.

**원칙**: 자동 차단·자동 정책 변경 없음. WAF/Deployment 변경은 항상 사람의
명시적 승인을 거친다.

### 대회 전 리허설 (선택)

실제 공격 없이 탐지→추천→COUNT→승격 흐름을 검증하려면 리허설 트래픽 생성기를
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

## 조회 구간

상단의 **구간**과 **간격**이 화면 전체의 시간창을 정한다. 지표, Target Group,
WAF 통계, Pod 로그, 앱 요청 로그가 **모두 같은 창**을 읽는다. 두 패널의 숫자를
나란히 놓고 비교할 수 있다는 뜻이다 — 이전에는 지표가 14분, WAF 샘플이 15분,
로그가 Insights 기본값을 각자 보고 있어서 같은 화면의 두 숫자가 서로 다른
시간을 세고 있었다.

- 구간은 15분 / 30분 / 1시간 / 2시간 / 4시간. **4시간이 상한**이다 — Insights는
  스캔 바이트당 과금이라 상한이 곧 비용의 상한이다.
- 간격은 버킷 수가 4~250개가 되는 조합만 열린다. 서버가 검증하고, 잘못된 조합이
  들어오면 거부 대신 유효한 값으로 고쳐서 쓴다(고친 결과가 화면에 그대로 표시됨).
- 창의 끝은 간격 경계로 내림한다. **모든 버킷이 완전한 버킷**이라 진행 중인
  미완성 버킷이 급락처럼 보이는 일이 없다.

각 패널은 자기가 무엇을 센 것인지 제목 아래에 적는다. 지표 카드의 대표값은
"최근 3버킷 합계/평균"이며 3버킷이 몇 분인지는 선택한 간격에 따라 달라지므로
그 값도 함께 적힌다 — `req/min` 같은 단위만으로는 3버킷 합계를 분당 값으로
잘못 읽게 된다.

### 채점 지표는 어디까지 맞고 어디부터 다른가

가용성은 `2xx && 5초 이내`, 성능은 그중 `SLO 이내`(user·product 200ms, stress 1s)로
센다. 채점기는 요청마다 **자기가 기대한 코드**(생성 201, 조회 200)를 알고 비교하지만
로그 한 줄에는 그 의도가 없어 2xx로 근사한다 — 그래서 채점기 값과 다를 수 있고,
화면이 그 사실을 함께 띄운다.

`Exception Handling`은 앱 로그에 남은 **미지정 경로** 요청 중 404/403으로 끝난 비율이다.
WAF가 차단한 요청은 앱에 도달하지 않아 이 분모에 없으므로, 같은 구간의 WAF 차단
건수를 옆에 따로 적는다. 두 수는 출처가 다르니 더하지 않는다.

`cost ratio`는 이 표에 없다. 다만 **관측할 수 없어서가 아니다** — 채점기가 쓰는
입력은 채점 창 동안의 인스턴스 대수이고, 그 대수는 CloudTrail의
`RunInstances`/`TerminateInstances`(사전 설정 불필요·90일 보존)로 대시보드가 꺼져
있던 구간까지 사후 재구성된다. 대수에서 점수로 가는 계산식이 비공개 절대식이라
**점수를 만들지 않을 뿐**이다.

대수는 `성능` 탭 최상단 `채점 창 노드 대수` 패널이 센다. 실시간 값은
`describe-instances` 30초 폴링이고, 대시보드가 꺼져 있던 구간은 기동 시 CloudTrail로
한 번 메운다. 패널이 내놓는 숫자는 **최종 평균**(지금 대수를 창 끝까지 유지했을 때)과
**1대 증감**(지금 한 대가 최종 평균을 움직이는 폭) 둘이고, 규격 외 인스턴스는 0이 아닐
때만 나타난다. 색으로 된 판정도 목표선도 없다 — 채점식이 비공개인 이상 초록색은
화면이 근거 없이 만들어낸 판단이 된다.

경기 시작 시각은 톱니 모달에서 입력한다. **비어 있으면 평균을 만들지 않는다** — 창
시작이 틀리면 시간가중 평균이 통째로 틀리고, 화면은 그게 틀렸다는 걸 보여줄 방법이
없기 때문이다.

노드 대수를 셀 때 **ASG 그룹 메트릭은 쓰지 않는다** — Karpenter가 띄운 노드는
어떤 ASG에도 속하지 않아 채점 대상 노드를 통째로 놓친다.

### WAF 통계는 로그가 있으면 전수 집계

`WAF_LOG_GROUP`이 설정돼 있으면 경로·IP·UA·메소드·쿼리 통계를 **WAF 로그의
Logs Insights 집계**로 읽는다. 선택한 구간을 그대로 따르고, 표본이 아니라 전수이며,
스캔한 바이트를 패널에 표시한다.

설정돼 있지 않으면 `GetSampledRequests`로 폴백한다. 이 API는 **규칙당 500건**
표본을 WAF 자신의 3시간 상한 안에서 돌려주므로 선택한 구간을 따르지 못한다.
그래서 폴백일 때는 패널이 그 사실과 함께 "`WAF_LOG_GROUP`을 설정하면 전수
집계로 바뀐다"를 함께 표시한다. Insights 집계가 실패해서 폴백한 경우에는 그
이유도 같이 적는다.

집계는 `(키, action)`으로 묶여서 오고 화면이 그것을 키 하나로 접는다. 차단된
것만 걸러 오면 빈 목록이 "아무것도 차단되지 않았다"인지 "아무것도 들어오지
않았다"인지 구분되지 않기 때문이다. 묶어서 받아도 스캔량은 늘지 않는다.

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
- **모든 패널이 한꺼번에 빈다 / `could not load credentials` / `ExpiredToken`** —
  자격증명 문제다. 톱니 → `AWS 자격증명` → `aws CLI 세션 불러오기`, 그 다음 `연결 확인`.
  `유효 (권한 제한)` 은 통과다 — 키는 맞고 확인용 `ec2:DescribeVpcs` 만 막힌 상태다.
  `.env` 만 고치고 재시작하지 않았다면 값이 반영되지 않는다(`.env` 는 기동 시점에만 읽힌다).
- **Kubernetes 조회 실패 (HTTP protocol is not allowed 등)** — `~/.kube/config`
  컨텍스트가 올바른 클러스터를 가리키는지 `kubectl config current-context`로 확인.
- **Pod/Node 리소스 사용률이 항상 비어있음** — 클러스터에 metrics-server가
  설치되어 있는지 `kubectl top nodes`로 확인.
- **`kubeconfig 의 인증 명령 "aws" 을(를) 찾지 못했습니다`** — AWS CLI 자체가 없다.
  설치하거나(`C:\Program Files\Amazon\AWSCLIV2` 는 PATH 에 없어도 자동 탐색된다)
  `~/.kube/config` 의 `users[].user.exec.command` 를 전체 경로로 바꾼다.
- **빌드가 `Cannot find module for page: /` 로 실패** (`✓ Compiled successfully`
  가 먼저 찍히는데도) — `.next` 캐시가 낡은 것. `mise run clean` 후 다시 빌드하거나
  처음부터 `mise run build-clean`을 쓴다. 소스 문제가 아니다.

---

## 프로젝트 구조

```
src/app/actions/dashboard.ts   # 모든 서버 액션 (AWS/K8s 접근은 전부 서버)
src/app/dashboard/page.tsx     # 대시보드 페이지
src/app/dashboard/ui/          # 클라이언트 컴포넌트 (탭 3개 + 설정 모달 + 공용 표시 요소)
src/lib/awscreds.ts            # 붙여넣은 자격증명 블록 파싱·마스킹 (서버·클라이언트 공용)
src/lib/server/                # server-only 모듈
  config.ts     # env + 임계치 설정 객체
  credentials.ts# 화면에서 주입한 AWS 키의 저장·해소(만료 시 자동 갱신)
  awslogin.ts   # 로컬 aws CLI 세션 읽기 (export-credentials → ~/.aws/credentials)
  credcheck.ts  # 주입된 키 확인 (인증 실패와 권한 거부를 구분)
  aws.ts        # SDK 클라이언트, ALB/TG/리스너규칙 자동 탐색, EKS 노드그룹 스케일링
  cloudwatch.ts # GetMetricData, current/previous/delta/%/status, TG별 지표
  waf.ts        # 샘플 수집, HTTP 요약, setRuleAction (COUNT 적용/BLOCK 승격/내리기)
  k8s.ts        # Pod/Event/Deployment/로그, JSON Patch + 검증
  resources.ts  # Pod/Node 리소스 사용률(metrics.k8s.io), HPA/Nodegroup 스케일링, 상태 분포
  requestlog.ts # Gin 액세스로그 파싱 → latency/상태코드/에러·경고
  ruleassemble.ts # 관측 트래픽 → 정규식 패턴 세트 + 규칙 JSON 조립
  logfields.ts  # 앱 로그 JSON에서 뽑는 Insights parse 구문 (requestid/uuid/User-Agent)
  anomaly.ts    # 이상 감지 (오탐 방지 규칙 + 규칙 적용 후 채점 키 하락 경보)
  wafcountevidence.ts # COUNT 매칭 요청 ↔ 앱 로그 requestid 조인 (GET 한정)
  fingerprint.ts# 오류 정규화·핑거프린트
  probe.ts      # 트래픽 점검 (입력 주소로 GET 1회, http/https만, 10초 제한)
  mask.ts       # 민감정보 마스킹
  db.ts         # SQLite (이력/baseline/스냅샷)
  cache.ts      # TTL + in-flight dedup 캐시
k8s-dashboard-rbac.yaml        # 스펙 필수 산출물 (참고용, 미적용)
```

## 동작 원칙

- WAF 변경은 항상 사람이 버튼을 누른다. SQLi는 조립 → COUNT 적용 → 실측 →
  BLOCK 승격, UA는 조립 → BLOCK. 자동 승격도 자동 롤백도 없다.
- 규칙은 **제공 API 경로 스코프다운 없이는 올라가지 않는다** — 조립 경로와
  붙여넣기 경로가 같은 검사를 통과한다. 미지정 경로가 404 대신 403을 받으면
  채점의 `Exception Handling`이 깨지기 때문이다.
- 규칙을 올린 시점의 채점 키를 스냅샷으로 남기고, 5분 안에 1%p 이상 떨어지면
  이상 목록에 CRITICAL로 띄운다.
- 자동 차단·자동 정책 변경 없음. Deployment 패치도 명시적 승인 후에만 실행.
- 단일 메트릭만으로 CRITICAL 판정 없음. 헬스체크 경로는 이상 판정에서 저순위
  처리하는데, 그 경로는 **`/healthcheck` 하나뿐**이다 — `/health`·`/healthz` 같은
  관용 경로는 이 앱이 서비스하지 않으므로 저순위가 아니라 **미지정 경로**이고,
  그쪽을 훑는 요청은 의심 경로로 보여야 한다 (`HEALTH_PATHS` 로 변경 가능).
- 서비스 경로(`APP_TRAFFIC_PATHS`)는 `/v1/user,/v1/product,/v1/stress,/v1/image,/images`.
  이 목록은 허용 목록이자 **모든 규칙의 경로 스코프다운 재료**다 — 실제로 서비스되는
  경로가 빠지면 그 경로로 오는 트래픽에는 규칙이 걸리지 않는다. 이미지가
  `/images/*.png` 정적 자산으로도 나가므로 두 형태를 모두 넣었다.
- 폴링 계층: K8s 3초 / 로그 5초(자동갱신 시) / CloudWatch·WAF 30초.
  서버 캐시가 in-flight 중복과 과도한 API 호출을 차단.
- 서브시스템 장애는 영역별로 격리 — 한 곳이 죽어도 화면 전체는 유지.

## 스택

Next.js 15 App Router · React 19 · TypeScript strict · Tailwind CSS v4 ·
AWS SDK v3 (cloudwatch, wafv2, elbv2, cloudwatch-logs, eks) · @kubernetes/client-node 1.x ·
better-sqlite3 (이력·baseline 저장) · pnpm · mise
