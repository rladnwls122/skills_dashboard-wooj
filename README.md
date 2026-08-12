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

좌측 상단 배너 6칸(ALB/RDS/WAF/K8S/PODS/ANOM)은 서브시스템별 실시간 상태등 —
빨간색이 점멸하면 해당 영역에 문제가 있다는 뜻. 탭은 좌측 레일(모바일은 상단
가로 스크롤)에서 전환한다.

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

1. **요약 (Overview)** — 핵심 메트릭 카드, Pod 상태, Warning 이벤트, 감지된
   이상 목록을 한 화면에 모아 보여줌. 장애 발생 시 가장 먼저 보는 탭.
2. **성능 (Performance)** — 맨 위 **채점 지표 정렬**은 채점기(skills-grader)가 쓰는
   지표 키에 관측 트래픽을 맞춰 세워 둔 표다. `(user|product|stress) availability` /
   `performance`, `image download`, `Exception Handling` 순으로, 각 키의 비율과
   충족/전체 건수를 보여준다. **점수는 매기지 않는다** — 점수는 채점기 실행 결과
   (`results_<비번호>.log`)가 정하고, 이 표는 그 값이 왜 그렇게 나오는지 보라고
   있는 것이다. 앱 로그 Logs Insights 한 번으로 집계하며 **조회를 눌러야** 실행된다.
   그 아래로 Pod 상태 분포와 개수(min/current/max), Node 개수와
   리소스 사용률, Pod Health 표, Target Group별 지표, 상태코드 분포, Warning
   Event Board, 그리고 **Deployment 조정**(Replicas/CPU/Memory Limit 변경 →
   승인 → 약 2분 뒤 사후 검증으로 IMPROVED/NO_CHANGE/DEGRADED/INCONCLUSIVE).
   병목을 보고 같은 화면에서 바로 조치한다. 표의 "로그" 버튼은 로그 탭으로
   이동하며 해당 Pod를 선택해 준다.
3. **방화벽 (WAF)** — WAF 이상 요약, 경로/IP/쿼리/헤더/메소드별 통계(경로에는
   "의심"·"헬스체크" 표시, IP는 점유율 30%↑ 강조), **샘플 요청 원본 테이블**
   (BLOCK/ALLOW/COUNT 필터·검색). 규칙 추천 카드에서 **시뮬레이션 → COUNT
   적용(승인 필요) → BLOCK 승격(COUNT 검증 이력 필요)** 순서로만 진행된다.
   각 카드의 **"룰 JSON"**과 **"Q 프롬프트 복사"** 버튼, 적용 이력에서 롤백.
4. **로그 (Logs)** — Pod 로그 터미널(검색·Previous·자동갱신, **"문제만"**으로
   Error/Warn만, **"시간 숨김"**으로 타임스탬프 접기), 요청 로그 분석
   (latency/비정상 응답/Error·Warn), 반복 오류 지문, 상태코드로 조회하는 앱
   요청 로그. 브라우저에서 필터를 걸면 "표시 N줄 / 조회 M줄"로 모집단을 밝힌다.
5. **점검 (Check)** — 입력한 주소로 대시보드가 **직접 GET 요청을 한 번** 보낸다.
   다른 화면은 전부 CloudWatch를 읽는데, CloudWatch는 몇 분 늦고 값이 비었을 때
   "트래픽이 없었다"와 "아직 게시되지 않았다"를 구분해 주지 않는다. "지금
   응답하는가"는 데이터가 답할 수 없는 질문이라 서비스에 직접 묻는다.
   기대 코드를 비우면 2xx, 넣으면 그 코드만 정상으로 본다. 반복(5/10/30초)을
   켜면 그 주기로 계속 찌른다. 요청에는
   `User-Agent: skills-dashboard/traffic-check`가 붙으므로 WAF·로그 탭에서 이
   요청을 실제 트래픽과 구분할 수 있다. 응답 본문은 읽지 않고 버리며(스크린샷에
   본문이 찍히지 않도록), 결과는 최근 30회까지 **메모리에만** 남는다 — 새로고침하면
   사라진다. 실패한 점검도 결과로 표시되지 실패로 던지지 않는다: 대시보드가
   고장난 것과 대상이 고장난 것은 다른 사실이다. `http`/`https`만 요청한다.
6. **시험 (Sandbox)** — WAF 규칙을 적용 전에 **로컬에서만** 돌려본다. AWS로
   아무것도 보내지 않고 WebACL도 건드리지 않는다. 아래 "규칙 시험 샌드박스" 참고.
7. **규칙생성 (AI)** — 용도별(의심 경로 / 의심 User-Agent / SQL 인젝션)로 규칙을
   조립한다. 정규식 패턴 세트는 규칙과 **별개의 AWS 리소스**이므로 산출물도 둘로
   나뉜다.
   - **① 패턴 세트** — 세트에 넣을 정규식 목록과 `aws wafv2 create-regex-pattern-set`
     명령. 세트를 먼저 만들어 ARN을 받는다.
   - **② 규칙 JSON** — ①의 세트를 **ARN으로 참조**한다. 만들기 전에는 ARN 자리가
     자리표시자이고, 화면이 "그대로 붙여넣으면 AWS가 거부한다"고 경고한다.
     ARN을 입력란에 붙여넣으면 규칙 JSON에 채워진다 (세트 이름을 ARN 자리에 넣으면
     AWS가 거부하므로 이름을 넣지 않는다).

   **"시험 탭으로 보내기"**는 패턴을 인라인으로 담은 별도 형태를 보낸다 — 로컬
   평가기는 그 형태만 읽을 수 있고, 덕분에 세트를 만들기 전에도 판정할 수 있다.
   같은 탭에서 **Incident Context**(Amazon Q 프롬프트 / Markdown / JSON)를 생성한다.

   **게이트웨이 기대 동작**: 이 환경의 게이트웨이는 미지정 경로 → `404`
   (엔드포인트가 없는 것처럼 보이게 해 스캐닝 차단), 지정 경로 + 정상 요청 →
   `200`, 지정 경로 + 비정상 요청(SQLi/XSS/Body 포맷 오류/차단 IP/rate limit
   초과) → `403`으로 응답한다. 따라서 404·403 자체는 장애가 아니라 정책이
   동작한 결과이며, **5XX와 "미지정 경로가 통과된 것"만이 계약 위반**이다.
   보고서는 관측된 트래픽을 이 기준에 대고 `[정상]`/`[편차]`로 갈라 적고,
   WAF 추천 규칙마다 Block 시 돌려줄 응답 코드를 함께 제안한다.

**규칙 조립이 지키는 표준** — 패턴은 한 줄에 하나(패턴 세트는 줄 단위로 독립
평가), 전부 소문자(LOWERCASE 변환이 먼저 적용되므로 대문자는 영영 매칭되지
않음), 리터럴의 메타문자는 이스케이프, POSIX 클래스 없이 RE2 문법만. 인코딩
우회는 URL_DECODE·HTML_ENTITY_DECODE·NORMALIZE_PATH·COMPRESS_WHITE_SPACE로
먼저 정규화한 뒤 매칭한다. AWS 고정 한도(세트당 정규식 10개, 패턴 200자)도
지키며, 패턴이 10개를 넘으면 **버리지 않고 세트를 나눠** OrStatement로 묶고
콘솔에서 몇 개를 만들어야 하는지 알려준다. 이 규약들은 테스트가 산출되는 모든
패턴에 대해 검사한다.

**패널 확대** — 카드 제목 옆 `⤢` 버튼이 같은 패널을 크게 연다. ESC와 배경
클릭으로 닫히고, 카드와 확대창은 같은 코드 경로를 쓰므로 두 곳이 다른 행이나
다른 분모를 보여줄 수 없다. 열려 있는 동안에도 자동 새로고침은 계속 돈다.

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

`cost ratio`는 이 도구가 관측할 수 없어 표에 없다. 0점으로 적으면 점수처럼 읽히기
때문에 아예 빼고, 왜 뺐는지 적는다.

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
- **Kubernetes 조회 실패 (HTTP protocol is not allowed 등)** — `~/.kube/config`
  컨텍스트가 올바른 클러스터를 가리키는지 `kubectl config current-context`로 확인.
- **Pod/Node 리소스 사용률이 항상 비어있음** — 클러스터에 metrics-server가
  설치되어 있는지 `kubectl top nodes`로 확인.
- **빌드가 `Cannot find module for page: /` 로 실패** (`✓ Compiled successfully`
  가 먼저 찍히는데도) — `.next` 캐시가 낡은 것. `mise run clean` 후 다시 빌드하거나
  처음부터 `mise run build-clean`을 쓴다. 소스 문제가 아니다.

---

## 프로젝트 구조

```
src/app/actions/dashboard.ts   # 모든 서버 액션 (AWS/K8s 접근은 전부 서버)
src/app/dashboard/page.tsx     # 대시보드 페이지
src/app/dashboard/ui/          # 클라이언트 컴포넌트 (탭 7개 + 공용 표시 요소)
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
  probe.ts      # 트래픽 점검 (입력 주소로 GET 1회, http/https만, 10초 제한)
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
