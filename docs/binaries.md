# 과제 바이너리가 실제로 찍는 것 (전국기능경기대회 · 클라우드컴퓨팅 3과제)

대시보드의 로그 파싱·채점 키·규칙 샌드박스는 전부 이 문서의 사실 위에 서 있다.
출처는 `3과제/문제/` 의 `user` · `product` · `stress` ELF 바이너리(Go 1.22, Gin v1.10.1, 디버그 심볼 포함)를
직접 디스어셈블한 결과와 `3과제_문제.pdf` · `3과제_채점기준.hwp` 다. 추측한 값은 없다.

## 1. 세 바이너리의 공통 구조

| 항목 | 값 |
|---|---|
| 프레임워크 | `gin.Default()` — Logger + Recovery 미들웨어, **debug 모드** |
| 추가 미들웨어 | `main.loggingMiddleware`: `log.Printf("[%s] %s %s from %s", RFC3339, method, path, clientIP)` → **stderr**, 핸들러 실행 **전**에 찍힘 |
| 포트 | `:8080` |
| 헬스체크 | `GET /healthcheck` → `200 {"status":"ok."}` |
| 옵션 | `-h / --help` → usage 출력 후 종료 |
| 요청 변조 방지 | 요청마다 `requestid` · `uuid` 가 쿼리스트링(GET) 또는 JSON body(POST)에 실린다. 바이너리는 AES-GCM(고정 키)으로 응답 토큰을 만든다 — 응답을 건드리면 채점에서 불이익 |

### 요청 한 건이 남기는 로그 두 줄

```
stderr  2025/09/23 03:12:45 [2025-09-23T03:12:45Z] POST /v1/user from 203.0.113.10
stdout  [GIN] 2025/09/23 - 03:12:45 | 201 |   12.345678ms |   203.0.113.10 | POST     "/v1/user"
```

* 상태·지연은 **`[GIN]` 줄에만** 있다. 이 줄이 액세스 로그다. 형식 문자열:
  `[GIN] %v |%s %3d %s| %13v | %15s |%s %-7s %s %#v` (컨테이너 stdout 은 TTY 가 아니라 색 코드 없음)
* 경로는 **쿼리스트링 포함** 전체 URI (`"/v1/user?email=…&requestid=…&uuid=…"`). 경로별 집계는 반드시 `?` 앞까지로 잘라야 한다 — 안 자르면 GET 한 건마다 행이 하나씩 생긴다.
* 지연은 Go `time.Duration.String()` 그대로: `850ns` · `45.678µs` · `12.345678ms` · `1.234567891s`, 1분을 넘으면 초 단위로 잘려 `1m2s`.
* client IP 는 gin 이 `X-Forwarded-For` 를 신뢰해 풀어낸 값 (debug 모드라 모든 프록시 신뢰 → ALB 뒤에서도 실제 클라이언트 IP).
* stderr 의 `[…] METHOD PATH from IP` 줄은 같은 요청의 중복이다. 요청 수로 세면 두 배가 된다 — 대시보드는 세지 않는다.
* 기동 시 `[GIN-debug] …` 라우트 목록·경고 줄이 몇 개 나온다. 액세스 라인이 아니다.

### 로그 그룹 형태

* **EKS Container Insights** — 2026 과제가 요구하는 배포다(ECS 사용 불가). 기본 그룹은
  `/aws/containerinsights/<클러스터>/application`. 줄이 JSON 으로 감싸이고 경로의 따옴표가 `\"` 로
  이스케이프된다: `{"log":"[GIN] … POST     \"/v1/user\"\n","stream":"stdout","kubernetes":{…}}`
* **ECS awslogs** — 2026 에서는 쓸 수 없지만 파서는 이 형태도 그대로 읽는다. 위 줄이 감싸이지 않은
  `@message` 로 온다. 그룹이 여러 개로 나뉘면 `APP_LOG_GROUP` 에 쉼표로 나열한다.

대시보드의 Insights 파서(`backend/analysis/logfields.ts`)는 `@message` 에 정규식을 걸어 두 형태를 모두 읽는다.
패턴에 백슬래시를 쓰지 않는 이유도 거기 적혀 있다 — `\\\\` 형태는 parse 절이 하나일 때만 맞고 두 번째 parse 가 붙으면 결과 행이 달라지는 것을 실제 로그 그룹으로 확인했다.
JSON 형태에서 uri/path 끝에 남는 `\` 는 백엔드(`cleanUri`/`cleanPath`)에서 떼어낸다.

## 2. 엔드포인트와 응답 코드 (바이너리가 낼 수 있는 모든 값)

### user (`MYSQL_USER` `MYSQL_PASSWORD` `MYSQL_HOST` `MYSQL_PORT` `MYSQL_DBNAME`, 풀 20/20)

| 요청 | 코드 | message / 로그 |
|---|---|---|
| `POST /v1/user` body `{requestid,uuid,username,email,status_message}` 모두 `binding:"required"` | 400 | `Bad Request` (바인딩 실패) |
| | 500 | `Failed to begin transaction` (stderr `Failed to open DB: %v`) |
| | **403** | **`It already exists in a database.`** — `username` 중복(UNIQUE uk_username). **앱이 스스로 내는 403** 이다. WAF 차단이 아니다 |
| | 500 | `Internal server error` (stderr `Failed to query DB: %v`) |
| | 500 | `Failed to commit transaction` (stderr `Failed to commit DB: %v`) |
| | **201** | `Created an user` |
| `GET /v1/user?email=…&requestid=…&uuid=…` (셋 다 필수) | 400 | `Bad Request` |
| | 500 | `DB query failed` (stderr `query error: %v`) |
| | 404 | `User not found` |
| | **200** | `Get an user information.` |

GET 은 DB 조회 전에 0~100 사이 난수만큼 `time.Sleep` 한다 (지연 분포에 인위적 꼬리가 있다).
**이메일 포맷은 검사하지 않는다** — 과제가 요구하는 "xxxx@xxxx.xxxx 가 아니면 403" 은 WAF(또는 앞단)가 내야 한다.

### product (`AWS_REGION` `TABLE_NAME`, 선택 `TABLE_INDEX_NAME`)

| 요청 | 코드 | message / 로그 |
|---|---|---|
| `POST /v1/product` body `{requestid,uuid,id,name,price}` | 400 | `Bad Request` |
| | **500** | **`Consumed resources by malicious attacks`** — 헤더 `User-Agent: Attacker-Bot` 일 때. stdout 에 `Consumed resources by malicious attacks.` 한 줄을 찍는다. **과제의 "비정상 요청" 그 자체** — 앱까지 오면 이미 실패다(500). WAF 가 403 으로 막아야 한다 |
| | 500 | `Internal server error` (stdout `Error: …`, DynamoDB PutItem 실패) |
| | **201** | `created a product.` |
| `GET /v1/product?id=…&requestid=…&uuid=…` | 400 | `Bad Request` |
| | 500 | `Internal server error` / `dynamodb unmarshal failed` |
| | 404 | `product not found` |
| | **200** | `Get a product information.` |

GET 도 0~100 난수 sleep 이 있다.

### stress

| 요청 | 코드 | message |
|---|---|---|
| `POST /v1/stress` body `{requestid,uuid,length}` | 400 | `Bad Request` |
| | **201** | `generated cpu load` — goroutine 4개로 `math.Pow` 를 `length` 만큼 돌린다 |

`GET /v1/stress` 는 라우트가 없어 gin 기본 `404 page not found` 다. 샌드박스의 정상 요청은 그래서 stress 만 POST 다.

## 3. 채점 키 (3과제_채점기준.hwp) 와 대시보드 `채점기 입력값` 카드의 대응

| 채점 항목 | 배점 | 대시보드 줄 | 출처 | 계산 |
|---|---|---|---|---|
| image download ≥ 50…90 % | 2 | `image download` | 앱 로그 | `/images/…` 요청 중 2xx 이고 5초 이내 / 전체 |
| Exception Handling ≥ 50…90 % | 2 | `Exception Handling` ≈ | WAF 로그 + 앱 로그 | (서비스 경로 BLOCK + 미지정 경로 404) / (그 합 + 앱까지 샌 비정상 요청 + 404 로 안 끝난 미지정 경로 + WAF 가 막아 403 이 된 미지정 경로) |
| (user/product/stress) availability ≥ 30…90 % | 12 | `(<api>) availability` | 앱 로그 | 2xx 이고 5초 이내 / 그 경로 전체 |
| (user/product/stress) performance ≥ 30…90 % | 12 | `(<api>) performance ≤ 0.2s / ≤ 1.0s` | 앱 로그 | 2xx 이고 SLO 이내 / 전체 |
| 인스턴스 비용 ratio 0.5 ~ 3.75 | 12 | 노드 수 비용 패널 | EC2 | 허용 타입 **`t3.medium`** (문제지 §7, `ALLOWED_INSTANCE_TYPE` 로 변경 가능) |

채점 문턱은 availability·performance 가 90 / 87.5 / 85 / 82.5 / 80 / 70 / 50 / 30 %,
image download·Exception Handling 이 90 / 85 / 80 / 50 % 다. 하나 넘을 때마다 0.5점이라
대시보드가 각 줄에 **지금 구간과 다음 문턱까지 남은 %p** 를 같이 찍는다.

주의할 점:

* 분모가 앱 로그 전체라 **앱이 스스로 내는 403(username 중복)·400·500 도 availability 분모에 들어간다.** 채점기는 자신이 보낸 요청만 센다.
* 응답 시간·코드는 **클라이언트 도착 기준**으로 채점된다. 앱 로그의 지연은 앱 내부 처리 시간이라 ALB·CloudFront·네트워크 구간이 빠져 있다 — 대시보드 값은 채점기보다 항상 낙관적이다.
* "≈" 가 붙은 줄은 분모 일부가 관측 불가다. 비율보다 **건수가 움직이는지**를 본다.
* cost ratio 는 채점기가 자기 기준으로 계산한다. 대시보드는 노드 대수와 1대 증감 효과만 보여주고 ratio 를 추정하지 않는다.

## 4. 과제 환경 (2026 문제지)

* 컴퓨트: **EKS + EC2(`t3.medium` 만)**. **ECS 사용 불가**, Fargate·Lambda 는 어떤 목적으로도 사용 불가.
  엔드포인트 하나로 단일화하고 프로토콜+호스트만 채점 플랫폼에 등록(경로 기입 금지).
* DB: RDS MySQL 8.0 `apdev-rds-instance` · db.t3.micro · Multi-AZ · gp3, `load_user.dump` 로 적재.
* 정적: S3 이미지를 같은 엔드포인트의 `/images/<object path>` 로 제공. 가용성·SLO 모두 5초.
* 응답 계약: 서비스 경로의 비정상 요청 → **403**, 제공하지 않는 경로 → **404**.
* 트래픽: 경기 시작 1시간 뒤부터 2시간. 경기 시간 3시간, 모든 시간 KST.

> **연도 차이 주의.** 이 문서 1~2절(로그 형식·바이너리 동작)은 2025 바이너리를 디스어셈블해 얻은
> 것이고 2026 과제도 같은 Go/Gin 바이너리를 쓰므로 그대로 유효하다. 반면 3절 채점 키와 4절 환경은
> **2026 문제지·채점기준 기준으로 갱신**했다 — 2025 는 ECS + `c5.large` 였고 채점 키 이름도 달랐다.
> 대시보드는 2026 기준으로 맞춰져 있다.
