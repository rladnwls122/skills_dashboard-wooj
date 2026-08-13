# 07 — 앱 로그와 WAF 로그를 requestid로 조인할 수 있는가

Type: research
Status: resolved
Blocked by: —
Parent: ../map.md

## Question

과제는 모든 요청에 `requestid`, `uuid` 쿼리스트링을 붙인다. WAF 로그(`WAF_LOG_GROUP`)와 앱 로그
(`APP_LOG_GROUP`)가 둘 다 CloudWatch Logs에 있으므로, 이 키로 두 로그를 묶으면 **한 요청의 WAF 판정과
앱 응답 코드를 한 행에서** 볼 수 있다. 이게 실제로 가능한지, 비용이 얼마인지 확인한다.

확인할 것:

1. **키가 양쪽에 실제로 남는가**
   - 앱 로그의 구조화 JSON `path` 필드에 쿼리스트링이 포함되는가? (`src/lib/server/logfields.ts`의
     `PARSE_FIELDS`가 뽑는 `path`. `requestlog.ts`는 `.split("?")[0]`으로 버리고 있다.)
     실제 로그 이벤트 원문 샘플로 확인할 것 — 추측하지 말 것.
   - WAF 로그의 `httpRequest.args`에 쿼리스트링 전체가 남는가? 길이 잘림은 없는가?
2. **Logs Insights로 조인을 흉내낼 수 있는가**
   - 한 쿼리에서 두 로그 그룹을 동시에 스캔할 수 있는가 (`logGroupNames` 복수 지정, 상한 몇 개까지).
   - Insights에 `JOIN` 문법이 없으므로 `parse`로 양쪽에서 `requestid`를 뽑고
     `stats ... by requestid` + 조건부 집계로 묶는 방식이 실제로 동작하는가.
     `@log` 필드로 어느 그룹에서 온 이벤트인지 구분되는가.
   - 실행 가능한 쿼리 문자열을 하나 만들어서 결과 샘플과 함께 남긴다.
3. **커버리지 한계**
   - POST/PUT은 `requestid`가 JSON 바디에 있어 WAF 로그에 없다 — GET만 조인된다는 게 맞는가?
     WAF 로깅에서 바디 일부를 남기는 옵션(`RequestBody` 관련 필드)으로 우회 가능한가, 그 비용은?
   - 조인 못 하는 요청의 비율이 실제 트래픽에서 얼마나 되는가 (POST 비중).
4. **비용** — 두 그룹을 함께 스캔할 때의 스캔 바이트, 1시간/4시간 창에서의 대략치.
   갱신 주기를 얼마로 두면 감당 가능한가.

**이 조사가 결정하는 것**: `04`의 오탐 판정 기준. 조인이 되면 "COUNT 규칙에 걸렸는데 앱이 2xx로 답한 요청 수"가
곧 오탐 건수가 되어 승격 판단이 숫자로 떨어진다. 안 되면 다른 기준을 세워야 한다.

결론은 "① GET 조인 가능, 쿼리는 이것" / "② 불가, 이유는 이것" 중 하나로 떨어져야 한다.
`WAF_LOG_GROUP`/`APP_LOG_GROUP`이 설정돼 있지 않거나 로그가 비어 있으면 그 사실을 명시하고
문서 근거로 가능 여부만 판정한다.

## 중간 사실 (앱 쪽, 실측 완료 2026-08-14)

`provided/stress` 바이너리를 WSL에서 직접 띄우고 요청을 넣어 로그 원문을 확보했다. AWS 접근 불필요.

```json
{"app":"stress","client_ip":"127.0.0.1","latency_ms":0.048,"method":"GET","path":"/v1/stress",
 "requestid":"999999999999","status":404,"ts":"2026-08-14T00:29:00.092658645+09:00",
 "uuid":"7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729"}
```

확정된 것:

1. **`requestid`와 `uuid`가 별도 JSON 필드로 찍힌다.** `path`는 쿼리스트링이 제거된 순수 경로다.
   즉 조인 키는 앱 쪽에 이미 1급 필드로 존재하며, `path`를 파싱할 필요가 없다.
2. **POST/PUT은 조인 불가 — 앱 쪽에도 없다.** 바디에 `requestid`를 담아 POST하면 로그에
   `"requestid":""`로 빈 값이 찍힌다. 앱은 이 두 값을 **쿼리스트링에서만** 읽는다.
   따라서 GET 요청만 조인 가능하고, 이건 WAF 로깅 설정으로 우회할 수 있는 문제가 아니다.
3. `app` 필드가 `user`/`product`/`stress`를 구분한다. `ts`는 KST 오프셋이 붙은 RFC3339.
   `status`, `client_ip`, `latency_ms`도 필드로 존재한다.
4. 앱이 미지정 경로(`/v1/none`)와 미정의 메소드(GET `/v1/stress`)에 **이미 404를 낸다.**
   404 요구사항은 앱만으로 충족되며, WAF가 그 요청을 Block하지만 않으면 된다.
5. 이 저장소의 `src/lib/server/logfields.ts` `PARSE_FIELDS`는 `latency_ms`/`method`/`path`/`status`만
   뽑는다. **`requestid`/`uuid` 추출을 추가해야 조인이 열린다.**

남은 조사: WAF 로그 쪽 (`httpRequest.args`의 내용과 잘림 여부), Logs Insights의 다중 로그 그룹 스캔과
`stats ... by requestid` 조인 흉내, 비용. 전부 문서로 판정 가능하며 실측이 필요 없다.

## Answer

**GET 조인 가능.** 단 방식이 처음 가정과 다르고, 리전 제약 때문에 한 쿼리로는 못 한다.

전체 조사 결과: [research/07-log-join.md](../research/07-log-join.md)

### 확정된 것

- WAF 로그 `httpRequest.args`는 쿼리스트링 **전문**을 담고 문서상 잘림 한도가 없다
  (잘림이 명시된 건 `labels` 100개와 `customValues` 32자뿐).
- **COUNT 판정은 `action`이 아니라 `nonTerminatingMatchingRules`에 나온다.**
  그것도 최상위와 `ruleGroupList[]` **두 군데**에 나타나므로 양쪽을 다 봐야 한다.
- WAF는 **바디를 전혀 로깅하지 않는다** → POST/PUT 우회는 확정적으로 불가능.
  앱 로그도 POST의 `requestid`를 빈 값으로 남기므로(위 중간 사실), **GET 전용이 최종이다.**
- 앱 로그는 Fluent Bit이 감싸서 `log` 필드 안의 **JSON 문자열**이다 → dot notation이 안 통하고
  반드시 `parse`가 필요하다. 이 저장소의 `PARSE_FIELDS`가 이미 그렇게 하고 있는 이유다.
- Logs Insights에 네이티브 `join`이 생겼지만 **이 용도로는 못 쓴다** — 오른쪽에 서브쿼리를 못 붙이는데
  `requestid`는 양쪽 다 `parse`가 필요하다. `stats ... by requestid` + 조건부 집계가 여전히 정답.

### 리전 제약과 그 해결

`.env.example`이 `WAF_SCOPE=CLOUDFRONT`다. Web ACL이 CloudFront 스코프면 us-east-1 소속이고,
**WAF 로그 그룹은 Web ACL과 같은 리전**이어야 한다. 앱 로그는 ap-northeast-2에 있다.
**Logs Insights는 리전을 넘지 못하므로 한 쿼리로는 조인이 불가능하다.**

선택지 셋 중 **대시보드 코드에서 병합**으로 간다:

1. us-east-1에서 WAF 로그를 조회하되 **COUNT 매칭된 요청만** 뽑는다 (`nonTerminatingMatchingRules`가
   비어있지 않은 것). 이 집합은 작다.
2. 거기서 나온 `requestid` 목록으로 ap-northeast-2 앱 로그를 조회한다.
3. TypeScript에서 `requestid`로 묶는다.

인프라(WAF를 ALB에 붙여 REGIONAL로 전환, Firehose 크로스 리전 전달)를 건드리는 대안은 **범위 밖**이고,
어차피 우리 코드에서 두 번 조회해 합치는 게 더 싸다 — COUNT 매칭 집합만 넘어다니므로 스캔량도 작다.

### 구현 시 밟을 지뢰 (전부 실측 확인됨)

- 결과 행이 **sparse** — 없는 컬럼은 0이 아니라 **키 자체가 사라진다**. `undefined` 처리 필수.
- `limit` 생략 시 **경고 없이 10,000행에서 조용히 절단**된다. 피크 시간당 42만 요청이므로
  `by requestid`로 묶은 결과는 반드시 집계 한 행으로 접어야 한다.
- `stats` alias와 `parse` 필드명이 충돌하면 쿼리가 거부된다.
- 비용은 문제가 아니다: 서울 $0.0076/GB, 피크 1시간 앱 그룹 스캔 0.46 GB.
  **1시간 창 + 60초 갱신으로 2시간 대회 전체 약 $1.2.** 동시 실행 100·타임아웃 60분이라 쿼터 여유.
- 이벤트당 1,067 B 중 **80%가 앱 로그가 아니라 k8s 메타데이터**다 — 스캔량을 줄이려면 여기가 표적.

### 검증 조건

WAF Web ACL과 로그 그룹은 조사 시점에 **실제로 존재하지 않았다**(`list-web-acls` 빈 배열,
`aws-waf-logs-` 그룹 0개). WAF 필드 관련은 전부 문서 근거다. 반면 **앱 로그 그룹은 살아 있어**
Insights 역학(다중 그룹 스캔, `@log` 출처 식별, `parse` 무시 동작, `sum(불리언)` 조건부 집계,
sparse 결과, 조용한 절단)은 전부 실데이터로 검증했다.
