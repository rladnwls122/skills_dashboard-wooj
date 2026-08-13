# 07 — 앱 로그와 WAF 로그를 requestid로 조인할 수 있는가 (WAF 쪽 + 쿼리 역학)

조사일: 2026-08-14 · 대상 계정: 600440344359 / ap-northeast-2
앞선 앱 쪽 실측(`issues/07-log-join.md`의 "중간 사실")은 그대로 유효하며 재검증하지 않았다.

---

## 결론: **① GET 조인 가능**

GET 요청에 한해 WAF 판정과 앱 응답 코드를 `requestid` 기준 한 행으로 묶을 수 있다.
문서 근거와 실측이 모두 일치한다.

근거 요약:

1. WAF 로그의 `httpRequest.args`는 **쿼리스트링 전문**을 담고, **문서상 어떤 길이 제한도 없다.**
   `~120자` 쿼리스트링이 잘릴 근거는 AWS 문서 어디에도 없다. 잘림이 문서화된 필드는
   `labels`(첫 100개)와 `customValues`(첫 32자)뿐이다.
2. Logs Insights 한 쿼리로 **최대 50개** 로그 그룹을 동시에 스캔할 수 있고,
   `@log`가 `account-id:log-group-name` 형태로 출처 그룹을 알려준다. **실측 확인함.**
3. `parse` + `stats ... by requestid` 조건부 집계 방식이 실제로 동작한다. **실측 확인함.**
4. 비용은 문제가 되지 않는다. 실측 기준 1시간 창 왕복 스캔이 **약 $0.01**,
   2시간 대회 내내 60초 주기로 돌려도 **$1.2 수준**이다.

**단, 티켓 전제 두 개가 틀렸으니 먼저 정정한다.**

### 정정 A — Logs Insights에는 이제 `JOIN`이 있다 (하지만 이 용도로는 못 쓴다)

티켓은 "Insights에 `JOIN` 문법이 없으므로"를 전제로 깔았으나, 현재 Logs Insights QL에는
네이티브 `join` 커맨드가 존재한다. ap-northeast-2에서 **실제로 동작하는 것까지 확인했다**
(아래 Q4 참조). 그럼에도 **이 조인에는 쓸 수 없다.** 이유:

> Subqueries on right side of join are not supported.
> Join keys must exist in both data sources and be of compatible types.

`requestid`는 **양쪽 모두 직접 참조 가능한 필드가 아니다.**
WAF 쪽은 `httpRequest.args` 문자열 안에, 앱 쪽은 Fluent Bit이 감싼 `log` JSON **문자열** 안에 들어 있다.
둘 다 조인 전에 `parse`가 필요한데, `join`의 오른쪽에는 서브쿼리를 붙일 수 없다.
→ **`stats ... by requestid` 방식이 여전히 정답이다.** `parse`는 `stats`보다 먼저,
다중 로그 그룹 전체 이벤트에 대해 실행되므로 이 제약을 받지 않는다.

### 정정 B — 앱 로그 필드는 "직접 주소지정 가능"하지 않다

과제 지시문은 "앱 쪽은 JSON이라 필드를 바로 쓸 수 있다"고 했지만, **CloudWatch에 실제로 적재된 형태는 다르다.**
`APP_LOG_GROUP`은 Container Insights 그룹(`/aws/containerinsights/skills-eks/application`)이고,
Fluent Bit이 컨테이너 stdout 한 줄을 감싸서 넣는다:

```json
{"time":"...","stream":"stderr","_p":"F",
 "log":"{\"app\":\"product\",\"client_ip\":\"10.0.2.187\",\"latency_ms\":0.006,\"method\":\"GET\",\"path\":\"/healthcheck\",\"requestid\":\"\",\"status\":200,\"ts\":\"...\",\"uuid\":\"\"}",
 "kubernetes":{"pod_name":"...","namespace_name":"default","container_name":"product", ...}}
```

앱의 JSON은 `log` 필드의 **문자열 값**이다. 실측으로 확인한 바:
`kubernetes.container_name`은 dot notation으로 정상 조회되지만(중첩 JSON 객체이므로),
`requestid` / `status` / `path`는 **아무것도 반환하지 않는다.** 문서도 이를 명시한다:

> Dot notation traverses only fields that are stored as structurally nested JSON objects at ingest time.
> If a field's value is a JSON-encoded string (a string whose content happens to be valid JSON),
> dot notation treats it as an opaque leaf value and does not access sub-fields within it.

따라서 앱 쪽은 반드시 `parse log /.../` 를 거쳐야 한다. 이 저장소의
`src/lib/server/logfields.ts`가 이미 정확히 그렇게 하고 있다(`PARSE_FIELDS`).
여기에 `requestid` 추출을 추가하면 조인이 열린다 — 티켓 "중간 사실" 5번과 일치.

---

## 실행 가능한 쿼리

`ap-northeast-2`, 두 로그 그룹 동시 스캔. **문법 검증 완료**(StartQuery가 수락하고 `Complete`로 끝남).

```
fields @timestamp
| parse log /"requestid":"(?<rid_app>[^"]+)"/
| parse log /"status":(?<st>\d+)/
| parse log /"path":"(?<pth>[^"]*)"/
| parse log /"app":"(?<svc>[^"]*)"/
| parse httpRequest.args /requestid=(?<rid_waf>[^&"]+)/
| parse @message /"ruleId":"(?<cnt_rule>[^"]*)","action":"COUNT"/
| fields coalesce(rid_app, rid_waf) as requestid
| filter ispresent(requestid)
| stats latest(action)             as waf_action,
        latest(terminatingRuleId)  as waf_terminating_rule,
        latest(cnt_rule)           as waf_count_rule,
        latest(st)                 as app_status,
        latest(pth)                as app_path,
        latest(svc)                as app_name,
        count(*)                   as events
        by requestid
| sort events desc
| limit 200
```

실행:

```bash
aws logs start-query --region ap-northeast-2 \
  --log-group-names "$WAF_LOG_GROUP" "$APP_LOG_GROUP" \
  --start-time $(($(date +%s) - 3600)) --end-time $(date +%s) \
  --query-string file://join.txt
```

동작 원리 — 각 `parse`는 해당 필드가 없는 이벤트에서 **조용히 무시된다**(실측 확인).
그래서 WAF 이벤트는 `rid_waf`만, 앱 이벤트는 `rid_app`만 채워지고, `coalesce`가 둘을 하나의
`requestid`로 합친다. `stats ... by requestid`가 같은 요청의 두 이벤트를 한 그룹으로 모으면,
`latest()`가 각 그룹에서 WAF 쪽 필드와 앱 쪽 필드를 각각 끌어온다. `events`가 2면 양쪽 다 잡힌 것,
1이면 한쪽만 잡힌 것이다.

### 04가 실제로 필요로 하는 형태 — 오탐 건수 한 줄

"COUNT 규칙에 걸렸는데 앱이 2xx로 답한 요청 수". 위 쿼리를 한 번 더 `stats`로 접는다
(한 쿼리에 `stats`는 최대 10개까지 허용된다):

```
fields @timestamp
| parse log /"requestid":"(?<rid_app>[^"]+)"/
| parse log /"status":(?<st>\d+)/
| parse httpRequest.args /requestid=(?<rid_waf>[^&"]+)/
| parse @message /"ruleId":"(?<cnt_rule>[^"]*)","action":"COUNT"/
| fields coalesce(rid_app, rid_waf) as requestid
| filter ispresent(requestid)
| stats latest(cnt_rule) as rule, latest(st) as status by requestid
| stats count(*)                                    as joined,
        sum(ispresent(rule))                        as waf_count_matched,
        sum(ispresent(rule) and status >= 200 and status < 300) as false_positives,
        sum(ispresent(rule) and status >= 400)      as true_positives
```

`sum(<불리언 식>)` 조건부 집계는 **문서에 예시가 없지만 실제로 동작한다** — 실측으로 확인했다
(`sum(strcontains(app_name,"stress"))` → 814, `sum(st >= 200 and st < 300)` → 2440).
문서에는 `if(condition, trueValue, falseValue)`와 `case(...)`가 "다른 함수의 인자로 쓸 수 있다"고만
적혀 있어 `sum(if(cond,1,0))` 형태도 가능하다. 불리언 직접 전달이 더 짧고 실측으로 검증됐다.

---

## 질문별 근거

### Q1. WAF 로그 스키마

CloudWatch Logs로 전달되는 WAFv2 로그 이벤트는 단일 JSON 문서이며, Insights가 dot notation으로
중첩 필드를 자동 발견한다(`httpRequest.uri`, `httpRequest.args` 모두 직접 참조 가능 — WAF 로그는
진짜 중첩 JSON 객체라서 정정 B의 함정에 걸리지 않는다).

**`httpRequest.uri`** — 문서 전문은 딱 한 줄이다:

> **uri** — The URI of the request.

쿼리스트링 포함 여부는 **문서에 명시되어 있지 않다.** 다만 `args`가 별도 필드로 존재하고,
`logging-examples.html`의 여덟 개 예시 전부가 `"uri":"/myUri"` 와 `"args":""` 를 나란히 보여주므로
**경로만 담는다고 보는 것이 타당하다**(명시적 문서 근거가 아닌 추론임을 밝혀 둔다).

**`httpRequest.args`** — 역시 한 줄이다:

> **args** — The query string.

**잘림 없음.** `logging-fields.html` 전체에서 `uri`/`args`에 대한 truncation·byte limit·character limit
기술은 **존재하지 않는다.** 해당 페이지의 "첫 N개" 문구는 단 두 곳뿐이다:

> **labels** — ... AWS WAF logs the first 100 labels.
> **customValues** — ... For string values, the logs print the first 32 characters of the string value.

WAF 쪽 쿼터 페이지(`limits.html`)에도 로그 레코드 크기 쿼터가 없다. 8 KB / 16 KB / 64 KB 제한은
**inspection(검사) 한도**이지 logging 한도가 아니며, 초과 시 `oversizeFields`에 마커만 남는다.
→ **~120자 쿼리스트링은 절대 잘리지 않는다.**

**판정 필드**:

| 필드 | 의미 |
|---|---|
| `action` | **terminating action만** — `ALLOW`/`BLOCK`/`CAPTCHA`/`CHALLENGE`. **여기에 `COUNT`는 절대 안 나온다.** |
| `terminatingRuleId` | 요청을 종료시킨 규칙 ID. 아무것도 종료시키지 않으면 `Default_Action` |
| `terminatingRuleType` | `RATE_BASED` / `REGULAR` / `GROUP` / `MANAGED_RULE_GROUP` |
| `terminatingRuleMatchDetails` | **SQLi/XSS 매치 구문에서만 채워진다.** byte-match·regex·rate 규칙은 `[]` |
| `nonTerminatingMatchingRules` | ← **COUNT 규칙 매치가 여기 나온다** |
| `ruleGroupList` | 룰 그룹별 매치 정보. 각 항목이 자체 `nonTerminatingMatchingRules`와 `excludedRules`를 가짐 |
| `labels` | 규칙들이 붙인 라벨. 첫 100개만 |

**"COUNT 규칙이 매치했지만 종료시키지 않았다"를 알려주는 필드 = `nonTerminatingMatchingRules`.**
문서:

> **nonTerminatingMatchingRules** — The list of non-terminating rules that matched the request.
> **action** — The action that AWS WAF applied to the request. This indicates either count, CAPTCHA, or challenge.

문서 예시(비종료 COUNT):

```json
"nonTerminatingMatchingRules":[{"ruleId":"TestRule","action":"COUNT","ruleMatchDetails":[...]}]
```

**중요한 함정 — COUNT는 두 군데에 나타난다:**

| 경우 | 나타나는 위치 |
|---|---|
| Web ACL 최상위 규칙의 action이 Count | **최상위** `nonTerminatingMatchingRules[]` |
| 룰 그룹 안 규칙이 원래 Count | `ruleGroupList[].nonTerminatingMatchingRules[]` |
| 룰 그룹 규칙을 `RuleActionOverrides`로 Count 오버라이드(현행) | `ruleGroupList[].nonTerminatingMatchingRules[]`, `overriddenAction` 동반 |
| 레거시 `ExcludedRules`(2022-10-27 이전) | `ruleGroupList[].excludedRules[]`, `exclusionType: EXCLUDED_AS_COUNT` |

문서 예시가 이를 직접 보여준다 — 최상위 `nonTerminatingMatchingRules`가 `[]`인데
`ruleGroupList[0].nonTerminatingMatchingRules`에 COUNT 매치가 들어 있는 케이스가 있다.
**최상위만 읽는 파서는 룰 그룹 COUNT를 전부 놓친다.**

위 쿼리가 `parse @message /"ruleId":"(?<cnt_rule>[^"]*)","action":"COUNT"/` 로 정규식을 쓰는 이유가
이것이다. 두 위치 모두 `{"ruleId":"X","action":"COUNT",...}` 라는 동일한 형태를 갖기 때문에
정규식 하나로 양쪽을 다 잡는다. `nonTerminatingMatchingRules.0.ruleId` 같은 배열 인덱스 표기도
문서상 유효하지만(`requestParameters.instancesSet.items.0.instanceId` 예시), 최상위만 잡히므로
정규식 쪽이 안전하다.

참고로 `EXCLUDED_AS_COUNT`는 `action` 필드의 값으로는 나오지 않는다 — 로깅 필터
(`ActionCondition`)의 valid value일 뿐이다: `ALLOW | BLOCK | COUNT | CAPTCHA | CHALLENGE | MONETIZE | EXCLUDED_AS_COUNT`.

### Q2. Redaction / 필드 제한

**`RedactedFields`** (`PutLoggingConfiguration`):

> You can specify only the following fields for redaction: `UriPath`, `QueryString`, `SingleHeader`, and `Method`.
> Array Members: Maximum number of 100 items.

> Redacted fields appear as `REDACTED` in the logs.

즉 `QueryString`을 redact하면 `args`가 통째로 `REDACTED`가 되어 **조인 키가 사라진다.**
→ **`WAF_LOG_GROUP` 로깅 설정에 `QueryString` redaction을 절대 넣지 말 것.** 이게 조인을 깨는
유일한 현실적 위험이다.

단 redaction은 **조건부**라는 점이 중요하다:

> Redaction applies only to the component that's specified in the rule's `FieldToMatch` setting,
> so the `SingleHeader` redaction doesn't apply to rules that use the `Headers` `FieldToMatch`.

무조건 제거가 필요하면 별도 기능인 data protection(치환 또는 해싱)을 쓴다. 이것도 마찬가지로
조인 키를 죽이므로 켜지 말 것.

**크기 상한**: WAF 쪽에는 로그 레코드 크기 쿼터가 **문서화되어 있지 않다.**
하류의 CloudWatch Logs 쿼터만 적용된다 — `Event size: 1,024 Kilobytes`.
~120자 쿼리스트링과는 6자리 자릿수 차이라 무관하다.

**로그 그룹 이름 규칙**:

> Your log group names must start with `aws-waf-logs-` and can end with any suffix you like.

그리고 Web ACL과 **같은 리전, 같은 계정**이어야 한다.

**바디 로깅 — 불가.** `logging-fields.html`의 필드 목록에 body 관련 필드가 **하나도 없다.**
`httpRequest`의 하위 필드는 clientIp/country/headers/uri/args/fragment/httpVersion/httpMethod/requestId로
끝난다. 문서의 POST + JSON 바디 예시조차 `"uri":""`, `"args":""`에 바디는 어디에도 없다.
바디 근처까지 가는 유일한 필드는 SQLi/XSS 매치에서만 채워지는 `terminatingRuleMatchDetails.matchedData`
(매치된 토큰만)와, 검사 한도 초과 마커인 `oversizeFields`(`REQUEST_BODY` 등 문자열만)다.

→ **티켓의 "WAF 로깅에서 바디 일부를 남기는 옵션으로 우회 가능한가?" 에 대한 답은 명확히 "불가".**
POST/PUT은 어떤 WAF 로깅 설정으로도 조인할 수 없다. 앱 쪽에서도 안 남는다는 기존 실측과 합쳐,
**GET-only는 확정된 한계**다.

**전달 보장** — 참고로 100% 보장은 아니다:

> On rare occasions, it's possible for AWS WAF log delivery to fall below 100%, with logs delivered
> on a best effort basis. ... this can result in records being dropped. This shouldn't affect more than a few records.

`LoggingFilter`로 로깅 대상을 줄일 수 있다(`DefaultBehavior: KEEP|DROP` + action/label 조건).
COUNT 매치만 남기도록 필터링하면 WAF 로그 볼륨과 스캔 비용을 크게 줄일 수 있다.

### Q3. 다중 로그 그룹 스캔 — **가능, 실측 확인**

**최대 50개.** (티켓이 참조했을 20이라는 숫자는 옛 값이다.)

> The list of log groups to be queried. You can include up to 50 log groups. — `logGroupNames`
> The list of log groups to query. You can include up to 50 log groups. — `logGroupIdentifiers`

실측: 이 계정의 로그 그룹 10개 전부를 한 쿼리에 넣어 정상 수락됨.
2개 그룹 동시 쿼리에서 `statistics.logGroupsScanned: 2` 확인.

**`@log`가 출처를 알려준다:**

> `@log` is a log group identifier in the form of `{{account-id}}:{{log-group-name}}`.
> When querying multiple log groups, this can be useful to identify which log group a particular event belongs to.

실측 반환값: `600440344359:/aws/containerinsights/skills-eks/application`. `@logStream`도 함께 나온다.
주의: 필드 자동 발견은 **Standard 로그 클래스에서만** 지원된다(Infrequent Access 불가).

**`logGroupNames` vs `logGroupIdentifiers`:**

> A `StartQuery` operation must include exactly one of the following parameters:
> `logGroupName`, `logGroupNames`, or `logGroupIdentifiers`.

셋은 상호 배타적이다. 차이가 실제로 문제되는 경우:

> If a log group that you're querying is in a source account and you're using a monitoring account,
> you must specify the ARN of the log group here. ... If you specify an ARN, use the format
> `arn:aws:logs:region:account-id:log-group:log_group_name` Don't include an `*` at the end.

즉 **ARN을 받는 건 `logGroupIdentifiers`뿐**이고, 크로스 계정(모니터링 계정 → 소스 계정)에서는 필수다.
길이 제한도 다르다: `logGroupNames` 512자 / `logGroupIdentifiers` 2048자.
**이 과제는 단일 계정이므로 `--log-group-names`로 충분하다.** 실측에서 ARN을 넘긴
`--log-group-identifiers`도 정상 동작함을 확인했다.

### Q4. JOIN 흉내 — 동작 확인

**`stats ... by requestid` 방식이 동작한다. 실측으로 검증한 항목:**

1. **없는 필드에 대한 `parse`는 조용히 무시된다.** `parse httpRequest.args /.../` 를
   `httpRequest`가 존재하지 않는 로그 그룹에 걸어도 에러 없이 `Complete`로 끝나고,
   해당 컬럼만 결과에서 빠진다. → 한 쿼리에 WAF 전용 parse와 앱 전용 parse를 섞어도 안전하다.
2. **`latest()`는 문자열에도 동작한다.** 문서상 aggregation function이 아니라
   "stats non-aggregation function"으로 분류되어 있다(따라서 시각화는 안 된다).
3. **`sum(<불리언>)` 조건부 집계가 동작한다** (문서에 예시 없음, 실측 검증).
   `parse`로 뽑은 문자열 숫자에 `st >= 200` 같은 수치 비교도 정상 동작한다(자동 형변환).

**반드시 알아야 할 함정들 (전부 실측):**

- **결과 행은 sparse다 — 없는 컬럼은 `0`이나 빈 문자열이 아니라 아예 빠진다.**
  이게 가장 위험하다. 실측 결과:

  ```json
  [{"field":"app_name","value":"product"},{"field":"n","value":"1653"}]
  [{"field":"app_name","value":"stress"},{"field":"n","value":"1654"},{"field":"marker","value":"stress"},{"field":"cnt_marker","value":"1654"}]
  ```

  `product` 행에는 `marker`도 `cnt_marker`도 **키 자체가 없다.** `count()`가 0을 반환하지 않고
  컬럼이 사라진다. → WAF 이벤트가 없는 `requestid` 그룹은 `waf_action` 키가 아예 없는 행으로 온다.
  **소비자 코드는 결과를 고정 스키마/고정 컬럼 순서로 파싱하면 안 되고, 필드명으로 조회한 뒤
  없으면 null로 취급해야 한다.** (단 `sum(불리언)`은 피연산 필드가 그룹 내에 존재하기만 하면
  거짓일 때 `0`을 정상 반환한다 — 실측에서 `n_4xx: 0` 확인.)

- **`stats` 출력 alias를 앞서 `parse`로 만든 필드명과 같게 두면 쿼리가 거부된다.**
  실측 에러: `MalformedQueryException: Ephemeral field is already defined: waf_rule`.
  그래서 위 쿼리가 `parse`에서 `cnt_rule`/`st`/`pth`/`svc` 같은 짧은 이름을 쓰고
  `stats`에서 `waf_count_rule`/`app_status`/... 로 이름을 바꾼다.

- **행 수 상한: 기본 10,000 / 최대 100,000.** 이게 이 조인의 실질적 제약이다.

  > If you omit `limit`, the query defaults to returning up to 10,000 log events.
  > You can specify a `limit` value of up to 100,000.
  > The maximum events returned in a single `GetQueryResults` API call is 10,000 log events per request.
  > You can retrieve up to 100,000 log event results from a query by paginating with the `nextToken`.

  실측: 413,246건이 매치되는 고카디널리티 `stats ... by`(고유 키 40만 개)를 `limit` 없이 돌리면
  **정확히 10,000행에 `status: Complete`** 로 끝난다 — **에러도 경고도 없는 조용한 절단.**
  `| limit 100000`을 붙이고 `nextToken`으로 6페이지를 돌자 60,000행이 나왔고 토큰이 더 남아 있었다.

  `requestid`는 요청당 고유하므로 카디널리티가 곧 요청 수다. 실측 피크가 **시간당 424,674 이벤트**였다.
  → **1시간 창 전체를 `by requestid`로 묶으면 10만 행 상한도 넘긴다.**
  반드시 `stats` 이전에 좁혀야 한다. 실용적으로는 위 "04가 필요로 하는 형태"처럼
  두 번째 `stats`로 접어 **한 행짜리 집계**로 만들거나, `filter`로 COUNT 매치 요청만 남기거나,
  창을 5~10분으로 줄인다. 집계 한 행으로 접는 쪽이 정답이다.

- **`filter`는 스캔량을 줄이지 않는다** (비용 절감이 아니라 결과 절감). 뒤 Q5 참조.
- 한 쿼리당 `stats`는 최대 10개. `sort`/`limit`은 마지막 `stats` 뒤에 와야 한다.
- `countDistinct`가 올바른 이름이다(`count_distinct` 아님). 고카디널리티에서는 근사값이다.
- `queryString` 최대 10,000자.
- **결과 데이터 1 MB 상한은 문서에 존재하지 않는다.** 쿼터 표의 1 MB는
  `put-log-events` 배치 크기로 무관하다.

**`join` 커맨드에 대하여** — 실재하고 ap-northeast-2에서 동작한다. 실측으로
`join type=inner left=a right=b where a.stream = b.stream (SOURCE '/aws/.../application')` 가
`a.@timestamp` / `a.@message` 접두 필드를 가진 실제 조인 행을 반환하는 것을 확인했다.
그러나 앞서 적었듯 **이 과제에는 쓸 수 없다** — 양쪽 조인 키가 모두 `parse`를 필요로 하는데
오른쪽에는 서브쿼리를 못 붙인다. 그 외 제약:

> Only one join command is supported per query.
> The number of unique key values in the secondary data source is limited to 50,000.
> Queries using join may scan more data and incur higher costs.

(참고: OpenSearch SQL 방언은 로그 그룹 간 `INNER`/`LEFT OUTER JOIN`을 지원하고
`jsonParse` 유사 기능도 있어 이론상 우회가 가능하나, 동시 실행 쿼터가 15로 낮고
`limit` 100,000이 CWLI 전용이라 이 대시보드 용도로는 이점이 없다.)

### Q5. 비용

**단가 — ap-northeast-2는 us-east-1보다 52% 비싸다.**

| 리전 | 단가 |
|---|---|
| us-east-1 | $0.0050 / GB |
| **ap-northeast-2 (서울)** | **$0.0076 / GB** |

(AWS Price List Bulk API, `productFamily: Data Payload`, `operation: StartQuery`,
`beginRange: 0` ~ `endRange: Inf` — **볼륨 티어 없는 정액**.)

> CloudWatch Logs Insights queries incur charges based on the amount of **uncompressed** log data scanned,
> regardless of query language.

**스캔 바이트를 결정하는 것**: 선택한 로그 그룹들의 시간 창 안 **비압축 원본 바이트 전체**다.
`filter`는 스캔량을 줄이지 않는다. 문서가 제시하는 감축 수단은 세 가지뿐이다 —
로그 그룹 수 줄이기, 시간 창 좁히기, 그리고 field index(단 `=`/`IN`에만 적용되고
`like`는 항상 전량 스캔). `limit any N`은 조기 종료로 실제 스캔을 줄인다.

**실측 (앱 로그 그룹, 피크 1시간, 2026-08-12 02:00–03:00 UTC):**

| 지표 | 값 |
|---|---|
| recordsScanned | 431,252 |
| bytesScanned | 460,227,146 B ≈ **0.46 GB** |
| 이벤트당 평균 | **약 1,067 B** |

이벤트당 1 KB는 Fluent Bit 래퍼 때문이다 — 앱이 찍는 원본 JSON은 ~200 B인데
`kubernetes` 메타데이터(pod_name, container_hash, container_image 등)가 800 B 가까이 붙는다.
**즉 스캔 비용의 80%는 앱 로그가 아니라 k8s 메타데이터다.**

WAF 로그 그룹은 현재 존재하지 않아 실측 불가. WAF 이벤트는 `headers` 배열이 커서
**이벤트당 약 2 KB로 추정**한다(추정치임을 명시). 같은 요청량 기준 시간당 약 0.85 GB.

**창 크기별 왕복 스캔 1회 비용 (피크 트래픽 기준):**

| 창 | 앱(실측) | WAF(추정) | 합계 | 비용 |
|---|---|---|---|---|
| 1시간 | 0.46 GB | 0.85 GB | ~1.31 GB | **약 $0.010** |
| 4시간 | 1.84 GB | 3.40 GB | ~5.24 GB | **약 $0.040** |

**2시간 대회 동안의 총액:**

| 창 / 갱신 주기 | 쿼리 수 | 총 비용 |
|---|---|---|
| 1시간 창 / 60초 | 120 | **약 $1.20** |
| 1시간 창 / 5분 | 24 | 약 $0.24 |
| 4시간 창 / 5분 | 24 | 약 $0.96 |

**권고: 1시간 롤링 창 + 60초 갱신.** 대회 전체 $1.2 수준이면 무시해도 되는 금액이고,
피크 트래픽을 가정한 상한이라 실제로는 더 낮게 나온다. 더 아끼고 싶다면 `LoggingFilter`로
WAF 쪽을 COUNT/BLOCK 매치 요청만 남기도록 걸면 WAF 스캔량이 한 자릿수 퍼센트로 떨어진다.

주의할 문서 경고:

> When you add a CloudWatch Logs Insights widget to a dashboard, ensure that the dashboard is not
> refreshing at a high frequency, because **each refresh starts a new query.**
> When you use the console to run queries, cancel all your queries before you close the console page.
> Otherwise, queries continue to run until completion.

**동시 실행 / 실행 시간 쿼터** — 전혀 제약이 안 된다:

| 항목 | 값 |
|---|---|
| 동시 실행 쿼리 (Logs Insights QL) | **100** (대시보드에 올린 쿼리 포함) |
| 동시 실행 쿼리 (PPL / SQL) | 15 |
| 쿼리 타임아웃 | **60분** |
| 쿼리 결과 보존 | 7일 |
| `StartQuery` 스로틀 | 10 TPS |
| `GetQueryResults` 스로틀 | 10 TPS |
| `nextToken` 만료 | 1시간 |

프리티어는 월 5 GB이나, **ingestion + archive storage + Insights 스캔이 공유**하는 할당량이라
이 규모에서는 사실상 기대할 수 없다.

---

## 환경 검증 결과

`aws logs describe-log-groups --region ap-northeast-2` 로 읽기 전용 확인 (2026-08-14):

| 로그 그룹 | storedBytes |
|---|---|
| `/aws/containerinsights/skills-eks/application` | 180,325,986 |
| `/aws/containerinsights/skills-eks/performance` | 106,446,822 |
| `/aws/containerinsights/skills-eks/dataplane` | 2,030,600 |
| `/aws/containerinsights/skills-eks/host` | 2,363,164 |
| `/aws/containerinsights/ishs-eks/*` | 4개, 합계 ~25 MB |
| `/aws/rds/proxy/skills-db-proxy`, `/aws/rds/proxy/ishs-db-proxy` | ~300 KB |

- **`WAF_LOG_GROUP`은 존재하지 않는다.** `aws-waf-logs-` 접두 그룹이 하나도 없다.
  `wafv2 list-web-acls`(REGIONAL, CLOUDFRONT)와 `wafv2 list-logging-configurations` 모두 빈 배열.
  → **WAF 쪽 필드는 전부 문서 근거로만 판정했고, 실측하지 않았다.**
- **`APP_LOG_GROUP`은 살아 있다** — `/aws/containerinsights/skills-eks/application`.
  클러스터는 내려갔지만 로그는 남아 있어(마지막 이벤트 2026-08-13 06:34 UTC)
  Logs Insights 역학은 전부 실제 데이터로 검증할 수 있었다.
- `.env.example`의 `WAF_LOG_GROUP=`은 비어 있고, 주석은 `aws-waf-logs-skills`를 예시로 든다.
  `WAF_SCOPE=CLOUDFRONT`이므로 Web ACL은 us-east-1에서 관리되지만,
  **CloudWatch 로그 그룹은 Web ACL과 같은 리전·계정이어야 한다** —
  CLOUDFRONT 스코프 Web ACL은 us-east-1 소속이므로 **로그 그룹도 us-east-1에 만들어야 한다.**
  앱 로그는 ap-northeast-2에 있다. **→ 두 로그 그룹이 서로 다른 리전에 놓인다.**

### 남은 위험 하나 — 리전 불일치

**Logs Insights 쿼리는 리전을 넘나들 수 없다.** `logGroupIdentifiers`의 크로스 계정 지원은
모니터링 계정 ↔ 소스 계정 이야기이지 크로스 리전이 아니다.
`WAF_SCOPE=CLOUDFRONT`를 유지하면 WAF 로그(us-east-1)와 앱 로그(ap-northeast-2)를
한 쿼리로 묶을 수 없다. 해결책 중 하나를 골라야 한다:

1. WAF를 ALB에 붙여 `WAF_SCOPE=REGIONAL` + ap-northeast-2 Web ACL로 간다 (가장 깔끔).
2. WAF 로깅 목적지를 Firehose로 바꿔 ap-northeast-2 로그 그룹으로 크로스 리전 전달한다.
3. 두 쿼리를 따로 날리고 애플리케이션 코드에서 `requestid`로 병합한다
   (Insights 조인 자체를 포기. 결과 행 수가 관리 가능하면 현실적).

**이건 문서로만 판정한 사항이고 실제 배포 구성을 보지 못했다.** WAF를 실제로 붙일 때
스코프와 로그 그룹 리전을 먼저 확인할 것. `04`로 넘기기 전에 정리되어야 하는 항목이다.

---

## 출처

**AWS WAF**

- 로그 필드 전체 목록 — https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
- 로그 이벤트 예시 (COUNT / 룰 그룹 / POST 바디) — https://docs.aws.amazon.com/waf/latest/developerguide/logging-examples.html
- 로깅 개요 — https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
- Redaction / 로깅 필터 / 전달 보장 — https://docs.aws.amazon.com/waf/latest/developerguide/logging-management.html
- CloudWatch Logs 목적지 및 `aws-waf-logs-` 이름 규칙 — https://docs.aws.amazon.com/waf/latest/developerguide/logging-cw-logs.html#logging-cw-logs-naming
- 룰 그룹 액션 오버라이드 (`ExcludedRules` → `RuleActionOverrides`) — https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-group-override-options.html#web-acl-rule-group-override-replaces-exclude
- Data protection (마스킹) — https://docs.aws.amazon.com/waf/latest/developerguide/data-protection-masking.html
- WAF 쿼터 — https://docs.aws.amazon.com/waf/latest/developerguide/limits.html
- API `LoggingConfiguration` (`RedactedFields`) — https://docs.aws.amazon.com/waf/latest/APIReference/API_LoggingConfiguration.html
- API `PutLoggingConfiguration` — https://docs.aws.amazon.com/waf/latest/APIReference/API_PutLoggingConfiguration.html
- API `LoggingFilter` — https://docs.aws.amazon.com/waf/latest/APIReference/API_LoggingFilter.html
- API `ActionCondition` (action valid values) — https://docs.aws.amazon.com/waf/latest/APIReference/API_ActionCondition.html

**CloudWatch Logs Insights**

- 로그 데이터 분석 (타임아웃·동시성·결과 보존·과금 원칙) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html
- 지원 로그와 자동 발견 필드 (`@log`, dot notation, JSON 문자열 함정, 200필드 상한) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData-discoverable-fields.html
- 쿼리 문법 및 비용 베스트 프랙티스 — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html
- `join` — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Join.html
- `stats` (집계 함수, `latest`/`earliest`, `countDistinct`, stats 10개 상한) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Stats.html
- `parse` (glob / regex / logfmt / csv) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Parse.html
- `filter` (`in` / `like` / `=~`, 인덱스 적용 조건) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Filter.html
- `limit` (기본 10,000 / 최대 100,000) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Limit.html
- 연산자·함수 (`coalesce`, `ispresent`, `if`, `case`, `strcontains`) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-operations-functions.html
- OpenSearch SQL (로그 그룹 간 JOIN) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_SQL.html
- 지원 쿼리 언어 — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_Languages.html
- API `StartQuery` (50개 상한, 파라미터 배타성, ARN 요건) — https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_StartQuery.html
- API `GetQueryResults` (페이지당 10,000, `statistics`) — https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetQueryResults.html
- CLI `start-query` — https://docs.aws.amazon.com/cli/latest/reference/logs/start-query.html
- CloudWatch Logs 쿼터 (Event size 1,024 KB, 스로틀) — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html

**가격**

- CloudWatch 요금 페이지 (프리티어 5 GB 공유) — https://aws.amazon.com/cloudwatch/pricing/
- Price List API, ap-northeast-2 ($0.0076/GB) — https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/current/ap-northeast-2/index.json
- Price List API, us-east-1 ($0.005/GB) — https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/current/us-east-1/index.json

## 문서에서 확인하지 못한 것

정직하게 남긴다 — 아래는 추론이거나 미확인이다.

- `httpRequest.uri`에 쿼리스트링이 포함되는지 **명시적 서술이 없다.** 예시 8개로부터 "경로만"으로 추론.
- WAF 로그 레코드 최대 크기가 **문서화되어 있지 않다.** CloudWatch 1,024 KB 이벤트 상한만 적용.
- `action` vs `overriddenAction`의 정확한 의미 — 산문 설명만 있고 예시가 없다.
- `sum(<불리언>)` 조건부 집계 문법 — **문서에 없다.** 실측으로만 검증했다.
- `stats`가 NULL/부재 필드를 다루는 일반 규칙 — 문서화되어 있지 않다. 실측으로만 확인했다.
- WAF 이벤트당 바이트 수 — WAF 로그 그룹이 없어 **측정하지 못했다.** 2 KB는 추정치이며
  비용 표의 WAF 열 전체가 이 추정에 의존한다.
- redaction 표시값이 `REDACTED`인지 `xxx`인지 — AWS 문서끼리 상충한다
  (`logging-management.html` + API 레퍼런스는 `REDACTED`, `logging-management-configure.html`은 `xxx`).
  다수결로 `REDACTED`로 적었다.
