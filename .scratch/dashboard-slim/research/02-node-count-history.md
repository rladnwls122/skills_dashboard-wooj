# 02 — 채점 창 전체의 노드 대수를 사후 재구성할 수 있는가

Status: resolved
Parent: ../issues/02-node-count-history.md
검증 일자: 2026-08-14 (KST) / 계정 `<계정ID>`, 리전 `ap-northeast-2`

---

## 결론: **사후 조회 가능**

채점 창 2시간의 노드 대수 시계열은 대시보드가 꺼져 있었더라도 AWS에서 사후 재구성할 수 있다.
따라서 **자체 샘플링은 정확도상 필수가 아니다.** 단, 단일 소스로는 안 되고 아래 조합이 필요하다.

| 소스 | 해상도 | 보존 | 커버리지 | 사전 설정 |
| --- | --- | --- | --- | --- |
| CloudTrail `RunInstances`/`TerminateInstances` | 이벤트 단위(정확) | **90일** | **전부** (ASG + Karpenter + 수동) | **불필요** |
| ContainerInsights `cluster_node_count` | 1분 | 15일 | 클러스터 전체 노드 | `amazon-cloudwatch-observability` add-on 필요 |
| `AWS/AutoScaling` `GroupInServiceInstances` | 1분 | 15일 | **Managed Nodegroup만** | 불필요 (EKS가 자동 활성화) |

**가장 중요한 함정**: 이 계정의 `skills-eks`는 **Karpenter**로 워크로드 노드(`t3.medium`)를 띄우고,
Managed Nodegroup(`eks-system-*`)은 시스템 파드용 1대뿐이었다. Karpenter 노드는 어떤 ASG에도 속하지
않으므로 `AWS/AutoScaling` 그룹 메트릭만 보면 **채점 대상 대수를 통째로 놓친다.** 실측 근거는 Q1-C 참조.

**권고**: 1차 소스는 `cluster_node_count`(설치돼 있으면), 최종 정산·검증은 CloudTrail.
SQLite 적재는 *정확도*가 아니라 *실시간 UX와 add-on 미설치 리스크 대비*용으로만 하면 된다.
꺼진 구간은 구멍으로 표시할 필요 없이 CloudTrail로 backfill 가능하다.

---

## 검증 환경에 대한 사실 고지

- 자격증명은 **존재**한다. `aws sts get-caller-identity` → `arn:aws:iam::<계정ID>:user/PowerUser`.
- 단, 검증 시점에 `skills-eks` 클러스터는 **이미 삭제된 상태**였다.
  - `aws eks list-clusters --region ap-northeast-2` → `{"clusters": []}`
  - `aws eks list-nodegroups --cluster-name skills-eks` → `ResourceNotFoundException: No cluster found for name: skills-eks`
  - `aws autoscaling describe-auto-scaling-groups --region ap-northeast-2` → `[]` (ASG도 전부 삭제됨)
- 그러나 **CloudWatch 메트릭과 CloudTrail 이벤트는 남아 있어** 과거 실행분으로 전 항목을 실증할 수 있었다.
  이것 자체가 "리소스가 사라져도 시계열은 사후 조회된다"는 결론의 직접 증거다.

---

## Q1. ASG 그룹 메트릭 — 기본 활성인가?

### A. 문서: "must enable" (기본 비활성)

> "Group metrics are available at one-minute granularity at no additional charge, **but you must enable them**."
> — [Amazon CloudWatch metrics for Amazon EC2 Auto Scaling](https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html)

모든 그룹 메트릭의 **Reporting criteria**가 `Reported if metrics collection is enabled`로 명시돼 있다.
즉 순수 ASG 관점에서는 `EnableMetricsCollection` API / `enable_metrics_collection` 없이는 나오지 않는다.

### B. 실측: EKS Managed Nodegroup은 **EKS가 대신 켜준다**

CloudTrail에 EKS 서비스 링크드 롤이 직접 호출한 기록이 남아 있다:

```
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=EnableMetricsCollection \
  --region ap-northeast-2
```

```json
{
  "eventTime": "2026-08-13T00:38:54Z",
  "eventSource": "autoscaling.amazonaws.com",
  "eventName": "EnableMetricsCollection",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::<계정ID>:assumed-role/AWSServiceRoleForAmazonEKSNodegroup/EKS",
    "invokedBy": "eks-nodegroup.amazonaws.com"
  },
  "requestParameters": {
    "autoScalingGroupName": "eks-system-a6cffc47-17cb-40ef-d97e-bc7798818a2e",
    "granularity": "1Minute"
  }
}
```

- 호출 주체가 `AWSServiceRoleForAmazonEKSNodegroup` — 사용자가 아니라 **EKS 자신**이다.
- `granularity: "1Minute"`, `metrics` 파라미터 없음 → 문서상 "If you omit the `--metrics` option, **all metrics are enabled**".
- 이 이벤트는 nodegroup ASG 생성 시각과 동일 초에 발생한다(9건 확인, 7/29~8/13).

**정리**: "기본 활성"은 아니지만, **EKS Managed Nodegroup을 쓰는 한 사용자가 따로 켤 필요가 없다.**
반대로 self-managed ASG나 Karpenter는 이 혜택을 못 받는다.

실제로 `AWS/AutoScaling` 네임스페이스에 8개 `eks-system-*` ASG에 대해 26종 그룹 메트릭이
`GroupInServiceInstances` / `GroupDesiredCapacity` / `GroupTotalInstances` 포함해 모두 존재했다.

### C. 실측: Karpenter 노드는 ASG 메트릭에 **안 잡힌다** (치명적)

`RunInstances` 이벤트를 주체별로 분해한 결과:

```
2026-08-13T06:19:32Z  eks-skills-eks-karpenter-...  t3.medium
  tagKeys: ['eks:eks-cluster-name', 'karpenter.k8s.aws/ec2nodeclass',
            'karpenter.sh/nodepool', 'kubernetes.io/cluster/skills-eks']
2026-08-13T05:42:04Z  AutoScaling                   t3.micro
2026-08-13T05:34:10Z  PowerUser                     t3.micro
```

- Karpenter가 띄운 `t3.medium`에는 **`aws:autoscaling:groupName` 태그가 없다** → 어떤 ASG에도 미소속.
- 같은 날 유일한 ASG(`eks-system-a6cffc47-...`)의 `GroupTotalInstances` 최댓값은 **1.0**이었다.

즉 채점 대상인 `t3.medium` 워크로드 노드는 ASG 그룹 메트릭 상에서 **완전히 투명하다.**

### D. 해상도와 보존 — 2시간 창을 덮는가? → 덮는다

1분 해상도 실측 (`GroupInServiceInstances`, period=60, 2시간 창):

```
$ aws cloudwatch get-metric-statistics --namespace AWS/AutoScaling \
    --metric-name GroupInServiceInstances \
    --dimensions Name=AutoScalingGroupName,Value=eks-system-cccff9ab-... \
    --start-time 2026-08-12T00:15:00Z --end-time 2026-08-12T02:15:00Z \
    --period 60 --statistics Average --region ap-northeast-2
→ 109 datapoints
2026-08-12T09:20:00+09:00  0.0
2026-08-12T09:21:00+09:00  0.0
2026-08-12T09:22:00+09:00  1.0
```

2시간 = 120분 중 109개(ASG 생성 시점부터). **분당 1점**이 실제로 확보된다.

보존 규칙 (문서 verbatim):

> - Data points with a period of less than 60 seconds are available for 3 hours.
> - Data points with a period of 60 seconds (1 minute) are available for **15 days**
> - Data points with a period of 300 seconds (5 minutes) are available for 63 days
> - Data points with a period of 3600 seconds (1 hour) are available for 455 days (15 months)
>
> — [Metrics concepts › Metrics retention](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#metrics-retention)

3시간짜리 대회 직후~15일 내 조회라면 **1분 해상도가 그대로 남아 있다.** 여유가 매우 크다.
(15일이 지나면 5분으로, 63일이 지나면 1시간으로 자동 롤업된다.)

주의 문구 하나:

> "When you enable Auto Scaling group metrics, Amazon EC2 Auto Scaling sends sampled data to CloudWatch
> every minute **on a best-effort basis**. In rare cases when CloudWatch experiences a service disruption,
> data isn't backfilled to fill gaps in group metric history."

---

## Q2. 대안 평가 — 과거 2시간 창 재구성

### ① `AWS/EC2` CPUUtilization `SampleCount` 우회 → **쓰지 말 것**

문서상으로는 차원 없이 조회하면 집계된다고 돼 있다:

> "For metrics produced by certain AWS services, such as Amazon EC2, CloudWatch can aggregate data across
> dimensions. For example, if you search for metrics in the `AWS/EC2` namespace but do not specify any
> dimensions, CloudWatch aggregates all data for the specified metric..."
> — [Metrics concepts › Dimensions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Dimension)

**그러나 이 계정에서 실측한 결과는 전부 0이었다.**

```
# 차원 지정 O — 데이터 있음
$ ... --dimensions Name=InstanceId,Value=i-00d698a345d3c6fbb \
      --start-time 2026-07-31T00:00:00Z --end-time 2026-08-14T00:00:00Z --period 3600
2026-08-02T11:00:00+09:00   SampleCount=44.0   Average=0.2659

# 차원 지정 X — 14일 전 구간 0건
$ ... (no --dimensions) --start-time 2026-07-31T00:00:00Z --end-time 2026-08-14T00:00:00Z --period 3600
→ (empty)
```

`list-metrics`에는 `CPUUtilization` 차원 조합이 71개나 존재하는데도 무차원 집계는 한 점도 반환하지 않았다.
게다가 근본적 결함이 세 가지 더 있다:

1. **basic monitoring은 5분 주기**다. 수명이 5분 미만인 인스턴스는 datapoint를 아예 남기지 않는다.
   대회 중 스케일 인/아웃이 잦으면 그대로 누락된다. 1분을 원하면 detailed monitoring(유료)이 필요하다.
2. `SampleCount`는 리전 내 **모든 EC2**를 세므로 클러스터 노드만 분리할 수 없다.
3. 차원 없는 집계는 인스턴스 타입/태그로 필터링이 불가능하다.

→ **기각.**

### ② CloudTrail `RunInstances` / `TerminateInstances` → **가장 신뢰도 높은 최종 소스**

- **사전 설정 불필요.** 관리 이벤트는 기본으로 기록되고 90일 Event history는 무료다.
  > "CloudTrail logs management events across AWS services by default and is available for no charge.
  > You can view, search, and download the most recent **90-day history** of your account's control plane
  > activity at no additional cost..." — [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/)
- **커버리지 100%**: ASG 기동분, Karpenter 기동분, 사람이 콘솔에서 띄운 것까지 전부 잡힌다(실측 확인).
- **인스턴스 타입이 이벤트에 들어 있다** → 규격 외 감지(Q3)까지 같은 소스로 해결된다.
- 기동/종료 이벤트 쌍으로 각 인스턴스의 생존 구간을 복원하면, **임의 시각의 대수를 정확히** 계산할 수 있다.
  CloudWatch의 1분 격자보다 오히려 정밀하다.

한계:
- `LookupEvents`의 TPS 쿼터는 **2**다 (아래 Q4).
  > "the TPS quota for the CloudTrail `LookupEvents` API is 2"
  > — [Quotas in AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html)
- 이벤트 전달에 지연이 있을 수 있으므로 대회 종료 직후 즉시 정산하기보다 몇 분 여유를 둔다.
- Spot 회수처럼 사용자 API 호출 없이 종료되는 경로는 `TerminateInstances`로 안 나타날 수 있다.
  이 경우 `cluster_node_count`나 `describe-instances` 결과와 교차 검증한다.

### ③ EKS Container Insights `cluster_node_count` → **사전 설치돼 있으면 1순위**

- **사전 설치 필요.** 기본 활성이 아니다.
  > "In Amazon EKS, RedHat OpenShift on AWS, and Kubernetes, Container Insights uses a **containerized
  > version of the CloudWatch agent** to discover all of the running containers in a cluster."
  > — [Container Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html)
  > "Two approaches are available: OTel Container Insights (recommended) and Enhanced Container Insights
  > (Classic). Both use the **`amazon-cloudwatch-observability` EKS add-on**..."
  > — [Container Insights › Amazon EKS](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/deploy-container-insights-EKS.html)
- 이 계정에는 **설치돼 있었다**. `ContainerInsights` 네임스페이스에 19,000개 이상 메트릭이 있고,
  `amazon-cloudwatch` 네임스페이스의 `fluent-bit` 파드 차원까지 확인된다.
- 필요한 메트릭이 모두 존재: `cluster_node_count`, `cluster_failed_node_count`,
  `cluster_number_of_running_pods`, `node_number_of_running_pods`, `node_status_condition_ready` 등.
- `cluster_node_count`의 차원은 `ClusterName` 하나뿐 → 질의가 간단하다.

실측 (동일한 2시간 창):

```
$ aws cloudwatch get-metric-statistics --namespace ContainerInsights \
    --metric-name cluster_node_count --dimensions Name=ClusterName,Value=skills-eks \
    --start-time 2026-08-12T00:15:00Z --end-time 2026-08-12T02:15:00Z \
    --period 60 --statistics Average --region ap-northeast-2
→ 108 datapoints, 시작 2026-08-12T09:27:00+09:00, Average=1.0
```

**1분 해상도, 2시간 창 거의 완전 커버, Karpenter 노드 포함.** ASG 메트릭의 커버리지 구멍이 없다.
보존은 일반 CloudWatch 규칙과 동일하므로 1분 해상도로 15일.

주의: 커스텀 메트릭 과금 대상이다. Classic은 메트릭당 $0.30/월, Enhanced observability(EKS)는
관측 100만 건당 $0.21 ([CloudWatch Pricing](https://aws.amazon.com/cloudwatch/pricing/)).
3시간 대회 규모에서는 무시할 수준이지만 add-on을 켜 두는 기간이 길면 누적된다.

또한 **add-on이 채점 창 시작 전에 이미 떠 있어야** 한다. 대회 당일 클러스터를 새로 만든다면
이 소스는 존재하지 않을 수 있고, 그때는 CloudTrail이 유일한 사후 소스다.

### ④ `ec2 describe-instances` 폴링 → **현재 상태 전용, 사후 조회 불가**

`DescribeInstances`는 **현재 상태만** 반환한다. 과거 시점 질의 파라미터가 없다.
종료된 인스턴스는 대체로 1시간 정도만 `terminated` 상태로 보이다가 목록에서 사라진다.
→ 사후 재구성 수단으로는 **부적합**. 실시간 화면과 규격 외 감지용으로만 쓴다.

---

## Q3. 규격 외 인스턴스 감지 — 가장 싼 호출

### 권장: 서버사이드 `--filters`를 건 `describe-instances` 1회

```bash
aws ec2 describe-instances \
  --region ap-northeast-2 \
  --filters Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[].{
      Id:InstanceId, Type:InstanceType, AZ:Placement.AvailabilityZone,
      Launch:LaunchTime, Tags:Tags}' \
  --output json
```

핵심은 **`--filters`를 반드시 쓰는 것**이다. 스로틀링 버킷이 달라진다:

> | API action category | Actions | Bucket maximum capacity | Bucket refill rate |
> | --- | --- | --- | --- |
> | Non-mutating actions | `Describe*`, `List*`, `Search*`, `Get*` (타 카테고리 제외) | **100** | **20** |
> | Unfiltered and unpaginated non-mutating actions | `DescribeInstances`, `DescribeInstanceStatus`, ... | **50** | **10** |
>
> "**Unfiltered and unpaginated non-mutating actions** — A specific subset of non-mutating API actions
> that, when requested without specifying either pagination or a filter, use tokens from a **smaller
> token bucket**. It is recommended that you make use of pagination and filtering so that tokens are
> deducted from the standard (larger) token bucket."
> — [Request throttling for the Amazon EC2 API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/throttling.html)

`--query`는 **클라이언트 사이드**라 스로틀링에 도움이 안 된다. `--filters`만 서버사이드다.

규격 외(`t3.medium` 외) 및 미사용 인스턴스 탐지는 타입 필터를 서버에서 부정형으로 걸 수 없으므로,
`running` 전량을 받아 클라이언트에서 `InstanceType != 't3.medium'`을 판정하는 편이 호출 수가 가장 적다
(1회 호출). 클러스터 소속만 보려면 태그 필터를 추가한다:

```bash
--filters Name=instance-state-name,Values=running \
          Name=tag-key,Values=kubernetes.io/cluster/skills-eks
```

단, 실측상 Karpenter 노드는 `kubernetes.io/cluster/skills-eks`와 `eks:eks-cluster-name` 태그를
갖지만 ASG 노드와 태그 셋이 다르므로, **미사용/떠돌이 인스턴스까지 잡으려면 태그 필터 없이
리전 전체를 훑는 쪽이 안전**하다.

### 비용

EC2 API 호출 자체에는 **과금이 없다.** 스로틀링 쿼터만 신경 쓰면 된다.

### 사후 조회가 필요하면

과거 시점의 규격 외 인스턴스는 `describe-instances`로 못 본다.
CloudTrail `RunInstances` 이벤트의 `requestParameters.instanceType` /
`responseElements.instancesSet.items[].instanceType`으로 재구성한다 (Q2-② 실측 코드 참조).

---

## Q4. 30~60초 주기 폴링의 비용·쿼터 영향 → **전부 무시할 수준**

2시간 동안 30초 주기 = **240회**, 60초 주기 = **120회**.

### 요청 레이트 쿼터 (전부 초당 기준, 우리는 초당 0.033회)

| API | 기본 쿼터 | 여유 |
| --- | --- | --- |
| `GetMetricData` | **500/초** | 15,000배 |
| `GetMetricStatistics` | **400/초** | 12,000배 |
| `ListMetrics` | **25/초** | 750배 |
| `DescribeInstances` (필터 사용) | 버킷 100, 리필 **20/초** | 600배 |
| `DescribeInstances` (필터 없음) | 버킷 50, 리필 **10/초** | 300배 |
| CloudTrail `LookupEvents` | **2/초** | 60배 |

출처: [CloudWatch service quotas](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_limits.html),
[EC2 API throttling](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/throttling.html),
[CloudTrail quotas](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html).

**어느 것도 근처에 가지 않는다.** 유일하게 조심할 것은 CloudTrail `LookupEvents` 2 TPS인데,
페이지네이션으로 90일치를 빠르게 훑을 때 초당 2회를 넘기기 쉽다. 백오프를 넣는다.

### 금액

CloudWatch 요금:

> - **Free Tier**: 1 Million API requests (**not including** GetMetricData, GetMetricStatistics ...)
> - **Paid**: **$0.01 per 1,000 requests**
> - GetMetricData, GetInsightRuleReport, GetMetricWidgetImage are "**always charged**"
>
> — [Amazon CloudWatch Pricing](https://aws.amazon.com/cloudwatch/pricing/)

즉 `GetMetricData`/`GetMetricStatistics`는 프리티어에서 제외되어 첫 호출부터 과금되지만 단가가 극히 낮다.

| 시나리오 | 호출 수 | 비용 |
| --- | --- | --- |
| 30초 주기 × 2시간, 호출당 메트릭 1개 | 240 | **$0.0024** |
| 30초 주기 × 2시간, 호출당 메트릭 5개 (GetMetricData) | 1,200 metrics | **$0.012** |
| 60초 주기 × 3시간 (대회 전체) | 180 | **$0.0018** |

**대회 전체를 30초로 돌려도 1센트 남짓이다.** 비용은 의사결정 요인이 아니다.

`DescribeInstances`와 CloudTrail `LookupEvents`(90일 Event history)는 **무료**다.

### 한 번에 가져올 수 있는 datapoint 상한

`GetMetricStatistics`는 호출당 **1,440 datapoint**가 상한이다. 실측으로 확인한 에러:

```
An error occurred (InvalidParameterCombination) when calling the GetMetricStatistics operation:
You have requested up to 18720 datapoints, which exceeds the limit of 1440.
You may reduce the datapoints requested by increasing Period, or decreasing the time range.
```

2시간 창을 period=60으로 뽑으면 120점이므로 **한 번의 호출로 충분하다.**
더 넓은 구간을 훑을 때만 period를 키우거나 창을 쪼갠다.
`GetMetricData`를 쓰면 요청당 여러 메트릭을 묶을 수 있어 호출 수를 더 줄일 수 있다.

---

## 대시보드 구현 권고

1. **실시간 화면**: 60초 주기로 `describe-instances --filters Name=instance-state-name,Values=running`
   1회. 대수·타입·규격 외 판정을 한 호출로 전부 처리한다. 무료·무제한에 가깝다.
2. **시계열 차트**: `ContainerInsights` `cluster_node_count`를 period=60으로 조회.
   add-on이 없으면 `AWS/AutoScaling` `GroupInServiceInstances`로 폴백하되
   **Karpenter 노드 누락 경고를 UI에 반드시 띄운다.**
3. **최종 정산 / 구멍 메우기**: CloudTrail `RunInstances` + `TerminateInstances`로
   인스턴스별 생존 구간을 복원해 임의 해상도로 대수를 재계산. 90일 무료, 사전 설정 불필요.
4. **SQLite 적재**: 해도 되지만 *정확도 보험*이 아니라 *API 호출 절약과 즉시 렌더링*이 목적이다.
   대시보드가 꺼져 있던 구간은 3번으로 backfill되므로 "구멍"으로 남길 필요가 없다.

---

## 실행한 검증 명령 (전부 read-only)

```bash
aws sts get-caller-identity
aws eks list-clusters --region ap-northeast-2
aws eks list-nodegroups --cluster-name skills-eks --region ap-northeast-2
aws autoscaling describe-auto-scaling-groups --region ap-northeast-2
aws cloudwatch list-metrics --namespace AWS/AutoScaling --region ap-northeast-2
aws cloudwatch list-metrics --namespace ContainerInsights --region ap-northeast-2
aws cloudwatch list-metrics --namespace AWS/EC2 --metric-name CPUUtilization --region ap-northeast-2
aws cloudwatch get-metric-statistics --namespace AWS/AutoScaling --metric-name GroupInServiceInstances ...
aws cloudwatch get-metric-statistics --namespace AWS/AutoScaling --metric-name GroupTotalInstances ...
aws cloudwatch get-metric-statistics --namespace ContainerInsights --metric-name cluster_node_count ...
aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization ...
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=EnableMetricsCollection ...
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAutoScalingGroup ...
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances ...
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=TerminateInstances ...
aws ec2 describe-instances --region ap-northeast-2 --filters Name=instance-state-name,Values=running
```

---

## 출처

### Auto Scaling 그룹 메트릭
- [Amazon CloudWatch metrics for Amazon EC2 Auto Scaling](https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html) — "you must enable them", 1분 granularity, 무과금, 그룹 메트릭 전체 목록, `enable-metrics-collection` CLI
- [Monitor CloudWatch metrics for your Auto Scaling groups and instances](https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-cloudwatch-monitoring.html) — `AWS/AutoScaling` vs `AWS/EC2` 네임스페이스 구분
- [enable-metrics-collection (CLI)](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/autoscaling/enable-metrics-collection.html)

### CloudWatch 해상도·보존·집계
- [Metrics concepts › Metrics retention](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#metrics-retention) — 3시간 / 15일 / 63일 / 455일
- [Metrics concepts › Dimensions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Dimension) — `AWS/EC2` 무차원 집계 서술
- [Aggregate statistics across resources](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/GetSingleMetricAllDimensions.html)
- [CloudWatch service quotas](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_limits.html) — GetMetricData 500/s, GetMetricStatistics 400/s, ListMetrics 25/s

### Container Insights
- [Container Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html) — CloudWatch agent 컨테이너 필요, EMF 기반
- [Container Insights › Amazon EKS](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/deploy-container-insights-EKS.html) — `amazon-cloudwatch-observability` EKS add-on
- [Metrics collected by Container Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics.html)

### CloudTrail
- [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/) — 90일 Event history 무료, 관리 이벤트 첫 사본 무료, 이후 10만 건당 $2.00
- [Quotas in AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html) — `LookupEvents` TPS = 2

### EC2 API
- [Request throttling for the Amazon EC2 API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/throttling.html) — 토큰 버킷, 필터/페이지네이션 권고, `DescribeInstances` 50/10 vs 100/20
- [Using filtering (CLI)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Filtering.html#Filtering_Resources_CLI)

### 요금
- [Amazon CloudWatch Pricing](https://aws.amazon.com/cloudwatch/pricing/) — API 요청 $0.01/1,000, GetMetricData/GetMetricStatistics 프리티어 제외, Container Insights 요금
