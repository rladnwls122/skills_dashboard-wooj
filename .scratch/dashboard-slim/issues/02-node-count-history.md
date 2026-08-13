# 02 — 채점 창 전체의 노드 대수를 사후 재구성할 수 있는가

Type: research
Status: resolved
Blocked by: —
Parent: ../map.md

## Question

비용 채점은 채점 창(T+1h ~ T+3h) 동안 **N분마다 집계한 인스턴스 대수**를 입력으로 쓴다.
대시보드가 같은 값을 계산하려면 그 창 **전 구간**의 대수 시계열이 필요하다.

대시보드는 로컬 실행이라 사람이 닫거나 재시작하면 자체 샘플링에는 구멍이 생긴다. 그래서 묻는다:

1. **대시보드가 꺼져 있던 구간까지 포함해** 노드 대수 시계열을 AWS에서 사후 조회할 수 있는가?
   - EKS Managed Nodegroup이 만드는 Auto Scaling Group의 CloudWatch 메트릭
     (`AWS/AutoScaling` 네임스페이스의 `GroupInServiceInstances` 등)이 **추가 설정 없이 켜져 있는지**,
     아니면 그룹 메트릭 수집을 명시적으로 활성화해야 하는지.
   - 해상도(1분/5분)와 보존 기간이 2시간 창을 덮는지.
   - 대안: `AWS/EC2` `CPUUtilization`의 `SampleCount`로 인스턴스 수를 세는 우회,
     CloudTrail `RunInstances`/`TerminateInstances` 이벤트로 재구성, EKS Container Insights의 노드 메트릭.
2. **규격 외 인스턴스 감지**에 필요한 것 — 실행 중인 EC2를 인스턴스 타입·리전·태그별로 나열하는 가장 싼 호출은?
   과제는 `t3.medium`만 허용하고 미사용 인스턴스도 감점 사유다.
3. 위 조회들의 **비용과 호출 빈도 제약** — 대회 중 30초~1분 주기로 돌려도 되는 수준인지.

결론은 "① 사후 조회가 되므로 자체 샘플링은 불필요" / "② 안 되므로 대시보드가 SQLite에 계속 적재해야 하고,
꺼진 구간은 구멍으로 표시해야 한다" 중 하나로 떨어져야 한다. 근거가 되는 AWS 문서 링크를 함께 남긴다.

가능하면 실제 계정에 대고 확인한다 (`aws cloudwatch list-metrics --namespace AWS/AutoScaling` 등).
자격증명이 없으면 문서 근거만으로 결론 내고 그 사실을 명시한다.

## Answer

**사후 조회 가능.** 채점 창 2시간의 노드 대수는 대시보드가 꺼져 있었더라도 AWS에서 재구성된다.
따라서 자체 SQLite 적재는 정확도 보험이 아니라 실시간 표시용으로만 필요하다.

전체 조사 결과: [research/02-node-count-history.md](../research/02-node-count-history.md) (418줄, 근거 링크 포함)

핵심 세 가지:

1. **ASG 그룹 메트릭에 의존하면 안 된다.** `skills-eks`는 Karpenter로 워크로드 노드(`t3.medium`)를 띄우고
   Managed Nodegroup은 시스템용 1대뿐이었다. Karpenter 인스턴스에는 `aws:autoscaling:groupName` 태그가
   없어 어떤 ASG에도 속하지 않으므로, `AWS/AutoScaling` 메트릭만 보면 **채점 대상 대수를 통째로 놓친다**
   (같은 날 `GroupTotalInstances` 최댓값 = 1.0).
2. **CloudTrail `RunInstances`/`TerminateInstances`가 유일하게 커버리지 100%**이고 사전 설정이 필요 없으며
   90일 보존이다. ASG·Karpenter·수동 생성을 가리지 않는다 → **최종 정산 소스**.
3. ContainerInsights `cluster_node_count`는 1분 해상도로 클러스터 전체 노드를 덮어 1차 소스로 좋지만,
   `amazon-cloudwatch-observability` add-on이 **채점 창 시작 전에 설치돼 있어야** 한다.
   설치 여부는 대회 당일 우리 손에 달렸으므로, 대시보드는 없을 때를 대비해야 한다.

기각된 대안: `AWS/EC2` CPUUtilization SampleCount(무차원 집계가 전 구간 0건, basic monitoring 5분이라
단명 인스턴스 누락), `describe-instances`(현재 상태 전용, 사후 조회 불가 — 실시간 표시에만 쓴다).

비용·쿼터는 무시할 수준: 30초 주기 2시간 = 240회 ≈ $0.0024. 주의점은 CloudTrail `LookupEvents` 2 TPS와
`describe-instances`에 서버사이드 `--filters`를 걸어야 페이지 버킷을 100/20으로 쓴다는 것 정도.

### 검증 조건 (믿을 때 주의할 것)

조사 시점(2026-08-14)에 `skills-eks` 클러스터와 ASG는 **이미 삭제된 상태**였고, 결론은 CloudWatch/CloudTrail에
남은 **과거 실행분**으로 실증했다. 그 사실 자체가 "리소스가 사라져도 시계열은 사후 조회된다"의 직접 증거다.

다만 Karpenter는 **연습 환경에서 그렇게 지어져 있었다**는 관측이지, 대회 당일이 그렇다는 보장이 아니다.
당일 구성은 우리가 짓는다. 그래서 결론은 "Karpenter일 것"이 아니라 **"어떤 프로비저너로 짓든 놓치지 않는
소스를 쓴다"** — 즉 CloudTrail을 기준으로 두는 것이다.
