## 설치

**mise 사용**
```bash
git clone https://github.com/rladnwls122/skills_dashboard-wooj.git
cd skills_dashboard-wooj
mise install
mise run install
```

**mise 미사용**
```bash
git clone https://github.com/rladnwls122/skills_dashboard-wooj.git
cd skills_dashboard-wooj
corepack enable pnpm
pnpm install
go mod download -C backend
```

**사전 요구사항**: Node.js 24, pnpm, Go, AWS CLI, kubectl
```bash
aws sts get-caller-identity
aws eks update-kubeconfig --name skills-eks --region ap-northeast-2
kubectl config current-context
```

---

## 실행

```bash
pnpm dev          # 또는 mise run dev
```
→ `http://127.0.0.1:3100/dashboard` 접속 (로그인 없음)

**프로덕션 빌드**
```bash
pnpm build:clean && pnpm start
```

**개별 실행이 필요할 때**
```bash
pnpm dev:backend   # 터미널 1
pnpm dev:frontend  # 터미널 2
```

**상태 확인**
```bash
curl http://127.0.0.1:8787/healthz
```

---

## 대시보드 사용법

시간 창(`15m/30m/1h/2h/4h`)은 전체 탭 공유.

**1. 성능 탭** — 대회 중 상시 감시
- 채점기 입력값(user·product·stress SLO, Email Validation, 비정상 요청 처리율) 확인
- TRT·4XX·5XX·RDS 연결 수, 이상 목록, Pod/Node 사용률 모니터링
- Deployment 조정: preview → 승인 → 적용 → ~2분 후 자동 검증

**2. 트래픽 탭** — 지금 뭐가 들어오는지 확인
- 경로별 요청/차단, User-Agent·QueryString 패턴 확인
- 애플리케이션/WAF 로그, Pod 로그 터미널(검색·자동갱신) 확인

**3. 규칙 생성 탭** — 순서대로 진행
1. User-Agent 목록 또는 SQLi 시그니처로 규칙 조립
2. 패턴 세트 AWS 생성 → ARN 치환
3. 로컬 테스트로 시뮬레이션
4. UA 규칙: `추천됨 → BLOCK` / SQLi 규칙: `추천됨 → COUNT → BLOCK`
5. COUNT 상태에서 정상/비정상 건수로 오탐 확인 후 승격
6. 적용 후 정상 경로 프로브 + 채점 입력값 재확인

**4. 설정 탭**
- 리소스 자동 탐색 / override
- AWS CLI 세션 불러오기 (키 만료 시 재사용)

---

## 트러블슈팅 순서

| 증상 | 확인 |
|---|---|
| 전체 패널 비어있음 | `/healthz` → AWS 자격증명 → region/scope |
| K8s만 비어있음 | `kubectl get pods -n default`, EKS 권한 |
| WAF만 비어있음 | `WAF_WEB_ACL_NAME`, scope=CLOUDFRONT, region=us-east-1 |
| 로그 없음 | 시간 창 → 로그 그룹명 → 실제 유입 확인 |
| 키 만료 | 설정 → AWS 자격증명 → CLI 세션 재불러오기 |
