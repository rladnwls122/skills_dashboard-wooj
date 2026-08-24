대회장에서 AWS·Kubernetes·WAF 를 한 화면으로 보는 운영 대시보드입니다.
읽기가 기본이고, 쓰기는 두 가지(Deployment 조정, WAF 규칙 적용)뿐이며 둘 다 누르기 전에 확인 화면을 거칩니다.

- **경기 당일 절차**는 [`docs/RUNBOOK.md`](docs/RUNBOOK.md) 를 보세요. 이 문서는 구축과 사용법입니다.
- **용어**(비정상 요청 403 · 미지정 경로 404 등)는 [`CONTEXT.md`](CONTEXT.md) 를 따릅니다.
- **과제 바이너리가 실제로 찍는 로그**는 [`docs/binaries.md`](docs/binaries.md) 에 정리돼 있습니다.

---

## 구축 런북

처음 한 번만 하면 됩니다. 순서대로 하면 10분 안에 끝납니다.

### 0. 준비물

| 필요한 것 | 확인 |
|---|---|
| **Node.js 24 이상** | `node -v` → `v24.x` 이상. **필수** — 이 버전부터 TypeScript 를 그대로 실행합니다 |
| pnpm | `pnpm -v` (없으면 `corepack enable pnpm`) |
| AWS CLI | `aws --version` |
| kubectl | `kubectl version --client` |

> 백엔드는 빌드 단계가 없습니다. Node 24 가 로드 시점에 타입을 지우므로 컴파일도, 바이너리도 없습니다.
> Node 23 이하에서는 **기동하지 않습니다.**

### 1. 내려받기와 설치

```bash
git clone https://github.com/rladnwls122/skills_dashboard-wooj.git
cd skills_dashboard-wooj
```

**pnpm** — corepack 이 Node 에 들어 있으므로 따로 설치할 것이 없습니다.
```bash
corepack enable pnpm
pnpm install --frozen-lockfile
```

**npm 이 편하면 그것도 됩니다.**
```bash
npm ci
```

`package-lock.json` 과 `pnpm-lock.yaml` 을 둘 다 두는 이유가 이것입니다.

> `npm ci` 와 `--frozen-lockfile` 은 락파일을 **그대로** 씁니다. 락파일과 `package.json` 이 어긋나면
> 조용히 다른 버전을 깔지 않고 실패합니다 — 당일에는 그게 맞습니다.
> 출력은 일부러 줄이지 않았습니다. 무엇이 깔리는지 보이는 편이 낫습니다.
>
> **필요한 도구는 Node.js 하나뿐입니다.** mise 도, Go 도 필요 없습니다 — 저장소에 `mise.toml` 이
> 있지만 편의용이고 대회장에서는 쓰지 않습니다. 모든 `pnpm <스크립트>` 는 `npm run <스크립트>` 로
> 그대로 바꿔 쓸 수 있습니다.

### 2. AWS 자격증명

**로컬에 `aws` CLI 가 로그인돼 있으면 아무것도 안 해도 됩니다** — 처음 기동할 때 `default` 프로파일 세션을 자동으로 불러옵니다(세션 한정, 저장 안 함).

```bash
aws sts get-caller-identity     # 계정 번호가 나오면 준비 끝
```

안 된다면 `aws sso login` 또는 `aws configure` 후 다시 확인하세요.
CLI 가 없는 PC 라면 기동 후 **톱니 → AWS 자격증명 → 키 직접 입력** 에 통째로 붙여넣으면 됩니다
(`export …` 블록 · PowerShell `$Env:…` · `.env` · `aws configure export-credentials` JSON 전부 인식).

### 3. kubeconfig

```bash
aws eks update-kubeconfig --name <클러스터 이름> --region ap-northeast-2
kubectl get pods -n default          # 여기서 응답이 와야 K8s 패널이 찹니다
```

> **주의**: 클러스터를 다시 만들었다면 kubeconfig 가 옛 엔드포인트를 가리켜 DNS 조회부터 실패합니다.
> 위 명령을 다시 돌리세요. 엔드포인트가 private 이면 VPC 안(또는 VPN·배스천)에서만 붙습니다.

### 4. 기동

```bash
pnpm dev
```
→ `http://127.0.0.1:3100/dashboard` (로그인 없음)

포트를 바꾸려면 `pnpm dev -p 3110` — UI·API·DB 가 한꺼번에 옮겨가므로 두 개를 동시에 띄울 수 있습니다.

### 5. 설정 채우기 (톱니)

값을 직접 타이핑하는 대신 **`자동 탐색`** 버튼을 쓰세요. 계정에 실제로 있는 리소스를 골라 넣어 주므로 오타로 인한 "빈 패널"이 생기지 않습니다.

| 항목 | 비고 |
|---|---|
| `AWS_REGION` | 워크로드가 있는 리전 |
| `WAF_SCOPE` | CloudFront 배포에 붙은 WebACL 이면 `CLOUDFRONT` (조회는 us-east-1) |
| `WAF_WEB_ACL_NAME` | **정확히** 맞아야 합니다 — 이름이 틀리면 규칙 적용을 거부합니다(아래 참고) |
| `WAF_LOG_GROUP` | 넣으면 표본이 아닌 **전수 집계**로 바뀝니다. 403 채점 키도 이때만 채워집니다 |
| `APP_LOG_GROUP` | `[GIN]` 액세스 라인이 들어 있는 그룹. ECS 라면 쉼표로 여러 개 (`/ecs/user,/ecs/product,/ecs/stress`) |
| `ALB_NAME` · `EKS_CLUSTER_NAME` · `RDS_PROXY_NAME` | 자동 탐색 권장 |
| `MATCH_START` | 경기 시작 시각. 비우면 비용 패널이 채점 창 평균을 계산하지 않습니다 |

### 6. 확인

```bash
curl http://127.0.0.1:8787/healthz          # 200
```
화면에서 **톱니 → 연결 확인** 을 눌러 계정 번호가 찍히면 끝입니다.

---

## 실행

```bash
pnpm dev            # 개발 (백엔드 --watch, 프런트 HMR)
pnpm start          # 프로덕션 (빌드된 프런트 + 백엔드)
pnpm build          # 프런트만 빌드 — 백엔드는 소스에서 바로 실행
pnpm test           # 타입체크 + 계약 테스트 + 단위 테스트
```

**개별 실행**
```bash
pnpm dev:backend    # 터미널 1
pnpm dev:frontend   # 터미널 2
```

### 저사양 PC 에서

- 화면이 **가려져 있으면 폴링이 멈춥니다.** 다른 창을 보는 동안에는 AWS 호출도, 차트 다시 그리기도 하지 않고, 돌아오면 즉시 한 번 새로 읽습니다. 최소화해 두는 것이 가장 확실한 절약입니다.
- 상단 **`갱신`** 을 `5초` → `30초` 로 올리면 렌더 비용이 그만큼 내려갑니다. 서버 캐시가 따로 있어 값이 낡지는 않습니다.
- 시간 창을 `4h` 로 두면 차트 점이 많아집니다. 평소에는 `1h` 로 두세요.
- 로그 터미널의 `tail` 을 2000 으로 두면 DOM 이 무거워집니다. `200` 이 기본이고 대개 충분합니다.
- 백엔드는 유휴 시 40–80MB 정도입니다. 브라우저가 대부분의 비용입니다.

---

## 대시보드 사용법

시간 창(`15m/30m/1h/2h/4h`)은 세 탭이 공유합니다.

### 1. PERFORMANCE — 상시 감시
- **채점기 입력값** — API 별 로드 처리·SLO, Email Request Validation, 비정상 요청 처리율, 미지정 경로 404. 각 줄이 **어느 로그에서 나온 값인지** 함께 적혀 있습니다. 점수는 매기지 않습니다.
- **채점 창 노드 대수** — 누적/최종 평균과 1대 증감 효과. 규격 외 인스턴스도 잡아 줍니다.
- TRT · 4XX · 5XX · RDS 연결 수, 이상 목록, Pod/Node 사용률.
- Deployment 조정: 미리보기 → 승인 → 적용 → 약 2분 뒤 자동 검증.

### 2. TRAFFIC — 지금 뭐가 들어오는지
- 경로별 요청·차단, User-Agent, QueryString 패턴.
- 앱 요청 로그(상태 코드·경로 필터, client IP·requestid·원문), WAF 로그, Pod 로그 터미널.

### 3. UA — 규칙 만들기

관측된 트래픽에서 **스캐너 차단 규칙 하나**를 만듭니다. 카드 상단에 동작 원리가 적혀 있습니다.

1. **`규칙 조립`** — 서비스 경로 세트와 스캐너 UA 세트, 두 개가 나옵니다.
2. **패턴 세트 2개를 AWS 에 먼저 생성** — `생성 CLI 복사` 를 쓰거나 콘솔에서 만들고, 받은 ARN 을 입력란에 붙여넣으면 규칙 JSON 에 채워집니다.
3. **`COUNT 로 올리기`** — 차단 없이 매칭만 시킵니다.
4. **`COUNT 실측 조회`** — 걸린 요청 중 **정상 응답이 몇 건인지** 봅니다. 0건이어야 안전합니다.
5. **`BLOCK 으로 승격`**.
6. 승격 직후 **정상 경로 프로브**를 한 번 돌려 오탐이 없는지 확인합니다.

> 규칙은 **서비스 경로 AND 스캐너 UA** 일 때만 차단합니다. UA 만으로 막으면 미지정 경로에도 403 이 나가는데, 과제 계약은 거기에 404 를 요구하므로 그 자체가 위반입니다.

### 4. 설정 (톱니)
- 리소스 자동 탐색 / 값 override (`.env` 보다 우선, 재시작 없이 적용)
- AWS 자격증명: CLI 세션 불러오기 · 키 직접 입력 · 연결 확인

---

## 트러블슈팅

| 증상 | 확인 |
|---|---|
| 전체 패널이 비어 있음 | 톱니 → **연결 확인**. 대부분 자격증명입니다. 만료가 가까우면 자동으로 다시 읽습니다 |
| K8s 패널만 실패 (`ENOTFOUND …eks.amazonaws.com`) | kubeconfig 가 옛 클러스터를 가리킵니다 → `aws eks update-kubeconfig` 재실행 |
| 키를 주입했는데 K8s 만 계속 실패 | 주입한 키는 exec-auth 에도 전달되지만 토큰 캐시가 남을 수 있습니다 → 톱니에서 다시 주입하면 클라이언트가 재생성됩니다 |
| WAF 패널만 비어 있음 | `WAF_WEB_ACL_NAME`, `WAF_SCOPE`(CLOUDFRONT 면 조회는 us-east-1) |
| `WebACL "…" 을(를) 찾지 못했습니다 … 규칙 적용을 중단했습니다` | 이름·scope 오타입니다. **다른 WebACL 을 덮어쓰지 않으려고 일부러 멈춘 것**이니 이름을 고치세요 |
| `ALB … 계정에 ALB 가 N개 있어 임의로 고르지 않았습니다` | `ALB_NAME` 을 지정하세요 |
| UA 통계가 비어 있어 규칙 조립 불가 | WAF 표본은 **규칙에 매칭된 요청만** 남습니다 → `WAF_LOG_GROUP` 을 지정하거나 광범위한 COUNT 규칙을 하나 추가 |
| 403 채점 키가 전부 0 | `WAF_LOG_GROUP` 미설정입니다. 앱 로그만으로는 차단 건수를 볼 수 없습니다 |
| 로그가 없음 | 시간 창 → `APP_LOG_GROUP` 이 `[GIN]` 라인이 있는 그룹인지 → 실제 유입 여부 |
| `…는 이미 사용 중입니다` | 이전 백엔드가 살아 있습니다. 종료하거나 `pnpm dev -p 3110` |
| 화면이 안 갱신됨 | 다른 창을 보고 있으면 폴링이 멈춥니다(의도된 동작). 창을 앞으로 가져오면 즉시 갱신됩니다 |

---

## 구조

```
backend/          Node.js + TypeScript, 빌드 없이 실행
  api/            node:http 라우터 (POST /api/*, 단일 응답 봉투)
  awsx/           CloudWatch · Logs Insights · WAF · EC2 · EKS
  kube/           Kubernetes 읽기와 Deployment 패치
  rules/          WAF 규칙 조립기와 로컬 평가 샌드박스
  analysis/       로그 파싱 · 이상 탐지 · 상관 · 마스킹
  live/           패널 조립과 TTL 캐시
  store/          SQLite (better-sqlite3)
src/              React + Vite 프런트엔드
docs/             RUNBOOK · 바이너리 분석
```

`src/lib/types.ts` 가 프런트와 백엔드가 공유하는 유일한 계약입니다.

## 라이선스

BSD-3-Clause. [`LICENSE`](LICENSE)
