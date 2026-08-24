대회장에서 AWS·Kubernetes·WAF 를 한 화면으로 보는 운영 대시보드입니다.
읽기가 기본이고, 쓰기는 두 가지(Deployment 조정, WAF 규칙 적용)뿐이며 둘 다 누르기 전에 확인 화면을 거칩니다.

- **경기 당일 절차**는 [`docs/RUNBOOK.md`](docs/RUNBOOK.md) 를 보세요. 이 문서는 구축과 사용법입니다.
- **용어**(비정상 요청 403 · 미지정 경로 404 등)는 [`CONTEXT.md`](CONTEXT.md) 를 따릅니다.
- **과제 바이너리가 실제로 찍는 로그**는 [`docs/binaries.md`](docs/binaries.md) 에 정리돼 있습니다.

---

## 대회장에서 — 파일 하나만 받으면 됩니다

빌드 도구가 필요 없습니다. Go 도 Node 도 pnpm 도 필요 없습니다 — 화면이 바이너리 안에 들어 있습니다.

1. [Releases](../../releases) 에서 운영체제에 맞는 파일을 받습니다.
   - Windows: `skills-dashboard-windows-amd64.exe`
   - Linux: `skills-dashboard-linux-amd64`
   - macOS(Apple Silicon): `skills-dashboard-darwin-arm64`
2. 그냥 실행합니다.
   ```bash
   # Windows
   .\skills-dashboard-windows-amd64.exe
   # Linux / macOS (실행 권한을 준 뒤)
   chmod +x ./skills-dashboard-linux-amd64 && ./skills-dashboard-linux-amd64
   ```
3. 브라우저로 **`http://127.0.0.1:8787/dashboard`** 를 엽니다. (UI·API 를 같은 바이너리가 서빙하므로 프록시 설정이 없습니다.)
4. **톱니 → `AWS 자격증명` → `aws CLI 세션 불러오기` → `연결 확인`.** 로컬에 `aws` CLI 가 로그인돼 있으면 첫 실행 때 자동으로 불러옵니다.

> 포트를 바꾸려면 `API_ADDR=127.0.0.1:8799` 환경변수를 주고 실행하거나, **실행 파일 옆에 `.env` 를 두면 됩니다** — 바이너리가 자기 폴더의 `.env` 를 직접 읽습니다(아래 `.env` 절 참고).
> SQLite 파일은 실행 위치의 `./data/dashboard.db` 에 생깁니다 — 설정과 주입한 자격증명이 여기 남으므로 재시작해도 유지됩니다(세션 한정 주입은 제외).

경기 당일 절차는 [`docs/RUNBOOK.md`](docs/RUNBOOK.md), 채점 키·바이너리 로그는 [`docs/binaries.md`](docs/binaries.md) 를 보세요.

---

## 소스에서 빌드 (선택)

릴리스 바이너리를 쓰면 이 절은 건너뛰어도 됩니다. 직접 빌드하려면 Go 1.24+ 와 Node 24 가 필요합니다.

```bash
corepack enable pnpm
pnpm install --frozen-lockfile
pnpm build:frontend               # dist/ 생성
cp -r dist backend/webdist        # 바이너리에 넣을 화면
cd backend
CGO_ENABLED=0 go build -tags embed -o ../skills-dashboard .
```

`-tags embed` 없이 빌드하면 API 만 서빙하는 개발용 바이너리가 나옵니다(화면은 `pnpm dev:frontend` 가 따로 띄웁니다).

---

## 구축 — 자격증명과 설정

위 방법으로 실행한 뒤, 처음 한 번 채워 두면 됩니다.

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

### 3-1. `.env` (선택 — 값을 미리 채워 두기)

설정 화면에서 손으로 넣어도 되지만, 같은 값을 매번 다시 넣기 싫다면 `.env` 에 적어 두면 됩니다.
**바이너리가 시작할 때 이 파일을 직접 읽습니다** — mise·direnv·dotenv-cli 같은 런처가 없어도 됩니다.
찾는 순서는 `ENV_FILE` 로 지정한 경로 → 현재 작업 디렉터리 → **실행 파일이 있는 폴더** 입니다.
마지막 항목 덕분에 릴리스 바이너리를 탐색기에서 더블클릭해도 옆에 둔 `.env` 가 그대로 먹습니다.

```bash
cp .env.example .env        # PowerShell: copy .env.example .env
```

우선순위는 뒤로 갈수록 강합니다:

`.env`  <  실제 환경변수  <  대시보드 설정(톱니 → SQLite)

- 값이 비어 있으면 그 줄은 무시합니다. `.env.example` 이 AWS 키를 빈 칸으로 두는 이유이기도 합니다 — 빈 값이 CLI 세션 주입을 가리면 안 되니까요.
- 이미 export 된 환경변수는 `.env` 가 덮지 않습니다. `API_ADDR=… ./skills-dashboard-windows-amd64.exe` 로 그때만 다르게 띄울 수 있습니다.
- `.env` 는 `.gitignore` 에 있습니다. **자격 증명을 커밋하지 마세요.**

기동 로그의 `env <경로> — N개 적용` 줄로 어떤 파일이 실제로 읽혔는지 확인할 수 있습니다.

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
| `APP_LOG_GROUP` | `[GIN]` 액세스 라인이 들어 있는 그룹. EKS 라면 Container Insights 의 `/aws/containerinsights/<클러스터>/application`. 여러 그룹으로 나뉘면 쉼표로 나열 |
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

- 화면이 **가려져 있으면 폴링이 멈춥니다.** 다른 탭·다른 창을 보는 동안에는 AWS 호출도, 차트 다시 그리기도 하지 않고, 돌아오면 즉시 한 번 새로 읽습니다. 최소화해 두는 것이 가장 확실한 절약입니다.

  > **단, 채점 창(경기 시작 +1h ~ +3h) 동안에는 대시보드를 앞에 두세요.** Pod·Node 사용률 이력은
  > 화면이 폴링할 때만 기록되므로, 가려 두면 그 구간의 그래프에 구멍이 생깁니다. 채점에 들어가는
  > 노드 대수는 CloudTrail 로 메워지니 영향이 없지만, 사용률 그래프는 되살릴 수 없습니다.
- 상단 **`갱신`** 을 `5초` → `30초` 로 올리면 렌더 비용이 그만큼 내려갑니다. 서버 캐시가 따로 있어 값이 낡지는 않습니다.
- 시간 창을 `4h` 로 두면 차트 점이 많아집니다. 평소에는 `1h` 로 두세요.
- 로그 터미널의 `tail` 을 2000 으로 두면 DOM 이 무거워집니다. `200` 이 기본이고 대개 충분합니다.
- 백엔드는 유휴 시 40–80MB 정도입니다. 브라우저가 대부분의 비용입니다.

---

## 대시보드 사용법

시간 창(`15m/30m/1h/2h/4h`)은 세 탭이 공유합니다.

### 1. PERFORMANCE — 상시 감시
- **채점기 입력값** — `image download` · `Exception Handling` · `(api) availability` · `(api) performance`. 채점기 로그(`results_<비번호>.log`)와 같은 키 이름이고, 각 줄에 **지금 어느 채점 구간인지와 다음 구간까지 남은 %p** 가 함께 나옵니다. 점수는 매기지 않습니다.
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
| `Exception Handling` 이 낮거나 0 | `WAF_LOG_GROUP` 미설정이면 403 쪽 분자가 안 보입니다. 설정 후에도 낮으면 미지정 경로가 404 로 끝나는지 확인 |
| 로그가 없음 | 시간 창 → `APP_LOG_GROUP` 이 `[GIN]` 라인이 있는 그룹인지 → 실제 유입 여부 |
| `…는 이미 사용 중입니다` | 이전 백엔드가 살아 있습니다. 종료하거나 `pnpm dev -p 3110` |
| 화면이 안 갱신됨 | 다른 창을 보고 있으면 폴링이 멈춥니다(의도된 동작). 창을 앞으로 가져오면 즉시 갱신됩니다 |

---

## 구조

```
backend/          Go (Fiber) — 릴리스는 프런트를 임베드한 단일 바이너리
  internal/api/   Fiber 라우터 (POST /api/*, 단일 응답 봉투)
  awsx/           CloudWatch · Logs Insights · WAF · EC2 · EKS
  kube/           Kubernetes 읽기와 Deployment 패치
  rules/          WAF 규칙 조립기와 로컬 평가 샌드박스
  analysis/       로그 파싱 · 이상 탐지 · 상관 · 마스킹
  live/           패널 조립과 TTL 캐시
  store/          SQLite (modernc.org/sqlite, 순수 Go)
src/              React + Vite 프런트엔드
docs/             RUNBOOK · 바이너리 분석
```

프런트엔드(`src/`)는 Node 판과 동일합니다 — 같은 JSON 계약(`src/lib/types.ts`)을 두 백엔드가 함께 씁니다.

## 라이선스

BSD-3-Clause. [`LICENSE`](LICENSE)
