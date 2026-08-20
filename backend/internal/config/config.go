// Package config resolves every value the service runs on.
//
// Two sources, in order: an override saved on the settings screen (SQLite),
// then the process environment. No .env file is parsed here — the process is
// started with an environment, and how that environment is populated is the
// launcher's business, not this service's.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// Server is the process-level configuration, read once at start.
type Server struct {
	Addr           string
	DBPath         string
	AllowedOrigins string
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func LoadServer() Server {
	return Server{
		// Loopback by default: this is a single-operator tool holding AWS
		// credentials, so binding 0.0.0.0 has to be a deliberate act.
		Addr:   env("API_ADDR", "127.0.0.1:8787"),
		DBPath: env("DB_PATH", "./data/dashboard.db"),
		// The dev server runs on 3100 (see mise.toml).
		AllowedOrigins: env("CORS_ALLOW_ORIGINS", "http://localhost:3100,http://127.0.0.1:3100"),
	}
}

// Polling mirrors src/lib/server/config.ts POLLING.
var Polling = struct {
	KubeTTL           time.Duration
	MetricsTTL        time.Duration
	WafTTL            time.Duration
	LogCacheTTL       time.Duration
	LogFailTTL        time.Duration
	VerificationDelay time.Duration
}{
	KubeTTL:           3 * time.Second,
	MetricsTTL:        30 * time.Second,
	WafTTL:            30 * time.Second,
	LogCacheTTL:       30 * time.Second,
	LogFailTTL:        10 * time.Second,
	VerificationDelay: 60 * time.Second,
}

// --- settings ---------------------------------------------------------------

// Specs is the settings screen, in display order. Mirrors SETTING_SPECS in
// src/lib/server/settings.ts.
var Specs = []types.SettingSpec{
	{Key: "AWS_REGION", Label: "AWS 리전", Hint: "워크로드(ALB·RDS·EKS)가 있는 리전. WAF 가 CLOUDFRONT scope 면 WAF 만 us-east-1 로 자동 전환됩니다.", Discover: nil},
	{Key: "WAF_SCOPE", Label: "WAF Scope", Hint: "CLOUDFRONT 또는 REGIONAL. CloudFront 배포에 붙은 WebACL 은 CLOUDFRONT 이고 us-east-1 에서만 조회됩니다.", Discover: nil},
	{Key: "WAF_WEB_ACL_NAME", Label: "WebACL 이름", Hint: "규칙 목록과 샘플 요청을 읽는 대상.", Discover: types.Ptr("webacl")},
	{Key: "WAF_LOG_GROUP", Label: "WAF 로그 그룹", Hint: "비어 있으면 GetSampledRequests(규칙에 매칭된 요청만, 규칙당 500건)로 떨어집니다. 지정하면 선택 구간 전수 집계로 바뀌고 User-Agent 통계가 채워집니다.", Discover: types.Ptr("waflog")},
	{Key: "ALB_NAME", Label: "ALB 이름", Hint: "TargetResponseTime·상태코드 지표와 Target Group 자동 탐색의 기준.", Discover: types.Ptr("alb")},
	{Key: "EKS_CLUSTER_NAME", Label: "EKS 클러스터", Hint: "노드 스케일링 조회에 사용. 앱 로그 그룹 기본값도 이 이름에서 만들어집니다.", Discover: types.Ptr("eks")},
	{Key: "RDS_PROXY_NAME", Label: "RDS Proxy 이름", Hint: "AWS/RDS 지표의 ProxyName 차원 값.", Discover: types.Ptr("rdsproxy")},
	{Key: "APP_LOG_GROUP", Label: "앱 로그 그룹", Hint: "요청 로그·채점 지표 집계에 쓰는 CloudWatch Logs 그룹. 앱이 ECS awslogs 로 서비스마다 따로 쓰면 쉼표로 여러 개 (예: /ecs/user,/ecs/product,/ecs/stress). [GIN] 액세스 라인이 들어 있는 그룹이어야 한다.", Discover: types.Ptr("loggroup")},
	{Key: "TARGET_NAMESPACE", Label: "Kubernetes 네임스페이스", Hint: "Pod·Deployment·이벤트를 읽는 네임스페이스.", Discover: nil},
	{Key: "MAX_REPLICAS", Label: "최대 replica", Hint: "Deployment 조정 화면이 허용하는 상한.", Discover: nil},
	{Key: "MATCH_START", Label: "경기 시작 시각", Hint: "채점 창(경기 시작 +1h ~ +3h)의 기준. 로컬 시각으로 2026-08-14 09:00 또는 09:00 형태. 비워 두면 비용 패널이 평균을 만들지 않고 현재 대수만 보여줍니다.", Discover: nil},
}

// Settings reads through the override table on every access. The table has ten
// rows, and a cache here would need invalidating from the save path in a way
// that is easy to get wrong — a setting that appears to save and then does not
// is the worst outcome.
type Settings struct {
	store *store.Store
}

func NewSettings(s *store.Store) *Settings { return &Settings{store: s} }

func (s *Settings) overrides() map[string]string {
	// A missing or locked database must not take the dashboard down — the
	// environment still works.
	if s.store == nil {
		return map[string]string{}
	}
	m, err := s.store.LoadSettings()
	if err != nil {
		return map[string]string{}
	}
	return m
}

func builtin(key string, value func(string) string) string {
	switch key {
	case "AWS_REGION":
		return "ap-northeast-2"
	case "WAF_SCOPE":
		return "CLOUDFRONT"
	case "WAF_WEB_ACL_NAME":
		return "skills-waf"
	case "WAF_LOG_GROUP":
		return ""
	case "ALB_NAME":
		return "skills-alb"
	case "EKS_CLUSTER_NAME":
		return "skills-eks"
	case "RDS_PROXY_NAME":
		return "skills-db-proxy"
	case "APP_LOG_GROUP":
		// Depends on the cluster name, which is itself overridable.
		return "/aws/containerinsights/" + value("EKS_CLUSTER_NAME") + "/application"
	case "TARGET_NAMESPACE":
		return "default"
	case "MAX_REPLICAS":
		return "20"
	case "MATCH_START":
		// Deliberately empty. The scoring window is derived from this value,
		// and a guessed start time produces a time-weighted average that is
		// wrong in a way the screen cannot show — so the cost panel says "not
		// set" instead of inventing a provisional number.
		return ""
	}
	return ""
}

// Value is the setting in force: override beats environment, environment beats
// the built-in default.
func (s *Settings) Value(key string) string {
	if o := s.overrides()[key]; o != "" {
		return o
	}
	if e := os.Getenv(key); e != "" {
		return e
	}
	return builtin(key, s.Value)
}

func (s *Settings) Source(key string) string {
	if o := s.overrides()[key]; o != "" {
		return "screen"
	}
	if os.Getenv(key) != "" {
		return "env"
	}
	return "default"
}

func (s *Settings) MaxReplicas() int {
	n, err := strconv.Atoi(s.Value("MAX_REPLICAS"))
	if err != nil || n <= 0 {
		return 20
	}
	return n
}

// Save applies a patch. Unknown keys are ignored rather than rejected: an old
// client sending a retired key should not fail the whole save.
func (s *Settings) Save(patch map[string]string) error {
	now := time.Now().UnixMilli()
	for k, v := range patch {
		known := false
		for _, spec := range Specs {
			if spec.Key == k {
				known = true
				break
			}
		}
		if !known {
			continue
		}
		if err := s.store.SaveSetting(k, strings.TrimSpace(v), now); err != nil {
			return err
		}
	}
	return nil
}

// View is what the settings screen renders: every key with its value, where the
// value came from, and what the environment alone would have produced — the
// last one is what makes a screen override reversible.
func (s *Settings) View() types.SettingsView {
	rows := make([]types.SettingRow, 0, len(Specs))
	var envText []string
	for _, spec := range Specs {
		rows = append(rows, types.SettingRow{
			SettingSpec:  spec,
			Value:        s.Value(spec.Key),
			Source:       s.Source(spec.Key),
			EnvValue:     os.Getenv(spec.Key),
			DefaultValue: builtin(spec.Key, s.Value),
		})
		if s.Source(spec.Key) == "screen" {
			envText = append(envText, spec.Key+"="+s.Value(spec.Key))
		}
	}
	return types.SettingsView{Rows: rows, EnvText: strings.Join(envText, "\n")}
}
