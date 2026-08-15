package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// Provider is everything this service cannot answer from its own SQLite file:
// AWS reads (CloudWatch, Logs Insights, WAFv2, ELBv2, EKS), Kubernetes reads and
// writes, and the WAFv2 rule engine that the sandbox evaluates against.
//
// It is an interface with one implementation on purpose. The routes and the
// local state are the deliverable here; the cloud reads are a separate,
// credential-holding concern, and keeping them behind this seam means the HTTP
// surface can be run, tested and pointed at by the UI without a single call
// leaving the machine. Swapping Unavailable{} for a real implementation is the
// only change needed to light the rest up.
type Provider interface {
	// Reset drops anything the provider memoized against the previous settings
	// (SDK clients capture a region at construction). Called on settings save.
	Reset()
	KubePanel(ctx context.Context) (types.KubePanel, error)
	MetricsPanel(ctx context.Context, win types.ResolvedWindow) (types.MetricsPanel, error)
	WafPanel(ctx context.Context, win types.ResolvedWindow) (types.WafPanel, error)
	WafSamples(ctx context.Context) ([]types.WafSampleRow, error)
	GradingPanel(ctx context.Context, win types.ResolvedWindow) (types.GradingPanel, error)
	PodLogs(ctx context.Context, p PodLogsParams, win types.ResolvedWindow) (types.PodLogsResult, error)
	RequestLogRows(ctx context.Context, p RequestLogParams, win types.ResolvedWindow) (types.RequestLogQueryResult, error)
	Deployment(ctx context.Context, namespace, name string) (types.DeploymentInfo, error)
	PatchDeployment(ctx context.Context, req DeploymentPatchRequest) (types.DeploymentInfo, error)
	Discover(ctx context.Context, kind string) (types.DiscoveryResult, error)
	AssembleRule(ctx context.Context, kind string, win types.ResolvedWindow) (types.AssembledRule, error)
	TestRule(ctx context.Context, p RuleTestParams) (types.RuleTestResult, error)
	IncidentContext(ctx context.Context) (types.IncidentContextResult, error)
	UpdateWafRule(ctx context.Context, ruleJson string, action *string, win types.ResolvedWindow) (types.WafRuleUpdateResult, error)
	CountEvidence(ctx context.Context, ruleName string, win types.ResolvedWindow) (types.CountEvidence, error)
	WafLogRows(ctx context.Context, p WafLogParams, win types.ResolvedWindow) (types.WafLogQueryResult, error)
	NodeCost(ctx context.Context) (types.NodeCountProjection, error)

	// Credentials are a provider concern for the same reason the reads are:
	// they are the thing that makes a cloud call possible, and a build with no
	// cloud layer wired up has nothing to inject them into.
	CredentialsView(nowMs int64) (types.CredentialsView, error)
	SaveCredentials(ctx context.Context, in CredentialsInput) error
	ImportCredentials(ctx context.Context, in ImportCredentialsInput) error
	ClearCredentials(ctx context.Context) error
	CheckCredentials(ctx context.Context) (types.CredentialCheck, error)
}

// ErrUnavailable is what every unported capability returns. It is a plain
// failed ActionResult on the wire, which is exactly what the UI already renders
// for an AWS call that did not work.
var ErrUnavailable = errors.New("연동 미구성")

func unavailable(what string) error {
	return fmt.Errorf("%s: %w — 이 백엔드는 로컬 상태(SQLite·설정·샌드박스 데이터·점검)만 제공합니다", what, ErrUnavailable)
}

// Unavailable is the default Provider: it makes no network calls at all and
// reports, per capability, that it is not wired up.
type Unavailable struct{}

func (Unavailable) Reset() {}

func (Unavailable) KubePanel(context.Context) (types.KubePanel, error) {
	return types.KubePanel{}, unavailable("Kubernetes 패널")
}

func (Unavailable) MetricsPanel(context.Context, types.ResolvedWindow) (types.MetricsPanel, error) {
	return types.MetricsPanel{}, unavailable("CloudWatch 지표 패널")
}

func (Unavailable) WafPanel(context.Context, types.ResolvedWindow) (types.WafPanel, error) {
	return types.WafPanel{}, unavailable("WAF 패널")
}

func (Unavailable) WafSamples(context.Context) ([]types.WafSampleRow, error) {
	return nil, unavailable("WAF 샘플 요청")
}

func (Unavailable) GradingPanel(context.Context, types.ResolvedWindow) (types.GradingPanel, error) {
	return types.GradingPanel{}, unavailable("채점 패널")
}

func (Unavailable) PodLogs(context.Context, PodLogsParams, types.ResolvedWindow) (types.PodLogsResult, error) {
	return types.PodLogsResult{}, unavailable("Pod 로그")
}

func (Unavailable) RequestLogRows(context.Context, RequestLogParams, types.ResolvedWindow) (types.RequestLogQueryResult, error) {
	return types.RequestLogQueryResult{}, unavailable("요청 로그 조회")
}

func (Unavailable) Deployment(context.Context, string, string) (types.DeploymentInfo, error) {
	return types.DeploymentInfo{}, unavailable("Deployment 조회")
}

func (Unavailable) PatchDeployment(context.Context, DeploymentPatchRequest) (types.DeploymentInfo, error) {
	return types.DeploymentInfo{}, unavailable("Deployment 변경")
}

func (Unavailable) Discover(context.Context, string) (types.DiscoveryResult, error) {
	return types.DiscoveryResult{}, unavailable("리소스 자동 탐색")
}

func (Unavailable) AssembleRule(context.Context, string, types.ResolvedWindow) (types.AssembledRule, error) {
	return types.AssembledRule{}, unavailable("규칙 자동 조립")
}

func (Unavailable) TestRule(context.Context, RuleTestParams) (types.RuleTestResult, error) {
	return types.RuleTestResult{}, unavailable("규칙 시뮬레이터")
}

func (Unavailable) IncidentContext(context.Context) (types.IncidentContextResult, error) {
	return types.IncidentContextResult{}, unavailable("인시던트 컨텍스트")
}

func (Unavailable) UpdateWafRule(context.Context, string, *string, types.ResolvedWindow) (types.WafRuleUpdateResult, error) {
	return types.WafRuleUpdateResult{}, unavailable("WAF 규칙 변경")
}

func (Unavailable) CountEvidence(context.Context, string, types.ResolvedWindow) (types.CountEvidence, error) {
	return types.CountEvidence{}, unavailable("WAF 차단 근거 분석")
}

func (Unavailable) WafLogRows(context.Context, WafLogParams, types.ResolvedWindow) (types.WafLogQueryResult, error) {
	return types.WafLogQueryResult{}, unavailable("WAF 로그 조회")
}

func (Unavailable) NodeCost(context.Context) (types.NodeCountProjection, error) {
	return types.NodeCountProjection{}, unavailable("비용/노드 수 산출")
}

func (Unavailable) CredentialsView(int64) (types.CredentialsView, error) {
	return types.CredentialsView{}, unavailable("AWS 자격증명 조회")
}

func (Unavailable) SaveCredentials(context.Context, CredentialsInput) error {
	return unavailable("AWS 자격증명 주입")
}

func (Unavailable) ImportCredentials(context.Context, ImportCredentialsInput) error {
	return unavailable("aws 프로파일 세션 불러오기")
}

func (Unavailable) ClearCredentials(context.Context) error {
	return unavailable("AWS 자격증명 해제")
}

func (Unavailable) CheckCredentials(context.Context) (types.CredentialCheck, error) {
	return types.CredentialCheck{}, unavailable("AWS 자격증명 확인")
}
