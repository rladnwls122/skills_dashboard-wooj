// Package service holds the dashboard's behaviour. Every method here maps 1:1
// to a public server action of the Next.js backend it replaces, so the HTTP
// layer above it is a thin envelope and the UI contract does not move.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/cache"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type Service struct {
	Store    *store.Store
	Settings *config.Settings
	Provider Provider
	// Now is injectable so window resolution and the verification delay are
	// testable without sleeping.
	Now func() time.Time
}

func New(st *store.Store, settings *config.Settings, provider Provider) *Service {
	if provider == nil {
		provider = Unavailable{}
	}
	return &Service{Store: st, Settings: settings, Provider: provider, Now: time.Now}
}

func (s *Service) nowMs() int64 { return s.Now().UnixMilli() }

func (s *Service) window(sel *types.WindowSelection) types.ResolvedWindow {
	return ResolveWindow(sel, s.nowMs())
}

// --- request payloads --------------------------------------------------------

type PodLogsParams struct {
	Pod       string                 `json:"pod"`
	Container string                 `json:"container"`
	Previous  bool                   `json:"previous"`
	TailLines int                    `json:"tailLines"`
	Window    *types.WindowSelection `json:"window"`
}

type RequestLogParams struct {
	StatusClass  string                 `json:"statusClass"`
	PathContains string                 `json:"pathContains"`
	Window       *types.WindowSelection `json:"window"`
}

type DeploymentPatchRequest struct {
	Namespace     string  `json:"namespace"`
	Name          string  `json:"name"`
	Replicas      *int    `json:"replicas,omitempty"`
	ContainerName *string `json:"containerName,omitempty"`
	CPULimit      *string `json:"cpuLimit,omitempty"`
	MemLimit      *string `json:"memLimit,omitempty"`
}

type RuleTestParams struct {
	RuleJson string              `json:"ruleJson"`
	Requests []types.TestRequest `json:"requests"`
}

// WafLogParams is the WAF log table's filter: "ALL" | "BLOCK" | "ALLOW" |
// "COUNT" and a path substring.
type WafLogParams struct {
	Action       string                 `json:"action"`
	PathContains string                 `json:"pathContains"`
	Window       *types.WindowSelection `json:"window"`
}

// CredentialsInput is typed in, or pasted as a blob — an `export` block, an
// .env fragment, a `~/.aws/credentials` section, the JSON the CLI prints. The
// three fields win over the blob when both are given.
type CredentialsInput struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Blob            string `json:"blob"`
	// false (the default) keeps the keys in this process's memory only.
	Persist bool `json:"persist"`
}

type ImportCredentialsInput struct {
	Profile string `json:"profile"`
	Persist bool   `json:"persist"`
}

// --- cloud-backed panels -----------------------------------------------------

func (s *Service) KubePanel(ctx context.Context) (types.KubePanel, error) {
	return s.Provider.KubePanel(ctx)
}

func (s *Service) MetricsPanel(ctx context.Context, sel *types.WindowSelection) (types.MetricsPanel, error) {
	return s.Provider.MetricsPanel(ctx, s.window(sel))
}

func (s *Service) WafPanel(ctx context.Context, sel *types.WindowSelection) (types.WafPanel, error) {
	return s.Provider.WafPanel(ctx, s.window(sel))
}

func (s *Service) WafSamples(ctx context.Context) ([]types.WafSampleRow, error) {
	return s.Provider.WafSamples(ctx)
}

func (s *Service) GradingPanel(ctx context.Context, sel *types.WindowSelection) (types.GradingPanel, error) {
	return s.Provider.GradingPanel(ctx, s.window(sel))
}

func (s *Service) PodLogs(ctx context.Context, p PodLogsParams) (types.PodLogsResult, error) {
	return s.Provider.PodLogs(ctx, p, s.window(p.Window))
}

func (s *Service) RequestLogRows(ctx context.Context, p RequestLogParams) (types.RequestLogQueryResult, error) {
	return s.Provider.RequestLogRows(ctx, p, s.window(p.Window))
}

func (s *Service) Discover(ctx context.Context, kind string) (types.DiscoveryResult, error) {
	return s.Provider.Discover(ctx, kind)
}

func (s *Service) IncidentContext(ctx context.Context) (types.IncidentContextResult, error) {
	return s.Provider.IncidentContext(ctx)
}

func (s *Service) AssembleRule(ctx context.Context, kind string, sel *types.WindowSelection) (types.AssembledRule, error) {
	return s.Provider.AssembleRule(ctx, kind, s.window(sel))
}

func (s *Service) TestRule(ctx context.Context, p RuleTestParams) (types.RuleTestResult, error) {
	return s.Provider.TestRule(ctx, p)
}

func (s *Service) UpdateWafRule(ctx context.Context, ruleJson string, action *string, sel *types.WindowSelection) (types.WafRuleUpdateResult, error) {
	return s.Provider.UpdateWafRule(ctx, ruleJson, action, s.window(sel))
}

func (s *Service) CountEvidence(ctx context.Context, ruleName string, sel *types.WindowSelection) (types.CountEvidence, error) {
	return s.Provider.CountEvidence(ctx, ruleName, s.window(sel))
}

func (s *Service) WafLogRows(ctx context.Context, p WafLogParams) (types.WafLogQueryResult, error) {
	return s.Provider.WafLogRows(ctx, p, s.window(p.Window))
}

func (s *Service) NodeCost(ctx context.Context) (types.NodeCountProjection, error) {
	return s.Provider.NodeCost(ctx)
}

// --- AWS credentials ---------------------------------------------------------
//
// The keys never travel back to the browser: every method here answers with the
// masked view, and the input is one-way.

func (s *Service) Credentials() (types.CredentialsView, error) {
	return s.Provider.CredentialsView(s.nowMs())
}

// applied is what every credential change returns. Injecting changes which
// account every panel is reading, so the SDK clients and every cached answer
// taken with the previous identity have to go — the same reasoning as a
// settings save, for the same reason.
func (s *Service) applied(ctx context.Context) (types.CredentialsResult, error) {
	s.Provider.Reset()
	cache.Invalidate("")
	view, err := s.Provider.CredentialsView(s.nowMs())
	if err != nil {
		return types.CredentialsResult{}, err
	}
	check, err := s.Provider.CheckCredentials(ctx)
	if err != nil {
		return types.CredentialsResult{}, err
	}
	return types.CredentialsResult{View: view, Check: check}, nil
}

func (s *Service) SaveCredentials(ctx context.Context, in CredentialsInput) (types.CredentialsResult, error) {
	if err := s.Provider.SaveCredentials(ctx, in); err != nil {
		return types.CredentialsResult{}, err
	}
	return s.applied(ctx)
}

func (s *Service) ImportCredentials(ctx context.Context, in ImportCredentialsInput) (types.CredentialsResult, error) {
	if err := s.Provider.ImportCredentials(ctx, in); err != nil {
		return types.CredentialsResult{}, err
	}
	return s.applied(ctx)
}

func (s *Service) ClearCredentials(ctx context.Context) (types.CredentialsResult, error) {
	if err := s.Provider.ClearCredentials(ctx); err != nil {
		return types.CredentialsResult{}, err
	}
	return s.applied(ctx)
}

// CheckCredentials makes the probe call without changing anything, so the
// caches other panels are serving from are left alone.
func (s *Service) CheckCredentials(ctx context.Context) (types.CredentialsResult, error) {
	view, err := s.Provider.CredentialsView(s.nowMs())
	if err != nil {
		return types.CredentialsResult{}, err
	}
	check, err := s.Provider.CheckCredentials(ctx)
	if err != nil {
		return types.CredentialsResult{}, err
	}
	return types.CredentialsResult{View: view, Check: check}, nil
}

// --- local: history, settings, sandbox data, probe ---------------------------

func (s *Service) WafHistory() ([]types.ApplyHistoryEntry, error) {
	return s.Store.ApplyHistory()
}

func (s *Service) SettingsView() types.SettingsView {
	return s.Settings.View()
}

// SaveSettings changes which account and region every panel reads, so
// anything cached against the previous selection is now describing the wrong
// thing, and the SDK clients still hold the old region — both are dropped.
func (s *Service) SaveSettings(patch map[string]string) (types.SettingsView, error) {
	if err := s.Settings.Save(patch); err != nil {
		return types.SettingsView{}, err
	}
	s.Provider.Reset()
	// "" is a prefix of every key, so this clears the lot.
	cache.Invalidate("")
	return s.Settings.View(), nil
}

func (s *Service) DefaultTestRequests() []types.TestRequest   { return DefaultTestRequests() }
func (s *Service) MaliciousTestRequests() []types.TestRequest { return MaliciousExampleRequests() }

func (s *Service) Probe(ctx context.Context, url string, expectStatus *int) (types.ProbeResult, error) {
	return Probe(ctx, url, expectStatus)
}

func (s *Service) ListDeployHistory() ([]types.DeployChangeEntry, error) {
	rows, err := s.Store.ListDeployHistory()
	if err != nil {
		return nil, err
	}
	out := make([]types.DeployChangeEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, types.DeployChangeEntry{
			ID:        r.ID,
			Ts:        time.UnixMilli(r.Ts).UTC().Format(time.RFC3339Nano),
			Namespace: r.Namespace,
			Name:      r.Name,
			Change:    r.Change,
			Verdict:   r.Verdict,
		})
	}
	return out, nil
}

// --- deployments -------------------------------------------------------------

var nameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// Validate rejects before anything is sent to the cluster (spec §22): the
// namespace is pinned to the configured one, names must be DNS labels, and the
// replica count is bounded by MAX_REPLICAS.
func (s *Service) Validate(req DeploymentPatchRequest) error {
	if !nameRe.MatchString(req.Namespace) {
		return fmt.Errorf("invalid namespace: %s", req.Namespace)
	}
	if target := s.Settings.Value("TARGET_NAMESPACE"); req.Namespace != target {
		return fmt.Errorf("namespace must be %s", target)
	}
	if !nameRe.MatchString(req.Name) {
		return fmt.Errorf("invalid deployment name: %s", req.Name)
	}
	if req.Replicas != nil {
		max := s.Settings.MaxReplicas()
		if *req.Replicas < 0 || *req.Replicas > max {
			return fmt.Errorf("replicas out of range (0..%d): %d", max, *req.Replicas)
		}
	}
	return nil
}

func (s *Service) Deployment(ctx context.Context, namespace, name string) (types.DeploymentInfo, error) {
	return s.Provider.Deployment(ctx, namespace, name)
}

// PreviewPatch validates and reads back the current state without changing
// anything — the confirm screen's data.
func (s *Service) PreviewPatch(ctx context.Context, req DeploymentPatchRequest) (types.DeploymentInfo, error) {
	if err := s.Validate(req); err != nil {
		return types.DeploymentInfo{}, err
	}
	return s.Provider.Deployment(ctx, req.Namespace, req.Name)
}

type PatchResult struct {
	HistoryID int                  `json:"historyId"`
	After     types.DeploymentInfo `json:"after"`
}

// PatchDeployment records the metric snapshot taken at change time, so the
// verification below has something to compare against.
func (s *Service) PatchDeployment(ctx context.Context, req DeploymentPatchRequest) (PatchResult, error) {
	if err := s.Validate(req); err != nil {
		return PatchResult{}, err
	}
	before := s.snapshotBefore(ctx, req.Name)
	parts := []string{}
	if req.Replicas != nil {
		parts = append(parts, fmt.Sprintf("replicas=%d", *req.Replicas))
	}
	if req.CPULimit != nil {
		parts = append(parts, "cpuLimit="+*req.CPULimit)
	}
	if req.MemLimit != nil {
		parts = append(parts, "memLimit="+*req.MemLimit)
	}
	after, err := s.Provider.PatchDeployment(ctx, req)
	if err != nil {
		return PatchResult{}, err
	}
	raw, err := json.Marshal(before)
	if err != nil {
		return PatchResult{}, err
	}
	id, err := s.Store.InsertDeployHistory(req.Namespace, req.Name, strings.Join(parts, ", "), string(raw), s.nowMs())
	if err != nil {
		return PatchResult{}, err
	}
	return PatchResult{HistoryID: id, After: after}, nil
}

// beforeSnapshot is the metric reading at change time. -1 means "not known",
// which the comparison reports as "비교 불가" rather than treating as zero.
type beforeSnapshot struct {
	Trt      float64 `json:"trt"`
	C4xx     float64 `json:"c4xx"`
	C5xx     float64 `json:"c5xx"`
	Restarts float64 `json:"restarts"`
}

func (s *Service) snapshotBefore(ctx context.Context, deployName string) beforeSnapshot {
	snap := beforeSnapshot{Trt: -1, C4xx: -1, C5xx: -1, Restarts: -1}
	if m, err := s.Provider.MetricsPanel(ctx, s.window(nil)); err == nil {
		snap.Trt = metricValue(m, "targetResponseTime")
		snap.C4xx = metricValue(m, "http4xx")
		snap.C5xx = metricValue(m, "http5xx")
	}
	if k, err := s.Provider.KubePanel(ctx); err == nil {
		total := 0
		for _, p := range k.Pods {
			if strings.HasPrefix(p.Name, deployName) {
				total += p.TotalRestarts
			}
		}
		snap.Restarts = float64(total)
	}
	return snap
}

func metricValue(m types.MetricsPanel, key string) float64 {
	for _, x := range m.Metrics {
		if x.Key == key {
			return x.Current
		}
	}
	return -1
}

// Verify compares metrics and pods against the snapshot taken at patch time
// (spec §23). Causality is never claimed.
func (s *Service) Verify(ctx context.Context, historyID int) (types.VerificationResult, error) {
	row, err := s.Store.GetDeployHistory(historyID)
	if err != nil {
		return types.VerificationResult{}, err
	}
	if row == nil {
		return types.VerificationResult{}, fmt.Errorf("이력 없음: %d", historyID)
	}
	now := s.Now()
	elapsed := time.Duration(now.UnixMilli()-row.Ts) * time.Millisecond
	if elapsed < config.Polling.VerificationDelay {
		wait := int(math.Ceil((config.Polling.VerificationDelay - elapsed).Seconds()))
		return types.VerificationResult{
			ActionID:  historyID,
			Verdict:   "INCONCLUSIVE",
			CheckedAt: now.UTC().Format(time.RFC3339Nano),
			Details: []string{fmt.Sprintf(
				"변경 후 %d초 경과 — 롤아웃 안정화 대기 (약 %d초 후 재검증)",
				int(math.Round(elapsed.Seconds())), wait,
			)},
		}, nil
	}

	var before beforeSnapshot
	if err := json.Unmarshal([]byte(row.MetricsBefore), &before); err != nil {
		return types.VerificationResult{}, err
	}
	metrics, err := s.Provider.MetricsPanel(ctx, s.window(nil))
	if err != nil {
		return types.VerificationResult{}, fmt.Errorf("CloudWatch 조회 실패: %w", err)
	}
	nowSnap := beforeSnapshot{
		Trt:      metricValue(metrics, "targetResponseTime"),
		C4xx:     metricValue(metrics, "http4xx"),
		C5xx:     metricValue(metrics, "http5xx"),
		Restarts: -1,
	}
	if kube, err := s.Provider.KubePanel(ctx); err == nil {
		total := 0
		for _, p := range kube.Pods {
			if strings.HasPrefix(p.Name, row.Name) {
				total += p.TotalRestarts
			}
		}
		nowSnap.Restarts = float64(total)
	}

	deployment, err := s.Provider.Deployment(ctx, row.Namespace, row.Name)
	if err != nil {
		return types.VerificationResult{}, err
	}
	rolloutOk := deployment.ReadyReplicas >= deployment.Replicas && deployment.Replicas > 0
	details := []string{fmt.Sprintf("Deployment %s: ready %d/%d%s", row.Name,
		deployment.ReadyReplicas, deployment.Replicas, map[bool]string{true: "", false: " — 롤아웃 미완료"}[rolloutOk])}

	improved, degraded := 0, 0
	cmp := func(label string, b, n float64) {
		if b < 0 || n < 0 {
			details = append(details, label+": 이전 값 없음 — 비교 불가")
			return
		}
		diff := n - b
		pct := 0
		switch {
		case b > 0:
			pct = int(math.Round(diff / b * 100))
		case diff > 0:
			pct = 100
		}
		sign := ""
		if pct >= 0 {
			sign = "+"
		}
		details = append(details, fmt.Sprintf("%s: %g → %g (%s%d%%)", label, b, n, sign, pct))
		// Below 20% is noise on a dashboard reading one-minute buckets.
		if pct > -20 && pct < 20 {
			return
		}
		if diff < 0 {
			improved++
		} else {
			degraded++
		}
	}
	cmp("TargetResponseTime", before.Trt, nowSnap.Trt)
	cmp("4XX/min", before.C4xx, nowSnap.C4xx)
	cmp("5XX/min", before.C5xx, nowSnap.C5xx)
	if before.Restarts >= 0 && nowSnap.Restarts >= 0 && nowSnap.Restarts > before.Restarts {
		degraded++
		details = append(details, fmt.Sprintf("재시작 수 증가: %g → %g", before.Restarts, nowSnap.Restarts))
	}

	verdict := "NO_CHANGE"
	switch {
	case !rolloutOk:
		verdict = "INCONCLUSIVE"
	case degraded > 0 && degraded >= improved:
		verdict = "DEGRADED"
	case improved > 0:
		verdict = "IMPROVED"
	}
	details = append(details, "주의: 메트릭 변화와 변경 조치의 인과관계는 확정할 수 없음")
	if err := s.Store.UpdateDeployVerdict(historyID, verdict); err != nil {
		return types.VerificationResult{}, err
	}
	result := types.VerificationResult{
		ActionID:  historyID,
		Verdict:   verdict,
		CheckedAt: now.UTC().Format(time.RFC3339Nano),
		Details:   details,
	}
	// Kept for the incident report, replacing any earlier verdict for the same
	// action (mirrors the "panel:verifications" cache in the TS actions layer).
	prior, _ := cache.Peek[[]types.VerificationResult]("panel:verifications")
	kept := make([]types.VerificationResult, 0, len(prior)+1)
	for _, v := range prior {
		if v.ActionID != historyID {
			kept = append(kept, v)
		}
	}
	cache.Put("panel:verifications", time.Hour, append(kept, result))
	return result, nil
}

// --- resource history --------------------------------------------------------

// Pod and node usage over time. metrics.k8s.io answers "what is it right now"
// and keeps no history, so the kube poll appends readings to SQLite and the
// charts read them back over the shared window. Read-only here: asking for a
// chart never triggers a cluster call.
const resPrefix = "res:"

func (s *Service) ResourceHistory(sel *types.WindowSelection) (types.ResourceHistory, error) {
	win := s.window(sel)
	out := types.ResourceHistory{
		PodCPU:  []types.NamedSeries{},
		PodMem:  []types.NamedSeries{},
		NodeCPU: []types.NamedSeries{},
		NodeMem: []types.NamedSeries{},
	}
	keys, err := s.Store.ListMetricKeys(resPrefix, win.StartMs)
	if err != nil {
		return out, err
	}
	for _, key := range keys {
		kind, metric, name, ok := parseSampleKey(key)
		if !ok {
			continue
		}
		rows, err := s.Store.LoadMetricSamples(key, win.StartMs)
		if err != nil {
			return out, err
		}
		points := []types.MetricPoint{}
		for _, r := range rows {
			if r.T < win.StartMs || r.T > win.EndMs {
				continue
			}
			points = append(points, types.MetricPoint{
				T: time.UnixMilli(r.T).UTC().Format(time.RFC3339Nano),
				V: math.Round(r.V*10) / 10,
			})
		}
		// A series with nothing in the window is dropped rather than returned
		// empty — an empty line in a legend is a name with no data behind it.
		if len(points) == 0 {
			continue
		}
		series := types.NamedSeries{Label: name, Points: points}
		switch {
		case kind == "pod" && metric == "cpu":
			out.PodCPU = append(out.PodCPU, series)
		case kind == "pod":
			out.PodMem = append(out.PodMem, series)
		case metric == "cpu":
			out.NodeCPU = append(out.NodeCPU, series)
		default:
			out.NodeMem = append(out.NodeMem, series)
		}
	}
	for _, list := range [][]types.NamedSeries{out.PodCPU, out.PodMem, out.NodeCPU, out.NodeMem} {
		sort.Slice(list, func(i, j int) bool { return list[i].Label < list[j].Label })
	}
	return out, nil
}

// Names can contain almost anything, so the name goes last and the parser splits
// on a fixed number of leading fields rather than on every colon.
func parseSampleKey(key string) (kind, metric, name string, ok bool) {
	rest, found := strings.CutPrefix(key, resPrefix)
	if !found {
		return "", "", "", false
	}
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) != 3 || parts[2] == "" {
		return "", "", "", false
	}
	kind, metric, name = parts[0], parts[1], parts[2]
	if kind != "pod" && kind != "node" {
		return "", "", "", false
	}
	if metric != "cpu" && metric != "mem" {
		return "", "", "", false
	}
	return kind, metric, name, true
}

// RecordResourceSamples appends one reading per series, floored to a 10-second
// grid: the kube panel polls every 3s, and three rows per pod per 10 seconds is
// detail nobody reads at three times the table size. The primary key is (key, t),
// so the floor makes repeated writes within one bucket idempotent.
func (s *Service) RecordResourceSamples(pods []types.PodResourceUsage, nodes []types.NodeResourceUsage, nowMs int64) error {
	return RecordResourceSamplesTo(s.Store, pods, nodes, nowMs)
}

// RecordResourceSamplesTo is the free-function form so the live provider can
// record on the kube-panel poll without holding a *Service.
func RecordResourceSamplesTo(st *store.Store, pods []types.PodResourceUsage, nodes []types.NodeResourceUsage, nowMs int64) error {
	const gridMs = 10_000
	t := nowMs / gridMs * gridMs
	write := func(kind, metric, name string, v *float64) error {
		// A pod with no limit set has no percentage. Writing 0 would draw a
		// floor that reads as "idle" when it means "not measurable".
		if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) {
			return nil
		}
		return st.SaveMetricSamples(resPrefix+kind+":"+metric+":"+name, []store.Sample{{T: t, V: *v}})
	}
	for _, p := range pods {
		if err := write("pod", "cpu", p.Pod, p.CPUPct); err != nil {
			return err
		}
		if err := write("pod", "mem", p.Pod, p.MemPct); err != nil {
			return err
		}
	}
	for _, n := range nodes {
		if err := write("node", "cpu", n.Name, &n.CPUPct); err != nil {
			return err
		}
		if err := write("node", "mem", n.Name, &n.MemPct); err != nil {
			return err
		}
	}
	return nil
}
