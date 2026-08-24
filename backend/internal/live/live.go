// Package live is the real service.Provider: AWS reads through awsx,
// Kubernetes through kube, the rule engine through rules. It also owns the
// panel-level TTL caches the TS actions layer kept (kube 3s tier, metrics 30s
// tier, log reads 30s), including the cross-panel peeks the anomaly detector
// and the incident report depend on.
package live

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/analysis"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/awsx"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/cache"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/creds"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/kube"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/rules"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/service"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type Provider struct {
	AWS      *awsx.AWS
	Kube     *kube.Kube
	Store    *store.Store
	Settings *config.Settings
	Creds    *creds.Manager
	Now      func() time.Time

	// Guards the one-shot CloudTrail backfill behind the node-count panel.
	backfill backfillState
}

func New(settings *config.Settings, st *store.Store) *Provider {
	cm := creds.New(st)
	return &Provider{
		AWS:      awsx.New(settings, st, cm),
		Kube:     kube.New(settings, st, cm),
		Store:    st,
		Settings: settings,
		Creds:    cm,
		Now:      time.Now,
	}
}

// Reset drops every memoized client, so the next request rebuilds them against
// whatever credentials are in force now.
//
// It used to reset AWS only, and the asymmetry was invisible until it mattered:
// after injecting keys on the 설정 screen the AWS panels came back and the
// Kubernetes panel stayed broken for the life of the process, because
// internal/kube builds its clients once and EKS exec-auth resolves an identity
// when that client is built. Re-injecting could not fix it either — nothing was
// asking for a new client. A credential change has to invalidate every client
// built from the old ones, not the convenient half.
func (p *Provider) Reset() {
	p.AWS.Reset()
	p.Kube.Reset()
}

// BootstrapCredentials makes a fresh start behave like pressing the 설정
// 화면's CLI 불러오기 button once: when nothing else supplies a key — no
// persisted injection from a previous run, no environment key — the local
// `aws` CLI's profile is imported session-only. Best-effort by design: a
// machine with no aws CLI configured logs one line and runs exactly as before,
// with the settings screen still available to inject by hand.
func (p *Provider) BootstrapCredentials(ctx context.Context) {
	if p.Creds.Injected() != nil {
		// A persisted injection from a previous run is already in force, and it
		// was a deliberate choice — do not shadow it with the CLI session.
		return
	}
	env := creds.Parsed{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
	}
	if env.Complete() {
		// The environment is in charge; ImportProfile would refuse anyway.
		return
	}
	profile := creds.DefaultProfile()
	if _, err := p.Creds.ImportProfile(ctx, profile, false); err != nil {
		log.Printf("CLI 자격증명 자동 불러오기 실패 (profile %q): %v — 설정 탭에서 직접 불러올 수 있습니다", profile, err)
		return
	}
	// SDK clients capture the credential provider at construction, and the
	// Kubernetes exec plugin captures its environment the same way; anything
	// built before this import must be rebuilt.
	p.Reset()
	log.Printf("CLI 자격증명 자동 불러오기 완료 (profile %q, 세션 한정)", profile)
}

// windowKey: cache keys have to change when the window does, or a panel serves
// the previous span's numbers under the new label.
func windowKey(w types.ResolvedWindow) string {
	return fmt.Sprintf("%d-%d-%d", w.WindowMin, w.IntervalMin, w.EndMs)
}

// --- Kubernetes panel — 3s tier ---------------------------------------------

func (p *Provider) KubePanel(ctx context.Context) (types.KubePanel, error) {
	return cache.Cached("panel:kube", config.Polling.KubeTTL, func() (types.KubePanel, error) {
		// Eight reads, in two waves rather than one queue.
		//
		// They used to run strictly one after another inside a 3-second TTL
		// cache. With EKS exec-auth every one of them pays for an `aws eks
		// get-token` round trip — call it 300ms — so the whole panel took
		// longer to build than the cache entry it was building lived for, and
		// the cache was never once warm: every poll re-ran every call, and the
		// screen lagged permanently behind the cluster.
		//
		// The reads share no state, only a shape: four of them depend on the
		// results of the first wave (pod resources on the pod list, pod scaling
		// on the deployment list, node scaling on the node count), so they
		// cannot start until it lands. Everything else goes out together.
		//
		// Error semantics are unchanged on purpose. podsErr is still captured
		// here and still returned AFTER the panel is assembled, because that
		// ordering is what lets the recording side effect below see a complete
		// panel; the other reads still swallow their errors into empty defaults
		// or into their own *Error field, which is what the UI renders them as.
		var (
			pods         []types.PodInfo
			podsErr      error
			events       []types.WarningEvent
			deployments  []types.DeploymentInfo
			nodeListing  kube.NodeListing
			firstWaveWg  sync.WaitGroup
			secondWaveWg sync.WaitGroup
		)
		firstWaveWg.Add(4)
		go func() {
			defer firstWaveWg.Done()
			pods, podsErr = p.Kube.ListPods(ctx)
		}()
		go func() {
			defer firstWaveWg.Done()
			events, _ = p.Kube.ListWarningEvents(ctx)
		}()
		go func() {
			defer firstWaveWg.Done()
			deployments, _ = p.Kube.ListDeployments(ctx)
		}()
		go func() {
			defer firstWaveWg.Done()
			// One node listing for both the header count and the per-node
			// capacity denominators — it used to be fetched twice.
			nodeListing = p.Kube.ListNodes(ctx)
		}()
		firstWaveWg.Wait()

		if pods == nil {
			pods = []types.PodInfo{}
		}
		if events == nil {
			events = []types.WarningEvent{}
		}
		if deployments == nil {
			deployments = []types.DeploymentInfo{}
		}
		// A failed listing keeps its ignored-error default of zero nodes, as
		// before; the listing itself is passed on with its error intact so the
		// resource table can refuse to draw rather than divide by a capacity it
		// never read.
		nodesReady, nodesTotal := nodeListing.Ready, nodeListing.Total

		var (
			podResources      []types.PodResourceUsage
			podResourceError  *string
			nodeResources     []types.NodeResourceUsage
			nodeResourceError *string
			podScaling        []types.ScaleInfo
			nodeScaling       []types.ScaleInfo
			scalingError      *string
		)
		secondWaveWg.Add(4)
		go func() {
			defer secondWaveWg.Done()
			podResources, podResourceError = p.Kube.GetPodResourceUsage(ctx, pods)
		}()
		go func() {
			defer secondWaveWg.Done()
			nodeResources, nodeResourceError = p.Kube.GetNodeResourceUsageFrom(ctx, nodeListing)
		}()
		go func() {
			defer secondWaveWg.Done()
			podScaling = p.Kube.GetPodScaling(ctx, deployments)
		}()
		go func() {
			defer secondWaveWg.Done()
			nodeScaling, scalingError = p.nodeScaling(ctx, nodesTotal)
		}()
		secondWaveWg.Wait()

		panel := types.KubePanel{
			Pods:              pods,
			Events:            events,
			Deployments:       deployments,
			NodesReady:        nodesReady,
			NodesTotal:        nodesTotal,
			StatusBreakdown:   kube.SummarizePodStatus(pods),
			PodResources:      podResources,
			PodResourceError:  podResourceError,
			NodeResources:     nodeResources,
			NodeResourceError: nodeResourceError,
			PodScaling:        podScaling,
			NodeScaling:       nodeScaling,
			ScalingError:      scalingError,
		}
		if podsErr != nil {
			return types.KubePanel{}, podsErr
		}
		// metrics.k8s.io keeps no history, so the reading is appended here — on
		// the poll that already exists. Recording must never break the panel.
		_ = service.RecordResourceSamplesTo(p.Store, panel.PodResources, panel.NodeResources, p.Now().UnixMilli())
		return panel, nil
	}, 0)
}

func (p *Provider) nodeScaling(ctx context.Context, currentNodeCount int) ([]types.ScaleInfo, *string) {
	groups, err := p.AWS.DiscoverNodeGroupScaling(ctx)
	if err != nil {
		return []types.ScaleInfo{{
			Name: "cluster", Current: currentNodeCount,
			Source: "조회 실패: " + awsx.ErrMsg(err),
		}}, nil
	}
	if len(groups) == 0 {
		return []types.ScaleInfo{{
			Name: "cluster", Current: currentNodeCount,
			Source: "managed nodegroup 없음 (Karpenter 등 — min/max 미검출)",
		}}, nil
	}
	out := make([]types.ScaleInfo, 0, len(groups))
	for _, g := range groups {
		out = append(out, types.ScaleInfo{
			Name: g.Name, Current: g.DesiredSize,
			Min: types.Ptr(g.MinSize), Max: types.Ptr(g.MaxSize),
			Source: "EKS Managed Nodegroup",
		})
	}
	return out, nil
}

// --- metrics + analysis panel — 30s tier ------------------------------------

// visibleMetrics mirrors VISIBLE_METRICS in the TS actions layer.
var visibleMetrics = []string{
	"targetResponseTime", "http4xx", "http5xx",
	"rdsClientConnections", "rdsDatabaseConnections", "wafBlocked", "wafAllowed",
}

func (p *Provider) MetricsPanel(ctx context.Context, win types.ResolvedWindow) (types.MetricsPanel, error) {
	panel, err := cache.Cached("panel:metrics:"+windowKey(win), config.Polling.MetricsTTL, func() (types.MetricsPanel, error) {
		core, err := p.AWS.FetchCoreMetrics(ctx, win)
		if err != nil {
			return types.MetricsPanel{}, err
		}
		byKey := map[string]types.MetricSummary{}
		for _, m := range core.Summaries {
			byKey[m.Key] = m
		}
		var statusDist *types.StatusDistribution
		if c2, ok := byKey["http2xx"]; ok {
			c3 := byKey["http3xx"].Current
			c4 := byKey["http4xx"].Current
			c5 := byKey["http5xx"].Current
			statusDist = &types.StatusDistribution{
				C2xx: c2.Current, C3xx: c3, C4xx: c4, C5xx: c5,
				Total: c2.Current + c3 + c4 + c5,
			}
		}

		var httpSummary *types.HttpSummary
		var httpSummaryError *string
		if hs, err := p.AWS.BuildHttpSummary(ctx, statusDist, win); err == nil {
			httpSummary = &hs
		} else {
			httpSummaryError = types.Ptr(awsx.ErrMsg(err))
		}

		targetGroupMetrics := []types.TargetGroupMetrics{}
		var targetGroupError *string
		if tg, err := p.AWS.FetchTargetGroupMetrics(ctx, win); err == nil {
			targetGroupMetrics = tg
		} else {
			targetGroupError = types.Ptr(awsx.ErrMsg(err))
		}

		kubePanel, _ := cache.Peek[types.KubePanel]("panel:kube")
		fingerprints, _ := cache.Peek[[]types.FingerprintEntry]("panel:fingerprints")
		input := analysis.AnomalyInput{
			Metrics:      core.Summaries,
			HttpSummary:  httpSummary,
			Pods:         kubePanel.Pods,
			Events:       kubePanel.Events,
			Fingerprints: fingerprints,
		}
		now := p.Now()
		anomalies := analysis.DetectAnomalies(input, now)
		correlations := analysis.Correlate(anomalies)
		timeline := analysis.BuildTimeline(input, anomalies, p.historyInput(), now)

		visible := []types.MetricSummary{}
		for _, k := range visibleMetrics {
			if m, ok := byKey[k]; ok {
				visible = append(visible, m)
			}
		}
		metricErrors := core.Errors
		if metricErrors == nil {
			metricErrors = []string{}
		}
		return types.MetricsPanel{
			Metrics:           visible,
			MetricErrors:      metricErrors,
			TargetGroupMetric: targetGroupMetrics,
			TargetGroupError:  targetGroupError,
			HttpSummary:       httpSummary,
			HttpSummaryError:  httpSummaryError,
			Anomalies:         anomalies,
			Correlations:      correlations,
			Timeline:          timeline,
			Window:            win,
		}, nil
	}, 0)
	if err == nil {
		// The window-free alias other panels peek (grading's WAF-blocked figure,
		// the incident report).
		cache.Put("panel:metrics:latest", config.Polling.MetricsTTL, panel)
	}
	return panel, err
}

// historyInput folds SQLite history into the timeline; a missing DB must not
// take the panel down.
func (p *Provider) historyInput() analysis.HistoryInput {
	h := analysis.HistoryInput{}
	if events, err := p.Store.RecentRestartEvents(p.Now().UnixMilli() - 60*60_000); err == nil {
		for _, e := range events {
			h.RestartEvents = append(h.RestartEvents, analysis.RestartEvent{Pod: e.Pod, Ts: e.Ts, Delta: e.Delta})
		}
	}
	if rows, err := p.Store.ListDeployHistory(); err == nil {
		for _, r := range rows {
			h.DeployHistory = append(h.DeployHistory, types.DeployChangeEntry{
				ID: r.ID, Ts: time.UnixMilli(r.Ts).UTC().Format(time.RFC3339Nano),
				Namespace: r.Namespace, Name: r.Name, Change: r.Change, Verdict: r.Verdict,
			})
		}
	}
	if rows, err := p.Store.ListWafHistoryRows(); err == nil {
		for _, r := range rows {
			h.WafHistory = append(h.WafHistory, analysis.WafHistoryRow{
				ID: r.ID, Ts: r.Ts, RuleName: r.RuleName, Action: r.Action, Status: r.Status, Detail: r.Detail,
			})
		}
	}
	return h
}

// --- WAF panel — 30s tier ----------------------------------------------------

func (p *Provider) WafPanel(ctx context.Context, win types.ResolvedWindow) (types.WafPanel, error) {
	return cache.Cached("panel:waf:"+windowKey(win), config.Polling.WafTTL, func() (types.WafPanel, error) {
		panel := types.WafPanel{History: []types.ApplyHistoryEntry{}}
		if acl, err := p.AWS.GetAclInfo(ctx); err == nil {
			panel.Acl = &acl
		} else {
			panel.AclError = types.Ptr(awsx.ErrMsg(err))
		}
		if history, err := p.Store.ApplyHistory(); err == nil {
			panel.History = history
		}
		return panel, nil
	}, 0)
}

func (p *Provider) WafSamples(ctx context.Context) ([]types.WafSampleRow, error) {
	return p.AWS.ListSampleRows(ctx)
}

// --- grading — on-demand, cached like every other Insights read --------------

func (p *Provider) GradingPanel(ctx context.Context, win types.ResolvedWindow) (types.GradingPanel, error) {
	return cache.Cached("panel:grading:"+windowKey(win), config.Polling.LogCacheTTL, func() (types.GradingPanel, error) {
		return p.AWS.FetchGradingPanel(ctx, win)
	}, config.Polling.LogFailTTL)
}

// --- deployments -------------------------------------------------------------

func (p *Provider) Deployment(ctx context.Context, namespace, name string) (types.DeploymentInfo, error) {
	return p.Kube.GetDeployment(ctx, namespace, name)
}

func toKubePatch(req service.DeploymentPatchRequest) kube.PatchRequest {
	return kube.PatchRequest{
		Namespace:     req.Namespace,
		Name:          req.Name,
		Replicas:      req.Replicas,
		ContainerName: req.ContainerName,
		CPULimit:      req.CPULimit,
		MemLimit:      req.MemLimit,
	}
}

func (p *Provider) PatchDeployment(ctx context.Context, req service.DeploymentPatchRequest) (types.DeploymentInfo, error) {
	return p.Kube.PatchDeployment(ctx, toKubePatch(req))
}

// --- discovery / rules -------------------------------------------------------

func (p *Provider) Discover(ctx context.Context, kind string) (types.DiscoveryResult, error) {
	return p.AWS.Discover(ctx, kind)
}

func (p *Provider) assembleEnv() rules.AssembleEnv {
	return rules.AssembleEnv{WafScope: p.Settings.WafScope(), WafRegion: p.Settings.WafRegion()}
}

func (p *Provider) AssembleRule(ctx context.Context, kind string, win types.ResolvedWindow) (types.AssembledRule, error) {
	summary, err := p.AWS.BuildHttpSummary(ctx, nil, win)
	if err != nil {
		return types.AssembledRule{}, err
	}
	return rules.AssembleRule(kind, summary, p.assembleEnv())
}

func (p *Provider) TestRule(ctx context.Context, params service.RuleTestParams) (types.RuleTestResult, error) {
	return rules.TestRule(params.RuleJson, params.Requests)
}

// --- WAF rule apply ----------------------------------------------------------

// UpdateWafRule is apply, promote, demote and remove — one call, because the
// rule is keyed by its Name and "promote" is "put it back at the other action".
// Every press is a person's press; nothing on this screen changes a WebACL on
// its own.
//
// The grading keys as they stood at the moment of the change go into the
// history row with it. That snapshot is what the false-block alarm compares
// against five minutes later, and it has to be taken here, before the rule can
// have moved anything.
func (p *Provider) UpdateWafRule(ctx context.Context, ruleJson string, action *string, win types.ResolvedWindow) (types.WafRuleUpdateResult, error) {
	want := ""
	if action != nil {
		want = *action
	}
	snapshot := p.gradingSnapshot(win)
	update, err := p.AWS.SetRuleAction(ctx, ruleJson, want)
	if err != nil {
		// The attempt is recorded either way: an operator who pressed the
		// button and saw an error still changed nothing, and the history is
		// what the incident report reads.
		_, _ = p.Store.InsertWafHistory(nameOrPasted(ruleJson), actionLabel(want), "FAILED", awsx.ErrMsg(err), "", p.Now().UnixMilli())
		cache.Invalidate("panel:waf")
		return types.WafRuleUpdateResult{}, err
	}
	historyID, err := p.Store.InsertWafHistory(
		update.RuleName, actionLabel(want), "SUCCESS", snapshot, update.PriorRules, p.Now().UnixMilli())
	if err != nil {
		return types.WafRuleUpdateResult{}, err
	}
	// The rule list on screen is read from the WebACL, so it has to be re-read
	// rather than patched locally.
	cache.Invalidate("panel:waf")
	return types.WafRuleUpdateResult{RuleName: update.RuleName, HistoryID: historyID}, nil
}

func actionLabel(action string) string {
	if action == "" {
		return "REMOVE"
	}
	return action
}

// nameOrPasted is the best name available for a failed apply: the rule's own
// Name when the JSON parsed, and a placeholder when it did not.
func nameOrPasted(ruleJson string) string {
	var doc struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal([]byte(ruleJson), &doc); err == nil && doc.Name != "" {
		return doc.Name
	}
	return "(이름 없음)"
}

// gradingSnapshot is whatever the 성능 tab last aggregated, over the same window
// it is showing. Never re-queried here: a rule change is not a reason to spend
// an Insights scan, and a five-minute-old baseline is still the baseline the
// operator was looking at when they pressed the button.
func (p *Provider) gradingSnapshot(win types.ResolvedWindow) string {
	type key struct {
		Label string  `json:"label"`
		Pct   float64 `json:"pct"`
		Total int     `json:"total"`
	}
	out := struct {
		At   int64 `json:"at"`
		Keys []key `json:"keys"`
	}{At: p.Now().UnixMilli(), Keys: []key{}}
	if grading, ok := cache.Peek[types.GradingPanel]("panel:grading:" + windowKey(win)); ok {
		for _, l := range grading.Lines {
			out.Keys = append(out.Keys, key{Label: l.Label, Pct: l.Pct, Total: l.Total})
		}
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// --- AWS credentials ---------------------------------------------------------
//
// The keys never travel back to the browser: every method here returns the
// masked view, and the input is one-way.

func (p *Provider) CredentialsView(nowMs int64) (types.CredentialsView, error) {
	return p.Creds.View(nowMs), nil
}

func (p *Provider) SaveCredentials(ctx context.Context, in service.CredentialsInput) error {
	// The blob is parsed on the server as well as in the browser so a paste
	// that only the server sees (autofill, a form post) lands the same way.
	pasted := creds.Parsed{}
	if strings.TrimSpace(in.Blob) != "" {
		pasted = creds.ParseBlob(in.Blob)
	}
	pick := func(typed, fromBlob string) string {
		if strings.TrimSpace(typed) != "" {
			return typed
		}
		return fromBlob
	}
	_, err := p.Creds.Set(creds.SetInput{
		Parsed: creds.Parsed{
			AccessKeyID:     pick(in.AccessKeyID, pasted.AccessKeyID),
			SecretAccessKey: pick(in.SecretAccessKey, pasted.SecretAccessKey),
			SessionToken:    pick(in.SessionToken, pasted.SessionToken),
			Expiration:      pasted.Expiration,
		},
		Origin:  "paste",
		Persist: in.Persist,
	})
	return err
}

// ImportCredentials resolves the session the local `aws` profile is holding —
// SSO included — and injects it. This is the path that keeps working on its
// own: the provider re-reads the profile as the session token expires.
func (p *Provider) ImportCredentials(ctx context.Context, in service.ImportCredentialsInput) error {
	_, err := p.Creds.ImportProfile(ctx, in.Profile, in.Persist)
	return err
}

func (p *Provider) ClearCredentials(ctx context.Context) error {
	p.Creds.Clear()
	return nil
}

func (p *Provider) CheckCredentials(ctx context.Context) (types.CredentialCheck, error) {
	return p.AWS.CheckCredentials(ctx), nil
}
