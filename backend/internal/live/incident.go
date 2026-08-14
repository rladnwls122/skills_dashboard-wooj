package live

// Incident context generation (spec §17, §18), ported from the
// generateIncidentContextAction flow: fetch the two panels (cached), peek the
// cross-panel caches, fold in SQLite history, render.

import (
	"context"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/analysis"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/cache"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/service"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func (p *Provider) IncidentContext(ctx context.Context) (types.IncidentContextResult, error) {
	now := p.Now()
	win := service.ResolveWindow(nil, now.UnixMilli())

	var metrics *types.MetricsPanel
	if m, err := p.MetricsPanel(ctx, win); err == nil {
		metrics = &m
	}
	var kubePanel *types.KubePanel
	if k, err := p.KubePanel(ctx); err == nil {
		kubePanel = &k
	}
	fingerprints, _ := cache.Peek[[]types.FingerprintEntry]("panel:fingerprints")
	verifications, _ := cache.Peek[[]types.VerificationResult]("panel:verifications")

	var logs, prevLogs *analysis.LogsRef
	if l, ok := cache.Peek[analysis.LogsRef]("panel:lastlogs"); ok {
		logs = &l
	}
	if l, ok := cache.Peek[analysis.LogsRef]("panel:lastprevlogs"); ok {
		prevLogs = &l
	}

	parts := analysis.IncidentParts{
		Fingerprints:  fingerprints,
		Logs:          logs,
		PreviousLogs:  prevLogs,
		Verifications: verifications,
	}
	if metrics != nil {
		parts.Metrics = metrics.Metrics
		parts.HttpSummary = metrics.HttpSummary
		parts.Anomalies = metrics.Anomalies
		parts.Correlations = metrics.Correlations
		parts.Timeline = metrics.Timeline
	}
	parts.Kube = kubePanel

	// History unavailable — snapshot proceeds with live data only.
	if rows, err := p.Store.ListWafHistoryRows(); err == nil {
		for _, h := range rows {
			parts.WafHistory = append(parts.WafHistory, analysis.WafHistoryEntry{
				Ts:       time.UnixMilli(h.Ts).UTC().Format(time.RFC3339Nano),
				RuleName: h.RuleName, Action: h.Action, Status: h.Status, Detail: h.Detail,
			})
		}
	}
	if rows, err := p.Store.ListDeployHistory(); err == nil {
		for _, d := range rows {
			parts.DeployHistory = append(parts.DeployHistory, analysis.DeployHistoryEntry{
				Ts:     time.UnixMilli(d.Ts).UTC().Format(time.RFC3339Nano),
				Target: d.Namespace + "/" + d.Name, Change: d.Change, Verdict: d.Verdict,
			})
		}
	}

	snapshot := analysis.BuildSnapshot(parts, now)
	json := analysis.ToJson(snapshot)
	// Persisting the snapshot is best-effort.
	_ = p.Store.SaveIncidentSnapshot(json, now.UnixMilli())

	return types.IncidentContextResult{
		Markdown:    analysis.ToMarkdown(snapshot),
		Json:        json,
		QPrompt:     analysis.ToQPrompt(snapshot),
		GeneratedAt: snapshot.Timestamp,
	}, nil
}
