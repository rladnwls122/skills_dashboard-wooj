package live

// Node count over the scoring window — the reading, the recording and the
// one-shot backfill. The arithmetic is in internal/nodecost.

import (
	"context"
	"sync"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/awsx"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/nodecost"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// Backfill runs once per process, on the first read that has a window to fill.
// A button would leave the panel quietly wrong until someone remembered to
// press it; a retry loop would re-scan CloudTrail every 30s for an error that is
// almost always a missing permission.
type backfillState struct {
	mu        sync.Mutex
	attempted bool
	note      string
}

func (p *Provider) recordNodeCount(count int, nowMs int64) {
	t := nowMs / nodecost.GridMs * nodecost.GridMs
	// Recording must never take the panel down: the count on screen is a live
	// reading, and only the cumulative average depends on the row landing.
	_ = p.Store.SaveMetricSamples(nodecost.SampleKey, []store.Sample{{T: t, V: float64(count)}})
}

func (p *Provider) loadNodeSamples(fromMs int64) []nodecost.Sample {
	rows, err := p.Store.LoadMetricSamples(nodecost.SampleKey, fromMs)
	if err != nil {
		return nil
	}
	out := make([]nodecost.Sample, 0, len(rows))
	for _, r := range rows {
		out = append(out, nodecost.Sample{T: r.T, V: r.V})
	}
	return out
}

// backfillOnce fills the stretches the dashboard was not running for, from
// CloudTrail's RunInstances/TerminateInstances history.
func (p *Provider) backfillOnce(ctx context.Context, win types.ScoringWindow, current int, nowMs int64) string {
	p.backfill.mu.Lock()
	defer p.backfill.mu.Unlock()
	if p.backfill.attempted {
		return p.backfill.note
	}
	from := win.StartMs
	to := win.EndMs
	if nowMs < to {
		to = nowMs
	}
	if to <= from {
		// There is nothing to reconstruct yet, so this was not an attempt.
		// Marking it as one before this check burned the single one-shot on
		// whoever opened the 비용 panel before the scoring window opened — and
		// the stretch the dashboard was not running for then stayed empty for
		// the rest of the process's life, with no note saying why.
		return ""
	}
	p.backfill.attempted = true

	runs, err := p.AWS.LookupInstanceEvents(ctx, "RunInstances", from, to)
	if err == nil {
		var terms []types.CloudTrailEvent
		terms, err = p.AWS.LookupInstanceEvents(ctx, "TerminateInstances", from, to)
		if err == nil {
			samples := nodecost.Reconstruct(nodecost.ParseTrailEvents(append(runs, terms...)), current, from, to)
			rows := make([]store.Sample, 0, len(samples))
			for _, s := range samples {
				rows = append(rows, store.Sample{T: s.T, V: s.V})
			}
			// ponytail: SaveMetricSamples prunes rows older than 6h, which
			// covers a 3h match. A window that opened longer ago than that
			// cannot be backfilled — raise the prune horizon if this is ever
			// used outside a contest day.
			if err = p.Store.SaveMetricSamples(nodecost.SampleKey, rows); err == nil {
				return ""
			}
		}
	}
	p.backfill.note = "CloudTrail 조회에 실패해 대시보드가 꺼져 있던 구간을 메우지 못했습니다 (" +
		awsx.ErrMsg(err) + "). 누적 평균은 이 화면이 켜져 있던 구간만 반영합니다."
	return p.backfill.note
}

// NodeCost is one call for the whole panel. It records the live reading as a
// side effect so the caller does not need a second scheduler for it.
func (p *Provider) NodeCost(ctx context.Context) (types.NodeCountProjection, error) {
	rows, err := p.AWS.DescribeRunningInstances(ctx)
	if err != nil {
		return types.NodeCountProjection{}, err
	}
	inCluster := 0
	for _, r := range rows {
		if r.ClusterTag != nil {
			inCluster++
		}
	}
	nowMs := p.Now().UnixMilli()
	p.recordNodeCount(inCluster, nowMs)

	offSpec := nodecost.OffSpec(rows, p.Settings.Region())
	startMs, ok := nodecost.ParseMatchStart(p.Settings.Value("MATCH_START"), nowMs)
	if !ok {
		// No match start: the count is real, the average is not computable, and
		// the panel says so rather than showing a provisional figure.
		return types.NodeCountProjection{
			Current: types.Ptr(inCluster),
			OffSpec: offSpec,
			Notes:   []string{"경기 시작 시각이 설정되지 않아 채점 창 평균을 계산하지 않습니다. 설정에서 MATCH_START 를 입력하세요."},
		}, nil
	}

	win := nodecost.Window(startMs)
	notes := []string{}
	if note := p.backfillOnce(ctx, win, inCluster, nowMs); note != "" {
		notes = append(notes, note)
	}
	if nowMs < win.StartMs {
		notes = append(notes, "채점 창이 아직 시작되지 않았습니다.")
	}
	if nowMs > win.EndMs {
		notes = append(notes, "채점 창이 끝났습니다. 값은 확정입니다.")
	}
	proj := nodecost.Project(p.loadNodeSamples(win.StartMs), types.Ptr(inCluster), win, nowMs)
	return types.NodeCountProjection{
		Window:              &win,
		Current:             proj.Current,
		ElapsedMin:          proj.ElapsedMin,
		RemainingMin:        proj.RemainingMin,
		CumulativeAvg:       proj.CumulativeAvg,
		FinalAvg:            proj.FinalAvg,
		MarginalPerInstance: proj.MarginalPerInstance,
		OffSpec:             offSpec,
		Notes:               notes,
	}, nil
}
