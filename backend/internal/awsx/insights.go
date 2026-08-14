package awsx

// CloudWatch Logs Insights runner, ported from logsinsights.ts. One query with
// a hard deadline; the window is clamped so scan volume stays bounded no
// matter what the caller asks for. On deadline the query is stopped
// server-side (StopQuery).

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
)

type InsightsRow map[string]string

type InsightsResult struct {
	Rows           []InsightsRow
	BytesScanned   int64
	RecordsMatched int64
	WindowLabel    string
}

type InsightsParams struct {
	LogGroup string
	Query    string
	WindowMs int64
	// Explicit bounds from the page's shared window. Given these, the query
	// covers exactly the span every other panel covers.
	StartMs  *int64
	EndMs    *int64
	Deadline time.Duration
	// Which region's Logs endpoint holds this group. A CLOUDFRONT-scope WAF log
	// group only exists in us-east-1 — querying it from the workload region
	// returns ResourceNotFoundException, which reads as "logging is off".
	Region string
}

// RunInsightsQuery queues behind a small semaphore — Logs Insights allows few
// concurrent queries per account and each one costs money.
func (a *AWS) RunInsightsQuery(ctx context.Context, p InsightsParams) (InsightsResult, error) {
	deadline := p.Deadline
	if deadline == 0 {
		deadline = config.InsightsLimits.QueryDeadline
	}
	explicit := p.StartMs != nil && p.EndMs != nil
	var windowMs int64
	if explicit {
		windowMs = *p.EndMs - *p.StartMs
	} else if p.WindowMs > 0 {
		windowMs = p.WindowMs
	} else {
		windowMs = config.InsightsLimits.DefaultWindow.Milliseconds()
	}
	// The cap applies either way: it is what bounds bytes scanned.
	if max := config.InsightsLimits.MaxWindow.Milliseconds(); windowMs > max {
		windowMs = max
	}
	endMs := time.Now().UnixMilli()
	if explicit {
		endMs = *p.EndMs
	}
	endSec := endMs / 1000
	startSec := endSec - windowMs/1000
	windowLabel := fmt.Sprintf("%dm", (windowMs+30_000)/60_000)

	region := p.Region
	if region == "" {
		region = a.Settings.Region()
	}
	client, err := a.logs(ctx, region)
	if err != nil {
		return InsightsResult{}, err
	}

	select {
	case a.insightsSem <- struct{}{}:
	case <-ctx.Done():
		return InsightsResult{}, ctx.Err()
	}
	defer func() { <-a.insightsSem }()

	started, err := client.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupName: aws.String(p.LogGroup),
		StartTime:    aws.Int64(startSec),
		EndTime:      aws.Int64(endSec),
		QueryString:  aws.String(p.Query),
	})
	if err != nil {
		return InsightsResult{}, err
	}
	if started.QueryId == nil {
		return InsightsResult{}, fmt.Errorf("StartQuery failed (no queryId)")
	}
	queryID := started.QueryId

	stop := time.Now().Add(deadline)
	for {
		select {
		case <-time.After(700 * time.Millisecond):
		case <-ctx.Done():
			return InsightsResult{}, ctx.Err()
		}
		res, err := client.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: queryID})
		if err != nil {
			return InsightsResult{}, err
		}
		switch res.Status {
		case cwltypes.QueryStatusComplete:
			rows := make([]InsightsRow, 0, len(res.Results))
			for _, fields := range res.Results {
				row := InsightsRow{}
				for _, f := range fields {
					if f.Field != nil && f.Value != nil {
						row[*f.Field] = *f.Value
					}
				}
				rows = append(rows, row)
			}
			out := InsightsResult{Rows: rows, WindowLabel: windowLabel}
			if res.Statistics != nil {
				out.BytesScanned = int64(res.Statistics.BytesScanned)
				out.RecordsMatched = int64(res.Statistics.RecordsMatched)
			}
			return out, nil
		case cwltypes.QueryStatusFailed, cwltypes.QueryStatusCancelled, cwltypes.QueryStatusTimeout:
			return InsightsResult{}, fmt.Errorf("Logs Insights query %s", res.Status)
		}
		if time.Now().After(stop) {
			// best effort — the deadline error is the one that matters
			_, _ = client.StopQuery(ctx, &cloudwatchlogs.StopQueryInput{QueryId: queryID})
			return InsightsResult{}, fmt.Errorf("Logs Insights 쿼리 데드라인 초과 (%.0fs)", deadline.Seconds())
		}
	}
}

func FmtBytes(n int64) string {
	switch {
	case n >= 1024*1024*1024:
		return fmt.Sprintf("%.2fGB", float64(n)/1024/1024/1024)
	case n >= 1024*1024:
		return fmt.Sprintf("%.2fMB", float64(n)/1024/1024)
	case n >= 1024:
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
