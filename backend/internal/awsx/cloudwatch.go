package awsx

// CloudWatch metric fetch + summarisation, ported from cloudwatch.ts.

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type rawPoint struct {
	t int64
	v float64
}

type RawSeries struct {
	Key    string
	Label  string
	Unit   string
	Stat   string // "Average" | "Sum"
	Points []rawPoint
	// ThresholdKey lets a per-TG series borrow the shared threshold.
	ThresholdKey string
	// Metric is the CloudWatch metric this came from — what someone checking
	// the number in the console has to search for.
	Metric string
}

func toSeries(key, label, unit, stat, metric string, r *cwtypes.MetricDataResult, thresholdKey string) RawSeries {
	points := []rawPoint{}
	if r != nil {
		for i, t := range r.Timestamps {
			v := 0.0
			if i < len(r.Values) {
				v = r.Values[i]
			}
			points = append(points, rawPoint{t: t.UnixMilli(), v: v})
		}
		sort.Slice(points, func(i, j int) bool { return points[i].t < points[j].t })
	}
	return RawSeries{Key: key, Label: label, Unit: unit, Stat: stat, Points: points, ThresholdKey: thresholdKey, Metric: metric}
}

// aggBuckets buckets are aggregated into the headline number to smooth a
// single noisy bucket; every summary carries a basis saying what it counted.
const aggBuckets = 3

func round3f(n float64) float64 { return math.Round(n*1000) / 1000 }

func Summarize(s RawSeries, win types.ResolvedWindow) types.MetricSummary {
	// Drop the newest (possibly incomplete) bucket, then compare the last 3
	// complete buckets against the 3 before them.
	pts := s.Points
	if len(pts) > 0 {
		pts = pts[:len(pts)-1]
	}
	slice := func(from, to int) []rawPoint {
		if from < 0 {
			from = 0
		}
		if to < from {
			to = from
		}
		return pts[from:to]
	}
	currentWin := slice(len(pts)-aggBuckets, len(pts))
	prevWin := slice(len(pts)-2*aggBuckets, len(pts)-aggBuckets)
	// A Sum metric is normalised to a per-minute rate rather than left as a
	// bucket total — thresholds are absolute, so a raw total would make the
	// alert depend on the chosen interval.
	agg := func(w []rawPoint) float64 {
		if len(w) == 0 {
			return 0
		}
		sum := 0.0
		for _, p := range w {
			sum += p.v
		}
		if s.Stat == "Average" {
			return sum / float64(len(w))
		}
		return sum / (float64(len(w)) * float64(win.IntervalMin))
	}
	current := round3f(agg(currentWin))
	previous := round3f(agg(prevWin))
	delta := round3f(current - previous)
	var percentChange *float64
	switch {
	case previous > 0:
		percentChange = types.Ptr(round3f((current - previous) / previous * 100))
	case current > 0:
		percentChange = nil
	default:
		percentChange = types.Ptr(0.0)
	}
	points := make([]types.MetricPoint, 0, len(pts))
	for _, p := range pts {
		points = append(points, types.MetricPoint{
			T: time.UnixMilli(p.t).UTC().Format(time.RFC3339Nano),
			V: round3f(p.v),
		})
	}
	thresholdKey := s.ThresholdKey
	if thresholdKey == "" {
		thresholdKey = s.Key
	}
	basis := fmt.Sprintf("%s %s · ", s.Metric, s.Stat)
	if s.Stat == "Sum" {
		basis += fmt.Sprintf("최근 %d버킷(%d분) 합계를 분당으로 환산 · 직전 동일 구간과 비교", aggBuckets, aggBuckets*win.IntervalMin)
	} else {
		basis += fmt.Sprintf("최근 %d버킷(%d분) 평균 · 직전 동일 구간과 비교", aggBuckets, aggBuckets*win.IntervalMin)
	}
	return types.MetricSummary{
		Key:           s.Key,
		Label:         s.Label,
		Unit:          s.Unit,
		Current:       current,
		Previous:      previous,
		Delta:         delta,
		PercentChange: percentChange,
		Status:        config.StatusFor(thresholdKey, current, percentChange),
		Points:        points,
		Basis:         basis,
	}
}

type CoreMetricsResult struct {
	Summaries []types.MetricSummary
	Errors    []string
}

func q(id, namespace, metricName string, dims []cwtypes.Dimension, stat string, periodSec int32) cwtypes.MetricDataQuery {
	return cwtypes.MetricDataQuery{
		Id: aws.String(id),
		MetricStat: &cwtypes.MetricStat{
			Metric: &cwtypes.Metric{
				Namespace:  aws.String(namespace),
				MetricName: aws.String(metricName),
				Dimensions: dims,
			},
			Period: aws.Int32(periodSec),
			Stat:   aws.String(stat),
		},
		ReturnData: aws.Bool(true),
	}
}

func dim(name, value string) cwtypes.Dimension {
	return cwtypes.Dimension{Name: aws.String(name), Value: aws.String(value)}
}

func byID(results []cwtypes.MetricDataResult) map[string]*cwtypes.MetricDataResult {
	out := map[string]*cwtypes.MetricDataResult{}
	for i := range results {
		out[aws.ToString(results[i].Id)] = &results[i]
	}
	return out
}

func (a *AWS) FetchCoreMetrics(ctx context.Context, win types.ResolvedWindow) (CoreMetricsResult, error) {
	end := time.UnixMilli(win.EndMs)
	start := time.UnixMilli(win.StartMs)
	periodSec := int32(win.IntervalMin * 60)

	results := []RawSeries{}
	errors := []string{}

	// --- ALB + RDS Proxy (workload region) ---
	if err := func() error {
		alb, err := a.DiscoverAlb(ctx)
		if err != nil {
			return err
		}
		albDim := []cwtypes.Dimension{dim("LoadBalancer", alb.LoadBalancer)}
		rdsProxy := a.Settings.RdsProxyName()
		queries := []cwtypes.MetricDataQuery{
			q("trt", "AWS/ApplicationELB", "TargetResponseTime", albDim, "Average", periodSec),
			q("c4xx", "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", albDim, "Sum", periodSec),
			q("c5xx", "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", albDim, "Sum", periodSec),
			q("c2xx", "AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", albDim, "Sum", periodSec),
			q("c3xx", "AWS/ApplicationELB", "HTTPCode_Target_3XX_Count", albDim, "Sum", periodSec),
			q("reqs", "AWS/ApplicationELB", "RequestCount", albDim, "Sum", periodSec),
			q("rdscc", "AWS/RDS", "ClientConnections", []cwtypes.Dimension{dim("ProxyName", rdsProxy)}, "Average", periodSec),
			q("rdsdc", "AWS/RDS", "DatabaseConnections", []cwtypes.Dimension{dim("ProxyName", rdsProxy)}, "Average", periodSec),
		}
		client, err := a.cloudWatch(ctx, a.Settings.Region())
		if err != nil {
			return err
		}
		res, err := client.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
			StartTime: aws.Time(start), EndTime: aws.Time(end), MetricDataQueries: queries,
		})
		if err != nil {
			return err
		}
		m := byID(res.MetricDataResults)
		results = append(results,
			toSeries("targetResponseTime", "TargetResponseTime", "s", "Average", "AWS/ApplicationELB TargetResponseTime", m["trt"], ""),
			toSeries("http4xx", "Target 4XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_4XX_Count", m["c4xx"], ""),
			toSeries("http5xx", "Target 5XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_5XX_Count", m["c5xx"], ""),
			toSeries("http2xx", "Target 2XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_2XX_Count", m["c2xx"], ""),
			toSeries("http3xx", "Target 3XX", "req/min", "Sum", "AWS/ApplicationELB HTTPCode_Target_3XX_Count", m["c3xx"], ""),
			toSeries("requestCount", "RequestCount", "req/min", "Sum", "AWS/ApplicationELB RequestCount", m["reqs"], ""),
			toSeries("rdsClientConnections", "RDS Proxy Client Conn", "conn", "Average", fmt.Sprintf("AWS/RDS ClientConnections (ProxyName=%s)", rdsProxy), m["rdscc"], ""),
			toSeries("rdsDatabaseConnections", "RDS Proxy DB Conn", "conn", "Average", fmt.Sprintf("AWS/RDS DatabaseConnections (ProxyName=%s)", rdsProxy), m["rdsdc"], ""),
		)
		return nil
	}(); err != nil {
		errors = append(errors, "ALB/RDS metrics: "+ErrMsg(err))
	}

	// --- WAF Blocked/Allowed (us-east-1 for CLOUDFRONT scope) ---
	if err := func() error {
		aclName := a.Settings.WafWebAclName()
		dims := []cwtypes.Dimension{dim("WebACL", aclName), dim("Rule", "ALL")}
		if a.Settings.WafScope() != "CLOUDFRONT" {
			dims = append(dims, dim("Region", a.Settings.Region()))
		}
		client, err := a.cloudWatch(ctx, a.Settings.WafRegion())
		if err != nil {
			return err
		}
		res, err := client.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
			StartTime: aws.Time(start), EndTime: aws.Time(end),
			MetricDataQueries: []cwtypes.MetricDataQuery{
				q("wafb", "AWS/WAFV2", "BlockedRequests", dims, "Sum", periodSec),
				q("wafa", "AWS/WAFV2", "AllowedRequests", dims, "Sum", periodSec),
			},
		})
		if err != nil {
			return err
		}
		m := byID(res.MetricDataResults)
		results = append(results,
			toSeries("wafBlocked", "WAF BlockedRequests", "req/min", "Sum", fmt.Sprintf("AWS/WAFV2 BlockedRequests (WebACL=%s, Rule=ALL)", aclName), m["wafb"], ""),
			toSeries("wafAllowed", "WAF AllowedRequests", "req/min", "Sum", fmt.Sprintf("AWS/WAFV2 AllowedRequests (WebACL=%s, Rule=ALL)", aclName), m["wafa"], ""),
		)
		return nil
	}(); err != nil {
		errors = append(errors, "WAF metrics: "+ErrMsg(err))
	}

	if len(results) == 0 {
		msg := "no metric data"
		if len(errors) > 0 {
			msg = ""
			for i, e := range errors {
				if i > 0 {
					msg += " / "
				}
				msg += e
			}
		}
		return CoreMetricsResult{}, fmt.Errorf("%s", msg)
	}

	for _, s := range results {
		// metric cache failure must not break the panel
		samples := make([]store.Sample, 0, len(s.Points))
		for _, p := range s.Points {
			samples = append(samples, store.Sample{T: p.t, V: p.v})
		}
		_ = a.Store.SaveMetricSamples(s.Key, samples)
	}

	summaries := make([]types.MetricSummary, 0, len(results))
	for _, r := range results {
		summaries = append(summaries, Summarize(r, win))
	}
	return CoreMetricsResult{Summaries: summaries, Errors: errors}, nil
}

// FetchTargetGroupMetrics: per-Target-Group ALB metrics (spec item 3).
func (a *AWS) FetchTargetGroupMetrics(ctx context.Context, win types.ResolvedWindow) ([]types.TargetGroupMetrics, error) {
	end := time.UnixMilli(win.EndMs)
	start := time.UnixMilli(win.StartMs)
	periodSec := int32(win.IntervalMin * 60)
	alb, err := a.DiscoverAlb(ctx)
	if err != nil {
		return nil, err
	}
	if len(alb.TargetGroups) == 0 {
		return []types.TargetGroupMetrics{}, nil
	}

	queries := []cwtypes.MetricDataQuery{}
	for i, tg := range alb.TargetGroups {
		dims := []cwtypes.Dimension{dim("LoadBalancer", alb.LoadBalancer), dim("TargetGroup", tg.TgDim)}
		queries = append(queries,
			q(fmt.Sprintf("tg%dtrt", i), "AWS/ApplicationELB", "TargetResponseTime", dims, "Average", periodSec),
			q(fmt.Sprintf("tg%dc4", i), "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", dims, "Sum", periodSec),
			q(fmt.Sprintf("tg%dc5", i), "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", dims, "Sum", periodSec),
		)
	}
	client, err := a.cloudWatch(ctx, a.Settings.Region())
	if err != nil {
		return nil, err
	}
	res, err := client.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
		StartTime: aws.Time(start), EndTime: aws.Time(end), MetricDataQueries: queries,
	})
	if err != nil {
		return nil, err
	}
	m := byID(res.MetricDataResults)

	out := make([]types.TargetGroupMetrics, 0, len(alb.TargetGroups))
	for i, tg := range alb.TargetGroups {
		trt := Summarize(toSeries(
			fmt.Sprintf("tg-%s-trt", tg.Name), "TargetResponseTime", "s", "Average",
			fmt.Sprintf("AWS/ApplicationELB TargetResponseTime (TargetGroup=%s)", tg.Name),
			m[fmt.Sprintf("tg%dtrt", i)], "targetResponseTime"), win)
		c4 := Summarize(toSeries(
			fmt.Sprintf("tg-%s-4xx", tg.Name), "4XX", "req/min", "Sum",
			fmt.Sprintf("AWS/ApplicationELB HTTPCode_Target_4XX_Count (TargetGroup=%s)", tg.Name),
			m[fmt.Sprintf("tg%dc4", i)], "http4xx"), win)
		c5 := Summarize(toSeries(
			fmt.Sprintf("tg-%s-5xx", tg.Name), "5XX", "req/min", "Sum",
			fmt.Sprintf("AWS/ApplicationELB HTTPCode_Target_5XX_Count (TargetGroup=%s)", tg.Name),
			m[fmt.Sprintf("tg%dc5", i)], "http5xx"), win)
		out = append(out, types.TargetGroupMetrics{
			Name: tg.Name, PathPattern: tg.PathPattern, ResponseTime: trt, C4xx: c4, C5xx: c5,
		})
	}
	return out, nil
}
