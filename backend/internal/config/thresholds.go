package config

// Metric thresholds and limits, ported from src/lib/server/config.ts.

import "time"

type MetricThreshold struct {
	// WARNING when (abs >= WarnAbs) OR (pct >= WarnPct AND abs >= MinAbs).
	// CRITICAL requires BOTH abs >= CritAbs AND pct >= CritPct — a single
	// criterion is never enough (false-positive guard, spec §8).
	WarnAbs, CritAbs, WarnPct, CritPct, MinAbs float64
}

var Thresholds = map[string]MetricThreshold{
	"targetResponseTime":     {WarnAbs: 0.5, CritAbs: 2.0, WarnPct: 80, CritPct: 200, MinAbs: 0.2},
	"http4xx":                {WarnAbs: 50, CritAbs: 300, WarnPct: 100, CritPct: 300, MinAbs: 20},
	"http5xx":                {WarnAbs: 20, CritAbs: 100, WarnPct: 100, CritPct: 300, MinAbs: 10},
	"rdsClientConnections":   {WarnAbs: 80, CritAbs: 200, WarnPct: 80, CritPct: 200, MinAbs: 20},
	"rdsDatabaseConnections": {WarnAbs: 60, CritAbs: 150, WarnPct: 80, CritPct: 200, MinAbs: 15},
	"wafBlocked":             {WarnAbs: 50, CritAbs: 500, WarnPct: 100, CritPct: 400, MinAbs: 20},
}

func StatusFor(key string, current float64, percentChange *float64) string {
	t, ok := Thresholds[key]
	if !ok {
		return "NORMAL"
	}
	pct := 0.0
	if percentChange != nil {
		pct = *percentChange
	}
	if current >= t.CritAbs && pct >= t.CritPct {
		return "CRITICAL"
	}
	if current >= t.WarnAbs {
		return "WARNING"
	}
	if pct >= t.WarnPct && current >= t.MinAbs {
		return "WARNING"
	}
	return "NORMAL"
}

// Insights limits — hard caps that bound bytes scanned structurally.
var InsightsLimits = struct {
	MaxWindow     time.Duration
	DefaultWindow time.Duration
	QueryDeadline time.Duration
	MaxConcurrent int
}{
	MaxWindow:     4 * time.Hour,
	DefaultWindow: time.Hour,
	QueryDeadline: 20 * time.Second,
	MaxConcurrent: 2,
}

var WafLimits = struct {
	MaxWCU              int
	SampleWindowMinutes int
}{MaxWCU: 5000, SampleWindowMinutes: 15}

// WafInsightsTTL: the WAF-log aggregation is five Insights queries over the
// whole window, so it refreshes on its own slower tier.
const WafInsightsTTL = 2 * time.Minute
