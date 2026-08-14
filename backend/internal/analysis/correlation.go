package analysis

// Correlation and timeline (spec §15, §16), ported from correlation.ts.
// Wording stays "suspected" — never a confirmed root cause. History rows are
// passed in rather than read here, so this stays pure of SQLite.

import (
	"fmt"
	"sort"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type RestartEvent struct {
	Pod   string
	Ts    int64
	Delta int
}

type WafHistoryRow struct {
	ID       int
	Ts       int64
	RuleName string
	Action   string
	Status   string
	Detail   string
}

// HistoryInput carries the SQLite-backed rows the timeline folds in. Any of
// the slices may be nil when the history DB is unavailable — the timeline
// still renders from live signals.
type HistoryInput struct {
	RestartEvents []RestartEvent
	DeployHistory []types.DeployChangeEntry
	WafHistory    []WafHistoryRow
}

func findAnomaly(anomalies []types.Anomaly, typ string) *types.Anomaly {
	for i := range anomalies {
		if anomalies[i].Type == typ {
			return &anomalies[i]
		}
	}
	return nil
}

func Correlate(anomalies []types.Anomaly) []types.CorrelationResult {
	results := []types.CorrelationResult{}
	app := findAnomaly(anomalies, "APPLICATION_FAILURE_SUSPECTED")
	c5 := findAnomaly(anomalies, "5XX_SPIKE")
	lat := findAnomaly(anomalies, "LATENCY_SPIKE")
	db := findAnomaly(anomalies, "DATABASE_PRESSURE_SUSPECTED")
	res := findAnomaly(anomalies, "RESOURCE_EXHAUSTION_SUSPECTED")
	traffic := findAnomaly(anomalies, "TRAFFIC_ANOMALY_SUSPECTED")
	wafSpike := findAnomaly(anomalies, "WAF_BLOCK_SPIKE")

	if app != nil && (c5 != nil || lat != nil) {
		evidence := append([]string{}, app.Evidence...)
		if c5 != nil {
			evidence = append(evidence, c5.Evidence...)
		}
		if lat != nil {
			evidence = append(evidence, lat.Evidence...)
		}
		results = append(results, types.CorrelationResult{
			Category:   "APPLICATION_FAILURE_SUSPECTED",
			Reason:     "5XX/지연 증가와 Pod 이상(CrashLoopBackOff)·반복 예외 로그가 같은 시간대에 관측 — 애플리케이션 결함이 원인일 가능성",
			Evidence:   evidence,
			Confidence: app.Confidence,
		})
	}
	if db != nil {
		results = append(results, types.CorrelationResult{
			Category:   "DATABASE_PRESSURE_SUSPECTED",
			Reason:     "Pod는 정상인데 RDS 연결·지연·5XX가 동반 상승 — DB 병목(느린 쿼리, 인덱스 부재, 커넥션 고갈) 가능성",
			Evidence:   db.Evidence,
			Confidence: db.Confidence,
		})
	}
	if res != nil {
		results = append(results, types.CorrelationResult{
			Category:   "RESOURCE_EXHAUSTION_SUSPECTED",
			Reason:     "재시작 증가 + OOMKilled — Memory Limit이 워크로드 대비 부족할 가능성. Previous Logs에서 OOM 직전 상태 확인 권장",
			Evidence:   res.Evidence,
			Confidence: res.Confidence,
		})
	}
	if traffic != nil && (wafSpike != nil || findAnomaly(anomalies, "4XX_SPIKE") != nil) {
		evidence := append([]string{}, traffic.Evidence...)
		if wafSpike != nil {
			evidence = append(evidence, wafSpike.Evidence...)
		}
		results = append(results, types.CorrelationResult{
			Category:   "TRAFFIC_ANOMALY_SUSPECTED",
			Reason:     "특정 IP/경로/UA 집중과 4XX·WAF 차단 증가가 동반 — 자동화/공격성 트래픽 가능성. WAF 규칙 추천 검토",
			Evidence:   evidence,
			Confidence: traffic.Confidence,
		})
	}
	return results
}

func iso(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}

// BuildTimeline merges CloudWatch spikes, K8s events, restarts, and change
// history into one chronological timeline.
func BuildTimeline(input AnomalyInput, anomalies []types.Anomaly, history HistoryInput, now time.Time) []types.TimelineEntry {
	entries := []types.TimelineEntry{}

	for i, ev := range input.Events {
		if i >= 30 {
			break
		}
		if ev.Timestamp == "" {
			continue
		}
		sev := "NORMAL"
		if ev.Highlighted {
			sev = "WARNING"
		}
		entries = append(entries, types.TimelineEntry{
			Ts:       ev.Timestamp,
			Source:   "K8s Event",
			Severity: sev,
			Text:     fmt.Sprintf("[%s/%s] %s: %s (×%d)", ev.Kind, ev.Name, ev.Reason, truncate(ev.Message, 120), ev.Count),
		})
	}
	for _, r := range history.RestartEvents {
		entries = append(entries, types.TimelineEntry{
			Ts: iso(r.Ts), Source: "Pod Restart", Severity: "WARNING",
			Text: fmt.Sprintf("%s 재시작 +%d", r.Pod, r.Delta),
		})
	}
	for i, d := range history.DeployHistory {
		if i >= 10 {
			break
		}
		entries = append(entries, types.TimelineEntry{
			Ts: d.Ts, Source: "Deployment 변경", Severity: "NORMAL",
			Text: fmt.Sprintf("%s/%s: %s (검증: %s)", d.Namespace, d.Name, d.Change, d.Verdict),
		})
	}
	for i, w := range history.WafHistory {
		if i >= 10 {
			break
		}
		sev := "NORMAL"
		if w.Status == "FAILED" {
			sev = "WARNING"
		}
		entries = append(entries, types.TimelineEntry{
			Ts: iso(w.Ts), Source: "WAF 변경", Severity: sev,
			Text: fmt.Sprintf("%s %s → %s", w.RuleName, w.Action, w.Status),
		})
	}
	for _, a := range anomalies {
		entries = append(entries, types.TimelineEntry{
			Ts: a.DetectedAt, Source: "Anomaly", Severity: a.Severity,
			Text: fmt.Sprintf("[%s] %s", a.Type, a.Title),
		})
	}
	nowIso := now.UTC().Format(time.RFC3339Nano)
	for _, p := range input.Pods {
		if p.StatusLabel != "Running" && p.StatusLabel != "NotReady" {
			entries = append(entries, types.TimelineEntry{
				Ts: nowIso, Source: "Pod 상태", Severity: "WARNING",
				Text: fmt.Sprintf("%s: %s (재시작 %d)", p.Name, p.StatusLabel, p.TotalRestarts),
			})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Ts < entries[j].Ts })
	if len(entries) > 80 {
		entries = entries[len(entries)-80:]
	}
	return entries
}
