package analysis

// Incident context for Amazon Q / human operators (spec §17, §18), ported from
// incident.ts. History rows come in through IncidentParts so this file stays
// pure of SQLite; persisting the snapshot is the caller's business.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type LogsRef struct {
	Pod       string   `json:"pod"`
	Container string   `json:"container"`
	Previous  bool     `json:"previous"`
	Lines     []string `json:"lines"`
}

type WafHistoryEntry struct {
	Ts       string `json:"ts"`
	RuleName string `json:"ruleName"`
	Action   string `json:"action"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
}

type DeployHistoryEntry struct {
	Ts      string `json:"ts"`
	Target  string `json:"target"`
	Change  string `json:"change"`
	Verdict string `json:"verdict"`
}

type IncidentSnapshot struct {
	Timestamp     string                     `json:"timestamp"`
	Metrics       []types.MetricSummary      `json:"metrics"`
	HttpSummary   *types.HttpSummary         `json:"httpSummary"`
	Kube          *types.KubePanel           `json:"kube"`
	Anomalies     []types.Anomaly            `json:"anomalies"`
	Correlations  []types.CorrelationResult  `json:"correlations"`
	Timeline      []types.TimelineEntry      `json:"timeline"`
	Fingerprints  []types.FingerprintEntry   `json:"fingerprints"`
	Logs          *LogsRef                   `json:"logs"`
	PreviousLogs  *LogsRef                   `json:"previousLogs"`
	WafHistory    []WafHistoryEntry          `json:"wafHistory"`
	DeployHistory []DeployHistoryEntry       `json:"deployHistory"`
	Verifications []types.VerificationResult `json:"verifications"`
}

type IncidentParts struct {
	Metrics       []types.MetricSummary
	HttpSummary   *types.HttpSummary
	Kube          *types.KubePanel
	Anomalies     []types.Anomaly
	Correlations  []types.CorrelationResult
	Timeline      []types.TimelineEntry
	Fingerprints  []types.FingerprintEntry
	Logs          *LogsRef
	PreviousLogs  *LogsRef
	WafHistory    []WafHistoryEntry
	DeployHistory []DeployHistoryEntry
	Verifications []types.VerificationResult
}

func BuildSnapshot(parts IncidentParts, now time.Time) IncidentSnapshot {
	s := IncidentSnapshot{
		Timestamp:     now.UTC().Format(time.RFC3339Nano),
		Metrics:       orEmpty(parts.Metrics),
		HttpSummary:   parts.HttpSummary,
		Kube:          parts.Kube,
		Anomalies:     orEmpty(parts.Anomalies),
		Correlations:  orEmpty(parts.Correlations),
		Timeline:      orEmpty(parts.Timeline),
		Fingerprints:  orEmpty(parts.Fingerprints),
		Logs:          parts.Logs,
		PreviousLogs:  parts.PreviousLogs,
		WafHistory:    orEmpty(parts.WafHistory),
		DeployHistory: orEmpty(parts.DeployHistory),
		Verifications: orEmpty(parts.Verifications),
	}
	// Drop the source-IP ranking at the single choke point every incident
	// output flows through: volume from one IP is the scenario's own load
	// generator, and this feeds the Amazon Q handoff.
	if s.HttpSummary != nil {
		copySummary := *s.HttpSummary
		copySummary.ByIp = []types.IpStat{}
		s.HttpSummary = &copySummary
	}
	return s
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ToMarkdown renders the full incident context.
func ToMarkdown(s IncidentSnapshot) string {
	md := []string{}
	push := func(lines ...string) { md = append(md, lines...) }

	push("# Incident Context")
	push("Generated: " + s.Timestamp)
	push("\n> 본 문서의 모든 원인 표현은 \"의심/가능성\"이며 확정 진단이 아님. 민감정보는 마스킹됨.")

	// The interpretation key goes first: without it a reader treats the 4XX/403
	// volume this environment produces by design as an outage.
	push("\n## 0. 게이트웨이 기대 동작 (판정 기준)")
	push(ContractLines()...)

	push("\n## 1. CloudWatch Metrics (현재 vs 이전 구간)")
	push("| Metric | Previous | Current | Δ | %Change | Status |")
	push("|---|---|---|---|---|---|")
	for _, m := range s.Metrics {
		pct := "N/A"
		if m.PercentChange != nil {
			pct = fmt.Sprintf("%g", *m.PercentChange)
		}
		push(fmt.Sprintf("| %s | %g | %g | %g | %s | %s |", m.Label, m.Previous, m.Current, m.Delta, pct, m.Status))
	}

	if h := s.HttpSummary; h != nil {
		push(fmt.Sprintf("\n## 2. HTTP / WAF 요청 요약 (%s)", h.Source))
		if d := h.StatusDist; d != nil {
			push(fmt.Sprintf("상태 분포(분당): 2xx=%g, 3xx=%g, 4xx=%g, 5xx=%g", d.C2xx, d.C3xx, d.C4xx, d.C5xx))
		}
		push("\n### Top Paths")
		for i, p := range h.ByPath {
			if i >= 10 {
				break
			}
			extra := ""
			if p.LowPriority {
				extra = ", 헬스체크 제외 대상"
			}
			push(fmt.Sprintf("- %s — %d건 (차단 %d%s)", p.Path, p.Count, p.Blocked, extra))
		}
		// Source-IP ranking is deliberately omitted.
		push("\n### Top User-Agents")
		for i, u := range h.ByUa {
			if i >= 5 {
				break
			}
			push(fmt.Sprintf("- %s — %d건", MaskText(u.Key), u.Count))
		}

		check := EvaluateContract(h)
		push("\n### 기대 동작 대비 편차 (§0 기준)")
		if len(check.Deviations) == 0 {
			push("- 계약 위반 관측 없음")
		}
		for _, d := range check.Deviations {
			push("- [편차] " + d)
		}
		for _, c := range check.Conforming {
			push("- [정상] " + c)
		}
	}

	if k := s.Kube; k != nil {
		push("\n## 3. Kubernetes 상태")
		push(fmt.Sprintf("노드: %d/%d Ready", k.NodesReady, k.NodesTotal))
		push("\n### Pods")
		push("| Pod | 상태 | Ready | 재시작 | 최근증가 | Node |")
		push("|---|---|---|---|---|---|")
		for _, p := range k.Pods {
			push(fmt.Sprintf("| %s | %s | %s | %d | +%d | %s |", p.Name, p.StatusLabel, p.Ready, p.TotalRestarts, p.RecentRestartIncrease, p.NodeName))
		}
		push("\n### Warning Events (최신순)")
		for i, e := range k.Events {
			if i >= 15 {
				break
			}
			push(fmt.Sprintf("- %s [%s/%s] %s: %s (×%d)", e.Timestamp, e.Kind, e.Name, e.Reason, MaskText(e.Message), e.Count))
		}
	}

	if len(s.Fingerprints) > 0 {
		push("\n## 4. Top Errors / Fingerprints")
		for i, f := range s.Fingerprints {
			if i >= 10 {
				break
			}
			push(fmt.Sprintf("- ×%d [%s] %s", f.Count, strings.Join(f.Pods, ", "), MaskText(f.Fingerprint)))
		}
	}

	if l := s.Logs; l != nil {
		prev := ""
		if l.Previous {
			prev = ", previous"
		}
		push(fmt.Sprintf("\n## 5. Pod Logs (%s/%s%s)", l.Pod, l.Container, prev))
		push("```")
		push(tailLines(l.Lines, 60)...)
		push("```")
	}
	if l := s.PreviousLogs; l != nil {
		push(fmt.Sprintf("\n## 6. Previous Logs (%s/%s)", l.Pod, l.Container))
		push("```")
		push(tailLines(l.Lines, 60)...)
		push("```")
	}

	push("\n## 7. Detected Anomalies")
	if len(s.Anomalies) == 0 {
		push("- 없음")
	}
	for _, a := range s.Anomalies {
		push(fmt.Sprintf("- [%s][%s] %s (confidence: %s)", a.Severity, a.Type, a.Title, a.Confidence))
		push("  - " + a.Detail)
		for _, ev := range a.Evidence {
			push("  - 근거: " + MaskText(ev))
		}
	}

	push("\n## 8. Correlation (추정 원인 — 확정 아님)")
	if len(s.Correlations) == 0 {
		push("- 상관관계 결과 없음")
	}
	for _, c := range s.Correlations {
		push(fmt.Sprintf("- [%s] %s (confidence: %s)", c.Category, c.Reason, c.Confidence))
		for _, ev := range c.Evidence {
			push("  - " + MaskText(ev))
		}
	}

	push("\n## 9. Timeline")
	for _, t := range tailTimeline(s.Timeline, 40) {
		push(fmt.Sprintf("- %s [%s] %s", t.Ts, t.Source, MaskText(t.Text)))
	}

	push("\n## 10. Actions Taken")
	push("### Deployment 변경")
	if len(s.DeployHistory) == 0 {
		push("- 없음")
	}
	for _, d := range s.DeployHistory {
		push(fmt.Sprintf("- %s %s: %s → 검증 %s", d.Ts, d.Target, d.Change, d.Verdict))
	}
	push("### WAF 적용/롤백 이력")
	if len(s.WafHistory) == 0 {
		push("- 없음")
	}
	for _, w := range s.WafHistory {
		push(fmt.Sprintf("- %s %s %s → %s (%s)", w.Ts, w.RuleName, w.Action, w.Status, w.Detail))
	}

	push("\n## 11. Post-action Verification")
	if len(s.Verifications) == 0 {
		push("- 검증 결과 없음")
	}
	for _, v := range s.Verifications {
		push(fmt.Sprintf("- #%d → %s (%s)", v.ActionID, v.Verdict, v.CheckedAt))
		for _, d := range v.Details {
			push("  - " + d)
		}
	}

	return MaskText(strings.Join(md, "\n"))
}

func tailLines(lines []string, n int) []string {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}

func tailTimeline(entries []types.TimelineEntry, n int) []types.TimelineEntry {
	if len(entries) > n {
		return entries[len(entries)-n:]
	}
	return entries
}

func ToJson(s IncidentSnapshot) string {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "{}"
	}
	return MaskText(string(raw))
}

// --- Amazon Q prompt ---------------------------------------------------------
// A different artifact from the full markdown, not a shortened copy of it —
// see the TS original for the packing rationale.

const (
	topPaths = 10
	topUas   = 8
)

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func topPathLines(h *types.HttpSummary) []string {
	if len(h.ByPath) == 0 {
		return nil
	}
	out := []string{fmt.Sprintf("- Top 경로 %d/%d (요청순, [지정]/[미지정]은 [A] 기준):", minInt(topPaths, len(h.ByPath)), len(h.ByPath))}
	for i, p := range h.ByPath {
		if i >= topPaths {
			break
		}
		extra := ""
		if p.LowPriority {
			extra = ", 헬스체크 제외 대상"
		}
		out = append(out, fmt.Sprintf("  %d. [%s] %s — %d건 (차단 %d%s)", i+1, PathScopeLabel(p.Path), p.Path, p.Count, p.Blocked, extra))
	}
	return out
}

func topUaLines(h *types.HttpSummary) []string {
	if len(h.ByUa) == 0 {
		return nil
	}
	out := []string{fmt.Sprintf("- Top User-Agent %d/%d (요청순):", minInt(topUas, len(h.ByUa)), len(h.ByUa))}
	for i, u := range h.ByUa {
		if i >= topUas {
			break
		}
		out = append(out, fmt.Sprintf("  %d. %s — %d건", i+1, MaskText(u.Key), u.Count))
	}
	return out
}

func ToQPrompt(s IncidentSnapshot) string {
	header := []string{
		"# WAF/게이트웨이 인시던트 분석 요청",
		"수집 시각: " + s.Timestamp,
		"",
		"[A] 판정 기준 — 게이트웨이 기대 동작",
	}
	header = append(header, ContractLines()...)
	header = append(header,
		"",
		"[B] 요청 사항",
		"1. [C]의 이상 징후 중 [A] 계약으로 설명되는 것과 실제 문제를 구분할 것.",
		"2. 실제 문제에 대해 근본 원인 가설을 근거와 함께 제시할 것 (확정 진단 금지).",
		"3. [G]의 규칙 후보를 검토하고, 필요하면 응답 코드(403/404)까지 지정해 보완할 것.",
		"4. 4XX/403/404 증가 자체를 장애로 판정하지 말 것 — [A]에서 정상 동작임.",
		"5. [F]의 Top 경로·Top User-Agent에서 스캐너/정찰 패턴을 식별하고, [미지정] 경로에 몰린 요청은 [A]의 404 정책으로 설명할 것.",
	)

	sections := []QSection{}

	anomalyLines := []string{}
	if len(s.Anomalies) == 0 {
		anomalyLines = append(anomalyLines, "- 탐지된 이상 징후 없음")
	}
	for _, a := range s.Anomalies {
		evidence := []string{}
		for i, e := range a.Evidence {
			if i >= 2 {
				break
			}
			evidence = append(evidence, MaskText(e))
		}
		anomalyLines = append(anomalyLines, fmt.Sprintf("- [%s/%s] %s: %s (confidence %s) | 근거 %s",
			a.Severity, a.Type, MaskText(a.Title), MaskText(a.Detail), a.Confidence, strings.Join(evidence, "; ")))
	}
	sections = append(sections, QSection{Title: "[C] 이상 징후 (심각도순)", Lines: anomalyLines})

	contract := EvaluateContract(s.HttpSummary)
	contractLines := []string{}
	if len(contract.Deviations) == 0 {
		contractLines = append(contractLines, "- 계약 위반 관측 없음")
	}
	for _, d := range contract.Deviations {
		contractLines = append(contractLines, "- [편차] "+MaskText(d))
	}
	for _, c := range contract.Conforming {
		contractLines = append(contractLines, "- [정상] "+MaskText(c))
	}
	sections = append(sections, QSection{Title: "[D] 기대 동작 대비 편차 ([A] 기준)", Lines: contractLines})

	metricLines := []string{}
	allNormal := true
	for _, m := range s.Metrics {
		if m.Status != "NORMAL" {
			allNormal = false
			pct := "N/A"
			if m.PercentChange != nil {
				pct = fmt.Sprintf("%g", *m.PercentChange)
			}
			metricLines = append(metricLines, fmt.Sprintf("- %s: %g → %g (%s%%, %s)", m.Label, m.Previous, m.Current, pct, m.Status))
		}
	}
	if allNormal {
		metricLines = append(metricLines, "- 임계치 초과 메트릭 없음")
	}
	sections = append(sections, QSection{Title: "[E] 근거 — 메트릭 (이전 → 현재)", Lines: metricLines})

	trafficLines := []string{}
	if h := s.HttpSummary; h != nil {
		trafficLines = append(trafficLines, fmt.Sprintf("- 출처: %s / %d건 / %s", h.Source, h.TotalSampled, h.WindowLabel))
		if d := h.StatusDist; d != nil {
			trafficLines = append(trafficLines, fmt.Sprintf("- 상태 분포(분당): 2xx=%g 3xx=%g 4xx=%g 5xx=%g", d.C2xx, d.C3xx, d.C4xx, d.C5xx))
		}
		trafficLines = append(trafficLines, topPathLines(h)...)
		trafficLines = append(trafficLines, topUaLines(h)...)
	}
	sections = append(sections, QSection{Title: "[F] 근거 — 트래픽", Lines: trafficLines})

	kubeLines := []string{}
	if k := s.Kube; k != nil {
		kubeLines = append(kubeLines, fmt.Sprintf("- 노드 %d/%d Ready", k.NodesReady, k.NodesTotal))
		shown := 0
		for _, p := range k.Pods {
			if p.StatusLabel == "Running" && p.RecentRestartIncrease == 0 {
				continue
			}
			if shown >= 6 {
				break
			}
			shown++
			kubeLines = append(kubeLines, fmt.Sprintf("- Pod %s: %s, ready %s, 재시작 %d (+%d)", p.Name, p.StatusLabel, p.Ready, p.TotalRestarts, p.RecentRestartIncrease))
		}
	}
	for i, f := range s.Fingerprints {
		if i >= 5 {
			break
		}
		kubeLines = append(kubeLines, fmt.Sprintf("- 반복 오류 ×%d: %s", f.Count, truncate(MaskText(f.Fingerprint), 120)))
	}
	sections = append(sections, QSection{Title: "[H] 근거 — 애플리케이션/쿠버네티스", Lines: kubeLines})

	histLines := []string{}
	for _, d := range tailDeploy(s.DeployHistory, 5) {
		histLines = append(histLines, fmt.Sprintf("- %s %s: %s → %s", d.Ts, d.Target, MaskText(d.Change), d.Verdict))
	}
	for _, w := range tailWaf(s.WafHistory, 5) {
		histLines = append(histLines, fmt.Sprintf("- %s %s %s → %s", w.Ts, w.RuleName, w.Action, w.Status))
	}
	for _, v := range tailVerify(s.Verifications, 5) {
		histLines = append(histLines, fmt.Sprintf("- 검증 #%d → %s (%s)", v.ActionID, v.Verdict, v.CheckedAt))
	}
	sections = append(sections, QSection{Title: "[I] 조치 및 검증 이력", Lines: histLines})

	corrLines := []string{}
	for _, c := range s.Correlations {
		corrLines = append(corrLines, fmt.Sprintf("- [%s] %s (confidence %s)", c.Category, MaskText(c.Reason), c.Confidence))
	}
	sections = append(sections, QSection{Title: "[J] 상관관계 (추정, 확정 아님)", Lines: corrLines})

	return PackToLimit(header, sections, MaxQPromptChars)
}

func tailDeploy(list []DeployHistoryEntry, n int) []DeployHistoryEntry {
	if len(list) > n {
		return list[len(list)-n:]
	}
	return list
}

func tailWaf(list []WafHistoryEntry, n int) []WafHistoryEntry {
	if len(list) > n {
		return list[len(list)-n:]
	}
	return list
}

func tailVerify(list []types.VerificationResult, n int) []types.VerificationResult {
	if len(list) > n {
		return list[len(list)-n:]
	}
	return list
}
