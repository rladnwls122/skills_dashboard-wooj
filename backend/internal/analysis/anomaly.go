package analysis

// Anomaly detection, ported from anomaly.ts. A single signal is never enough
// for CRITICAL (spec §8): severity escalates only when corroborating signals
// exist.

import (
	"fmt"
	"regexp"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/rules"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type AnomalyInput struct {
	Metrics      []types.MetricSummary
	HttpSummary  *types.HttpSummary
	Pods         []types.PodInfo
	Events       []types.WarningEvent
	Fingerprints []types.FingerprintEntry
}

func metricOf(input AnomalyInput, key string) *types.MetricSummary {
	for i := range input.Metrics {
		if input.Metrics[i].Key == key {
			return &input.Metrics[i]
		}
	}
	return nil
}

func escalate(base string, corroborating int) string {
	if base == "NORMAL" {
		return "NORMAL"
	}
	if corroborating >= 1 && base == "CRITICAL" {
		return "CRITICAL"
	}
	return "WARNING"
}

func fmtPct(p *float64) string {
	if p == nil {
		return "이전 구간 0 → 신규 발생"
	}
	sign := ""
	if *p >= 0 {
		sign = "+"
	}
	return fmt.Sprintf("%s%g%%", sign, *p)
}

var mozillaRe = regexp.MustCompile(`(?i)mozilla`)

func DetectAnomalies(input AnomalyInput, now time.Time) []types.Anomaly {
	anomalies := []types.Anomaly{}
	nowIso := now.UTC().Format(time.RFC3339Nano)
	trt := metricOf(input, "targetResponseTime")
	c4 := metricOf(input, "http4xx")
	c5 := metricOf(input, "http5xx")
	wafB := metricOf(input, "wafBlocked")
	rds := metricOf(input, "rdsClientConnections")

	badPods := []types.PodInfo{}
	oomPods := []types.PodInfo{}
	crashPods := []types.PodInfo{}
	for _, p := range input.Pods {
		if p.StatusLabel != "Running" || p.RecentRestartIncrease > 0 || p.Phase == "Failed" {
			badPods = append(badPods, p)
		}
		oom := p.StatusLabel == "OOMKilled"
		for _, c := range p.Containers {
			if c.Reason == "OOMKilled" {
				oom = true
			}
		}
		if oom {
			oomPods = append(oomPods, p)
		}
		if p.StatusLabel == "CrashLoopBackOff" {
			crashPods = append(crashPods, p)
		}
	}
	repeatedErrors := []types.FingerprintEntry{}
	for _, f := range input.Fingerprints {
		if f.Count >= 5 {
			repeatedErrors = append(repeatedErrors, f)
		}
	}

	abnormal := func(m *types.MetricSummary) bool { return m != nil && m.Status != "NORMAL" }
	// A metric CloudWatch never returned is a hole in the evidence, not a
	// corroborating spike. Counting nil as a signal meant that on a cluster
	// where, say, the WAF metrics are simply not published, every single alarm
	// arrived with three free "corroborating" signals and escalate() promoted a
	// lone WARNING to CRITICAL. abnormal() is the shape the rest of this file
	// already uses, and it is the one that is true only about what was measured.
	spikeSignals := 0
	for _, hit := range []bool{
		abnormal(trt),
		abnormal(c4),
		abnormal(c5),
		abnormal(wafB),
		len(badPods) > 0,
		len(repeatedErrors) > 0,
	} {
		if hit {
			spikeSignals++
		}
	}

	push := func(typ, base, title, detail string, evidence []string, confidence string) {
		anomalies = append(anomalies, types.Anomaly{
			ID:         fmt.Sprintf("%s-%d", typ, len(anomalies)),
			Type:       typ,
			Severity:   escalate(base, spikeSignals-1),
			Title:      title,
			Detail:     detail,
			Evidence:   evidence,
			Confidence: confidence,
			DetectedAt: nowIso,
		})
	}

	if abnormal(c4) {
		conf := "MEDIUM"
		if c4.Status == "CRITICAL" {
			conf = "HIGH"
		}
		push("4XX_SPIKE", c4.Status, "4XX 응답 급증",
			fmt.Sprintf("4XX가 %g → %g (%s) 변화. 정상 404/인증 실패 가능성도 있으므로 경로 분포 확인 필요.", c4.Previous, c4.Current, fmtPct(c4.PercentChange)),
			[]string{fmt.Sprintf("Target 4XX: %g → %g/min", c4.Previous, c4.Current)}, conf)
	}
	if abnormal(c5) {
		conf := "MEDIUM"
		if c5.Status == "CRITICAL" {
			conf = "HIGH"
		}
		push("5XX_SPIKE", c5.Status, "5XX 응답 급증",
			fmt.Sprintf("5XX가 %g → %g (%s) 변화 — 애플리케이션 또는 백엔드 장애 의심.", c5.Previous, c5.Current, fmtPct(c5.PercentChange)),
			[]string{fmt.Sprintf("Target 5XX: %g → %g/min", c5.Previous, c5.Current)}, conf)
	}
	if abnormal(trt) {
		push("LATENCY_SPIKE", trt.Status, "응답 지연 급증",
			fmt.Sprintf("TargetResponseTime %gs → %gs (%s).", trt.Previous, trt.Current, fmtPct(trt.PercentChange)),
			[]string{fmt.Sprintf("TargetResponseTime: %gs → %gs", trt.Previous, trt.Current)}, "MEDIUM")
	}
	if abnormal(wafB) {
		push("WAF_BLOCK_SPIKE", wafB.Status, "WAF 차단 급증",
			fmt.Sprintf("BlockedRequests %g → %g/min — 공격 시도 증가 또는 오탐 증가 가능성 모두 검토 필요.", wafB.Previous, wafB.Current),
			[]string{fmt.Sprintf("WAF BlockedRequests: %g → %g/min", wafB.Previous, wafB.Current)}, "MEDIUM")
	}

	if h := input.HttpSummary; h != nil {
		total := h.TotalSampled
		if total < 1 {
			total = 1
		}
		// Request volume is never an anomaly in this environment — only traffic
		// aimed outside the served surface (probing, scanning) counts.
		offSurface := []types.PathStat{}
		offSurfaceCount := 0
		for _, p := range h.ByPath {
			if !p.LowPriority && !config.IsBenignPath(p.Path) {
				offSurface = append(offSurface, p)
				offSurfaceCount += p.Count
			}
		}
		concentrated := []string{}
		if len(offSurface) > 0 {
			top := offSurface[0]
			if config.IsPathSuspicious(top.Path, top.Count, total) {
				concentrated = append(concentrated, fmt.Sprintf("경로 %s: 샘플 %d/%d건 (서비스 경로 외)", top.Path, top.Count, total))
			}
		}
		if len(h.ByUa) > 0 {
			topUa := h.ByUa[0]
			if offSurfaceCount >= 20 && float64(topUa.Count)/float64(total) >= 0.4 && !mozillaRe.MatchString(topUa.Key) {
				concentrated = append(concentrated, fmt.Sprintf(`UA "%s": %d/%d건`, topUa.Key, topUa.Count, total))
			}
		}
		if len(concentrated) > 0 {
			base, conf := "WARNING", "MEDIUM"
			if len(concentrated) >= 2 {
				base, conf = "CRITICAL", "HIGH"
			}
			push("TRAFFIC_ANOMALY_SUSPECTED", base, "비정상 트래픽 집중 의심",
				"서비스 경로(/v1/*) 외 요청이 집중 — 스캔 또는 탐색 시도 가능성. WAF 탭에서 규칙 추천 확인.",
				concentrated, conf)
		}

		// Malicious-client signatures in the sampled UA/query mix. UNKNOWN is
		// excluded on purpose — a positive signature is required to alarm.
		type flagged struct {
			hit   *rules.ThreatHit
			key   string
			count int
		}
		flaggedUa := []flagged{}
		for _, u := range h.ByUa {
			hit := rules.ClassifyUa(u.Key)
			if hit != nil && hit.Category != rules.CategoryUnknown {
				flaggedUa = append(flaggedUa, flagged{hit, u.Key, u.Count})
			}
		}
		b64Query := []types.KeyCount{}
		for _, q := range h.QueryPatterns {
			if rules.QueryHasBase64Blob(q.Key) {
				b64Query = append(b64Query, q)
			}
		}
		if len(flaggedUa) > 0 || len(b64Query) > 0 {
			evidence := []string{}
			for i, f := range flaggedUa {
				if i >= 5 {
					break
				}
				evidence = append(evidence, fmt.Sprintf(`악성 클라이언트 UA "%s" (%s/%s): %d건`, f.key, f.hit.Category, f.hit.Label, f.count))
			}
			for i, q := range b64Query {
				if i >= 3 {
					break
				}
				key := q.Key
				if len(key) > 60 {
					key = truncate(key, 60)
				}
				evidence = append(evidence, fmt.Sprintf(`base64 난독화 쿼리 의심: "%s"`, key))
			}
			// Only a named offensive tool is CRITICAL on its own.
			hasScanner := false
			for _, f := range flaggedUa {
				if f.hit.Category == rules.CategoryScanner || f.hit.Category == rules.CategoryRecon {
					hasScanner = true
					break
				}
			}
			base := "WARNING"
			if hasScanner {
				base = "CRITICAL"
			}
			push("MALICIOUS_CLIENT_SUSPECTED", base, "악성 클라이언트 시그니처 탐지",
				"샘플 트래픽에서 스캐너·정찰 툴 또는 위조/난독 시그니처가 관측됨", evidence, "HIGH")
			// A named scanner/recon tool is an unambiguous signature on its own —
			// its severity must not be downgraded by escalate() just because no
			// other metric is spiking.
			anomalies[len(anomalies)-1].Severity = base
		}
	}

	if len(crashPods) > 0 || (abnormal(c5) && len(repeatedErrors) > 0) {
		base, conf := "WARNING", "MEDIUM"
		if len(crashPods) > 0 && abnormal(c5) {
			base = "CRITICAL"
		}
		if len(crashPods) > 0 {
			conf = "HIGH"
		}
		evidence := []string{}
		for _, p := range crashPods {
			evidence = append(evidence, fmt.Sprintf("Pod %s: CrashLoopBackOff (재시작 %d)", p.Name, p.TotalRestarts))
		}
		for i, f := range repeatedErrors {
			if i >= 3 {
				break
			}
			evidence = append(evidence, fmt.Sprintf("반복 오류 ×%d: %s", f.Count, truncate(f.Fingerprint, 80)))
		}
		push("APPLICATION_FAILURE_SUSPECTED", base, "애플리케이션 장애 의심",
			"CrashLoopBackOff 또는 반복 예외 로그와 5XX가 동반 — 애플리케이션 결함 가능성 (확정 아님, 로그 확인 필요).",
			evidence, conf)
	}

	if abnormal(rds) && abnormal(trt) && len(badPods) == 0 {
		base := "WARNING"
		if abnormal(c5) {
			base = "CRITICAL"
		}
		push("DATABASE_PRESSURE_SUSPECTED", base, "데이터베이스 부하 의심",
			"RDS 연결 증가 + 지연 증가 + Pod 정상 조합 — DB 측 병목 가능성 (쿼리/인덱스/커넥션 풀 점검 필요).",
			[]string{
				fmt.Sprintf("RDS Proxy Client Conn: %g → %g", rds.Previous, rds.Current),
				fmt.Sprintf("TargetResponseTime: %gs → %gs", trt.Previous, trt.Current),
				"이상 Pod 없음",
			}, "MEDIUM")
	}

	if len(oomPods) > 0 {
		base := "WARNING"
		for _, p := range oomPods {
			if p.RecentRestartIncrease > 0 {
				base = "CRITICAL"
				break
			}
		}
		evidence := []string{}
		for _, p := range oomPods {
			limit := "-"
			if len(p.Containers) > 0 {
				limit = p.Containers[0].MemLimit
			}
			evidence = append(evidence, fmt.Sprintf("Pod %s: OOMKilled, limit=%s, 최근 재시작 +%d", p.Name, limit, p.RecentRestartIncrease))
		}
		push("RESOURCE_EXHAUSTION_SUSPECTED", base, "리소스 고갈 의심 (OOM)",
			"OOMKilled 발생 — Memory Limit 부족 가능성. Action 탭에서 리소스 상향 검토.", evidence, "HIGH")
	}

	highlightedEvents := 0
	for _, e := range input.Events {
		if e.Highlighted {
			highlightedEvents++
		}
	}
	if len(anomalies) == 0 && (len(badPods) > 0 || highlightedEvents >= 3) {
		evidence := []string{}
		for i, p := range badPods {
			if i >= 3 {
				break
			}
			evidence = append(evidence, fmt.Sprintf("Pod %s: %s", p.Name, p.StatusLabel))
		}
		evidence = append(evidence, fmt.Sprintf("Warning 이벤트(강조) %d건", highlightedEvents))
		push("UNKNOWN_ANOMALY", "WARNING", "미분류 이상 징후",
			"메트릭 스파이크는 없으나 Pod 이상 또는 Warning 이벤트 다수 — 원인 미상, 추가 확인 필요.",
			evidence, "LOW")
	}

	return anomalies
}
