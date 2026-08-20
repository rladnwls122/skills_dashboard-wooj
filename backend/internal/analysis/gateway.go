package analysis

// The gateway response contract and the Amazon Q prompt packer, ported from
// gateway.ts. A 404 on /login is the gateway working, a 404 on /v1/user is a
// routing failure — every report states the contract up front.

import (
	"fmt"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

var GatewayContract = struct {
	UnlistedStatus int
	NormalStatus   int
	AbnormalStatus int
	AbnormalKinds  []string
}{
	UnlistedStatus: 404,
	NormalStatus:   200,
	AbnormalStatus: 403,
	AbnormalKinds:  []string{"email 포맷 오류(POST /v1/user)", "User-Agent Attacker-Bot", "SQL Injection", "XSS", "Body 포맷 오류"},
}

// MaxQPromptChars: Amazon Q's prompt input caps at 10,000 characters —
// anything past it is silently lost.
const MaxQPromptChars = 10_000

// ContractLines renders the contract for the top of a report. Five lines: this
// is the interpretation key, not the finding.
func ContractLines() []string {
	c := GatewayContract
	return []string{
		"- 지정 경로: " + strings.Join(config.AppTrafficPaths(), ", "),
		fmt.Sprintf("- 미지정 경로(예: /v1/admin, /login, /.env) → %d Not Found — 엔드포인트가 없는 것처럼 보이게 하여 스캐닝 차단", c.UnlistedStatus),
		fmt.Sprintf("- 지정 경로 + 정상 요청 → %d OK (백엔드 전달)", c.NormalStatus),
		fmt.Sprintf("- 지정 경로 + 비정상 요청(%s) → %d Forbidden", strings.Join(c.AbnormalKinds, " / "), c.AbnormalStatus),
		fmt.Sprintf(`- 따라서 %d/%d는 그 자체로 장애가 아니라 정책이 동작한 결과. 5XX와 "미지정 경로의 %d"만이 계약 위반.`, c.UnlistedStatus, c.AbnormalStatus, c.NormalStatus),
	}
}

type ContractCheck struct {
	// Observations that match the contract — stated so a reader does not read a
	// 403/404 spike as an outage.
	Conforming []string
	// Observations the contract does not allow. These are the findings.
	Deviations []string
}

// EvaluateContract scores the sampled traffic against the contract.
// Deliberately hedged: WAF logs carry the WAF's own action, not the status the
// client finally saw.
func EvaluateContract(h *types.HttpSummary) ContractCheck {
	check := ContractCheck{Conforming: []string{}, Deviations: []string{}}
	if h == nil {
		return check
	}

	c := GatewayContract
	listed := []types.PathStat{}
	unlisted := []types.PathStat{}
	for _, p := range h.ByPath {
		if p.LowPriority {
			continue
		}
		if config.IsAppTrafficPath(p.Path) {
			listed = append(listed, p)
		} else {
			unlisted = append(unlisted, p)
		}
	}

	unlistedBlocked := []types.PathStat{}
	unlistedPassed := []types.PathStat{}
	for _, p := range unlisted {
		if p.Blocked > 0 {
			unlistedBlocked = append(unlistedBlocked, p)
		}
		if p.Count-p.Blocked > 0 {
			unlistedPassed = append(unlistedPassed, p)
		}
	}
	listedBlocked := []types.PathStat{}
	for _, p := range listed {
		if p.Blocked > 0 {
			listedBlocked = append(listedBlocked, p)
		}
	}

	topN := func(list []types.PathStat, n int, f func(types.PathStat) string) string {
		if len(list) > n {
			list = list[:n]
		}
		parts := make([]string, 0, len(list))
		for _, p := range list {
			parts = append(parts, f(p))
		}
		return strings.Join(parts, ", ")
	}

	if len(unlistedPassed) > 0 {
		passedCount := 0
		for _, p := range unlistedPassed {
			passedCount += p.Count - p.Blocked
		}
		check.Deviations = append(check.Deviations, fmt.Sprintf(
			"미지정 경로 %d개(요청 %d건)가 WAF를 통과 — 게이트웨이가 %d로 응답했는지 확인 필요 (%d면 라우팅 노출): %s",
			len(unlistedPassed), passedCount, c.UnlistedStatus, c.NormalStatus,
			topN(unlistedPassed, 5, func(p types.PathStat) string {
				return fmt.Sprintf("%s %d건 통과", p.Path, p.Count-p.Blocked)
			})))
	}
	if len(unlistedBlocked) > 0 {
		// A WAF Block answers 403 by default. On an unlisted path that tells the
		// scanner the path is guarded — the contract wants it indistinguishable
		// from a path that does not exist.
		check.Deviations = append(check.Deviations, fmt.Sprintf(
			"미지정 경로가 WAF에서 차단됨 → 기본 응답은 %d이지만 계약상 %d여야 함. 해당 규칙에 CustomResponse %d 설정 검토: %s",
			c.AbnormalStatus, c.UnlistedStatus, c.UnlistedStatus,
			topN(unlistedBlocked, 5, func(p types.PathStat) string {
				return fmt.Sprintf("%s %d건", p.Path, p.Blocked)
			})))
	}
	if len(listedBlocked) > 0 {
		total := 0
		for _, p := range listedBlocked {
			total += p.Blocked
		}
		check.Conforming = append(check.Conforming, fmt.Sprintf(
			"지정 경로 차단 %d건 → 비정상 요청에 대한 %d로 계약과 일치 (%s)",
			total, c.AbnormalStatus,
			topN(listedBlocked, 5, func(p types.PathStat) string {
				return fmt.Sprintf("%s %d건", p.Path, p.Blocked)
			})))
	}

	if d := h.StatusDist; d != nil {
		if d.C5xx > 0 {
			check.Deviations = append(check.Deviations, fmt.Sprintf("5XX %g건/분 — 계약에 없는 응답. 백엔드 장애이며 WAF 정책으로 설명되지 않음.", d.C5xx))
		}
		if d.C3xx > 0 {
			check.Deviations = append(check.Deviations, fmt.Sprintf("3XX %g건/분 — 계약에 없는 응답. 리다이렉트 경로 확인 필요.", d.C3xx))
		}
		if d.C4xx > 0 && len(unlisted) > 0 {
			total := 0
			for _, p := range unlisted {
				total += p.Count
			}
			check.Conforming = append(check.Conforming, fmt.Sprintf(
				"4XX %g건/분 관측 + 미지정 경로 요청 %d건 — 스캐닝에 대한 %d 응답으로 설명 가능. 4XX 증가만으로 장애로 판정하지 말 것.",
				d.C4xx, total, c.UnlistedStatus))
		}
		if d.C5xx == 0 && d.C3xx == 0 {
			check.Conforming = append(check.Conforming, fmt.Sprintf(
				"5XX/3XX 없음 — 응답 코드는 계약 범위(%d/%d/%d) 안에 있음.",
				c.NormalStatus, c.AbnormalStatus, c.UnlistedStatus))
		}
	}

	return check
}

// PathScopeLabel says which side of the contract a path sits on.
func PathScopeLabel(path string) string {
	if config.IsAppTrafficPath(path) {
		return "지정"
	}
	return "미지정"
}

// QSection is a prioritised block of the Q prompt.
type QSection struct {
	Title string
	Lines []string
}

// PackToLimit packs prioritised sections into a hard character budget.
// Sections are added whole while they fit; the first one that does not is
// truncated line-by-line and everything after it is named but not included.
func PackToLimit(header []string, sections []QSection, limit int) string {
	out := append([]string{}, header...)
	used := len(strings.Join(out, "\n"))
	omitted := []string{}
	// Room for the trailing "생략" notice, which is only written if needed.
	const reserve = 120

	for _, s := range sections {
		if len(s.Lines) == 0 {
			continue
		}
		titleCost := len(s.Title) + 2
		if used+titleCost+reserve > limit {
			omitted = append(omitted, s.Title)
			continue
		}
		out = append(out, "", s.Title)
		used += titleCost
		kept := 0
		for _, line := range s.Lines {
			if used+len(line)+1+reserve > limit {
				break
			}
			out = append(out, line)
			used += len(line) + 1
			kept++
		}
		if kept < len(s.Lines) {
			note := fmt.Sprintf("- …이하 %d행 생략(길이 제한)", len(s.Lines)-kept)
			out = append(out, note)
			used += len(note) + 1
		}
	}

	if len(omitted) > 0 {
		out = append(out, "", fmt.Sprintf("> 길이 제한(%d자)으로 생략된 항목: %s. 전체 내용은 Markdown/JSON 산출물 참조.", limit, strings.Join(omitted, ", ")))
	}

	text := strings.Join(out, "\n")
	if len(text) > limit {
		return truncate(text, limit)
	}
	return text
}
