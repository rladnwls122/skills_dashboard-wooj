package live

// What a COUNT rule actually caught, and whether any of it was legitimate.
//
// A count of matches is not enough to promote a rule to BLOCK: twenty matches
// could be twenty attacks or twenty real users. The only way to tell from the
// outside is to line each matched request up with what the application did with
// it — a 2xx means the request was served normally, and blocking it would have
// cost availability.
//
// Two queries, not one. The WAF log for a CLOUDFRONT-scope Web ACL lives in
// us-east-1 while the application log lives in the workload region, and Logs
// Insights cannot cross regions. So: pull the matched requests, take their
// request ids, ask the application log about those ids, and join here.
//
// GET only, and that is final. The task appends requestid/uuid to the query
// string and the app reads them from there, so POST/PUT carry no join key on
// either side. Those matches are reported as unjoinable rather than folded into
// either bucket — the screen must not invent evidence it does not have.
//
// Ported from wafcountevidence.ts.

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/analysis"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/awsx"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

const (
	// GetSampledRequests caps at 500 per rule and the count set is small by
	// construction; a higher cap would only add rows nobody scrolls to.
	matchLimit = 500
	// How many ids one join query carries. Insights takes an `in` list inline,
	// so this bounds the query text as well as the scan.
	joinBatch = 200
)

var regexMetaRe = regexp.MustCompile(`[.*+?^${}()|\[\]\\/]`)

// escapeForRegex escapes a rule name for embedding in an Insights regex
// literal.
func escapeForRegex(s string) string {
	return regexMetaRe.ReplaceAllString(s, `\$0`)
}

// buildCountQuery finds the requests a COUNT rule matched.
//
// The obvious filter — `action = "COUNT"` — never matches anything. A counting
// rule does not terminate evaluation, so the request's action is whatever the
// rest of the ACL decided, normally ALLOW. The match is recorded in
// `nonTerminatingMatchingRules`, which appears both at the top level and again
// inside each `ruleGroupList` entry.
//
// ponytail: matched by regex on the raw message rather than by enumerating
// `nonTerminatingMatchingRules.<i>.ruleId` at every index and nesting depth.
// Two known imprecisions, both acceptable here: a request this rule counted but
// another rule blocked is excluded (we only care whether the rule would break
// legitimate traffic, and that traffic was not served either way), and a rule
// whose name is quoted inside another field would false-positive. Enumerate the
// indices if either ever bites.
func buildCountQuery(ruleName string) string {
	return strings.Join([]string{
		"fields @timestamp, httpRequest.uri as uri, httpRequest.args as args",
		"httpRequest.httpMethod as method",
		fmt.Sprintf(`filter @message like /"ruleId":"%s"/`, escapeForRegex(ruleName)),
		`filter action != "BLOCK"`,
		"sort @timestamp desc",
		fmt.Sprintf("limit %d", matchLimit),
	}, " | ")
}

// buildJoinQuery is the application's side of the join. `limit` is explicit
// because Insights truncates at 10,000 rows silently, and a silent truncation
// here would read as "no legitimate traffic was caught".
func buildJoinQuery(requestIDs []string) string {
	quoted := make([]string, 0, len(requestIDs))
	for _, id := range requestIDs {
		quoted = append(quoted, `"`+strings.ReplaceAll(id, `"`, "")+`"`)
	}
	return strings.Join([]string{
		"fields @timestamp, log",
		analysis.ParseFields,
		fmt.Sprintf("filter requestid in [%s]", strings.Join(quoted, ", ")),
		"fields requestid, status, latency_ms, path, method",
		fmt.Sprintf("limit %d", len(requestIDs)),
	}, " | ")
}

// extractRequestID reads the join key out of the query string. The WAF log
// stores it verbatim, with or without a leading "?". Either `requestid` or
// `uuid` is the key — the task appends both and the app writes both, but only
// one is present on some paths.
func extractRequestID(args string) *string {
	if args == "" {
		return nil
	}
	q := strings.TrimPrefix(args, "?")
	for _, pair := range strings.Split(q, "&") {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		key := pair[:eq]
		if key != "requestid" && key != "uuid" {
			continue
		}
		raw := pair[eq+1:]
		if raw == "" {
			continue
		}
		if decoded, err := url.QueryUnescape(raw); err == nil {
			return types.Ptr(decoded)
		}
		// A malformed escape is still a usable literal key.
		return types.Ptr(raw)
	}
	return nil
}

// verdictFor: a served request is one the application answered 2xx. Anything
// else — an error, a 404, a redirect — is not evidence that blocking would have
// cost anything.
func verdictFor(status *int) string {
	if status == nil {
		return "unjoinable"
	}
	if *status >= 200 && *status < 300 {
		return "normal"
	}
	return "abnormal"
}

func summarize(ruleName string, matches []types.CountMatch) types.CountEvidence {
	out := types.CountEvidence{RuleName: ruleName, Total: len(matches), Matches: matches, Notes: []string{}}
	if out.Matches == nil {
		out.Matches = []types.CountMatch{}
	}
	for _, m := range matches {
		switch m.Verdict {
		case "normal":
			out.Normal++
		case "abnormal":
			out.Abnormal++
		default:
			out.Unjoinable++
		}
	}
	return out
}

// promotionNote says whether the evidence supports promoting the rule to BLOCK.
// Advisory only — the button is never disabled by this, because waiting for a
// sample during a two-hour match can cost more than the rule is worth.
func promotionNote(e types.CountEvidence) string {
	if e.Normal > 0 {
		return fmt.Sprintf("정상 응답을 받은 요청 %d건이 이 규칙에 걸렸습니다 — 승격하면 그만큼 403이 나갑니다.", e.Normal)
	}
	if e.Total < 20 {
		return fmt.Sprintf("표본 부족 (%d건). 20건 이상 쌓인 뒤 판단하는 편이 안전합니다.", e.Total)
	}
	return fmt.Sprintf("매칭 %d건 중 정상 응답 0건. 승격해도 정상 트래픽에 닿지 않습니다.", e.Total)
}

func (p *Provider) CountEvidence(ctx context.Context, ruleName string, win types.ResolvedWindow) (types.CountEvidence, error) {
	if strings.TrimSpace(ruleName) == "" {
		return types.CountEvidence{}, fmt.Errorf("규칙 이름이 비어 있습니다.")
	}
	logGroup := p.Settings.WafLogGroup()
	if logGroup == "" {
		out := summarize(ruleName, nil)
		out.Notes = []string{"WAF 로그 그룹이 설정되지 않아 COUNT 실측을 읽을 수 없습니다. 설정에서 지정하세요."}
		return out, nil
	}

	wafRes, err := p.AWS.RunInsightsQuery(ctx, awsx.InsightsParams{
		LogGroup: logGroup,
		Region:   p.Settings.WafRegion(),
		Query:    buildCountQuery(ruleName),
		StartMs:  &win.StartMs,
		EndMs:    &win.EndMs,
	})
	if err != nil {
		return types.CountEvidence{}, err
	}

	notes := []string{}
	matches := make([]types.CountMatch, 0, len(wafRes.Rows))
	for _, r := range wafRes.Rows {
		args := r["args"]
		matches = append(matches, types.CountMatch{
			Ts:        analysis.ToIso(r["@timestamp"]),
			Method:    r["method"],
			URI:       r["uri"],
			Args:      args,
			RequestID: extractRequestID(args),
			Verdict:   "unjoinable",
		})
	}
	if len(matches) == matchLimit {
		notes = append(notes, fmt.Sprintf("매칭이 %d건 상한에 닿았습니다 — 실제로는 더 많습니다.", matchLimit))
	}

	ids := []string{}
	seen := map[string]struct{}{}
	for _, m := range matches {
		if m.RequestID == nil {
			continue
		}
		if _, dup := seen[*m.RequestID]; dup {
			continue
		}
		seen[*m.RequestID] = struct{}{}
		ids = append(ids, *m.RequestID)
	}

	bytes := wafRes.BytesScanned
	if len(ids) > 0 && p.Settings.AppLogGroup() != "" {
		type appHit struct {
			status  *int
			latency *float64
		}
		byID := map[string]appHit{}
		for start := 0; start < len(ids); start += joinBatch {
			end := start + joinBatch
			if end > len(ids) {
				end = len(ids)
			}
			appRes, err := p.AWS.RunInsightsQuery(ctx, awsx.InsightsParams{
				LogGroup: p.Settings.AppLogGroup(),
				Region:   p.Settings.Region(),
				Query:    buildJoinQuery(ids[start:end]),
				StartMs:  &win.StartMs,
				EndMs:    &win.EndMs,
			})
			if err != nil {
				// The WAF half is still worth showing: the matches are real and
				// the join is what could not be made.
				notes = append(notes, "앱 로그 조인 실패 — 정상/비정상 판정 없이 매칭만 표시합니다: "+awsx.ErrMsg(err))
				break
			}
			bytes += appRes.BytesScanned
			for _, row := range appRes.Rows {
				// Insights results are sparse: a field with no value is absent,
				// not empty, so every read has to tolerate the zero value.
				id := row["requestid"]
				if id == "" {
					continue
				}
				hit := appHit{}
				if raw, ok := row["status"]; ok && raw != "" {
					hit.status = types.Ptr(atoiF(raw))
				}
				if raw, ok := row["latency_ms"]; ok && raw != "" {
					hit.latency = types.Ptr(parseF(raw))
				}
				byID[id] = hit
			}
		}
		for i := range matches {
			if matches[i].RequestID == nil {
				continue
			}
			hit, ok := byID[*matches[i].RequestID]
			if !ok {
				continue
			}
			matches[i].Status = hit.status
			matches[i].LatencyMs = hit.latency
			matches[i].Verdict = verdictFor(hit.status)
		}
	}

	noKey := 0
	for _, m := range matches {
		if m.RequestID == nil {
			noKey++
		}
	}
	if noKey > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d건은 조인 키가 없습니다 (POST/PUT은 requestid가 쿼리스트링에 실리지 않습니다). 정상/비정상 어느 쪽으로도 세지 않았습니다.", noKey))
	}

	out := summarize(ruleName, matches)
	out.BytesScanned = bytes
	out.Notes = append(notes, promotionNote(out))
	return out, nil
}
