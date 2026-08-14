package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// The one thing on this dashboard that asks something other than AWS.
//
// Every other number here comes from CloudWatch or Logs Insights, both of which
// lag by minutes and, when a panel comes back empty, cannot distinguish "no
// traffic" from "nothing published yet". "Is the service answering right now" is
// not a question that data can answer, so this asks the service.
//
// Deliberately small: one GET, one status code, one elapsed time, run only when
// someone presses the button. Nothing is stored.
//
// On SSRF: the address has exactly one source, the 점검 tab's input field, and
// the service binds loopback on the operator's own machine. The response body is
// discarded, so a probe of a metadata endpoint yields a status code and a
// duration, not a credential. See src/lib/server/probe.ts for the full argument.
// If this ever stops being a single-operator local tool, a target allowlist
// becomes required.
const probeTimeout = 10 * time.Second

var schemeRe = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)

func parseTarget(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("점검할 주소가 비어 있습니다")
	}
	if !schemeRe.MatchString(trimmed) {
		trimmed = "http://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("http/https 주소만 점검합니다 (받은 값: %s:)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("주소에 호스트가 없습니다: %s", raw)
	}
	return u, nil
}

func expectLabel(expectStatus *int) string {
	if expectStatus != nil && *expectStatus > 0 {
		return fmt.Sprintf("%d 응답만", *expectStatus)
	}
	return "2xx 응답"
}

func statusMatches(status int, expectStatus *int) bool {
	if expectStatus != nil && *expectStatus > 0 {
		return status == *expectStatus
	}
	return status >= 200 && status < 300
}

// Probe reports whether the target answered. A probe that failed is still a
// completed probe: it comes back as a result with ok=false, not as an error.
// The dashboard failing and the target failing are different facts, and
// collapsing them makes a dashboard bug look like an outage. Only a malformed
// address is returned as an error.
func Probe(ctx context.Context, rawURL string, expectStatus *int) (types.ProbeResult, error) {
	u, err := parseTarget(rawURL)
	if err != nil {
		return types.ProbeResult{}, err
	}
	res := types.ProbeResult{
		URL:    u.String(),
		Ok:     false,
		At:     time.Now().UTC().Format(time.RFC3339Nano),
		Expect: expectLabel(expectStatus),
	}

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return types.ProbeResult{}, err
	}
	// Named on purpose: whoever reads the target's access log should be able to
	// tell this request apart from the traffic it stands in for.
	req.Header.Set("user-agent", "skills-dashboard/traffic-check")
	req.Header.Set("cache-control", "no-store")

	started := time.Now()
	resp, err := http.DefaultClient.Do(req)
	res.ElapsedMs = time.Since(started).Milliseconds()
	if err != nil {
		msg := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			msg = fmt.Sprintf("%d초 안에 응답 없음 (timeout)", int(probeTimeout/time.Second))
		}
		res.Error = types.Ptr(msg)
		return res, nil
	}
	defer resp.Body.Close()
	// Drained, never shown. This reports whether the service answered; a
	// response body on screen is a response body in a screenshot.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	res.Status = types.Ptr(resp.StatusCode)
	res.Ok = statusMatches(resp.StatusCode, expectStatus)
	if final := resp.Request.URL.String(); final != u.String() {
		res.FinalURL = types.Ptr(final)
	}
	return res, nil
}
