package rules

import (
	"strings"
	"testing"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func TestTestRuleBlocksMaliciousPath(t *testing.T) {
	ruleJSON := `{
	  "Name": "block-wp",
	  "Priority": 0,
	  "Action": { "Block": {} },
	  "Statement": {
	    "ByteMatchStatement": {
	      "SearchString": "/wp-login.php",
	      "FieldToMatch": { "UriPath": {} },
	      "PositionalConstraint": "STARTS_WITH",
	      "TextTransformations": [ { "Priority": 0, "Type": "LOWERCASE" } ]
	    }
	  }
	}`
	requests := []types.TestRequest{
		{ID: "benign", Method: "GET", Path: "/v1/user", UserAgent: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36", IP: "10.0.0.1", Country: "KR", Benign: true},
		{ID: "mal", Method: "GET", Path: "/wp-login.php", UserAgent: "curl/8", IP: "203.0.113.9", Country: "CN", Benign: false},
	}
	res, err := TestRule(ruleJSON, requests)
	if err != nil {
		t.Fatal(err)
	}
	if res.Caught != 1 || res.Blocked != 0 || res.Passed != 1 {
		t.Fatalf("caught=%d blocked=%d passed=%d", res.Caught, res.Blocked, res.Passed)
	}
	if res.Verdict != "SAFE" {
		t.Fatalf("verdict=%s", res.Verdict)
	}
}

func TestTestRuleManagedGroupApproximation(t *testing.T) {
	ruleJSON := `{
	  "Name": "managed",
	  "Priority": 0,
	  "OverrideAction": { "None": {} },
	  "Statement": {
	    "ManagedRuleGroupStatement": { "VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet" }
	  }
	}`
	requests := []types.TestRequest{
		{ID: "traversal", Method: "GET", Path: "/v1/image/../../etc/passwd", UserAgent: "curl/8.4.0", IP: "203.0.113.14", Country: "CN", Benign: false},
	}
	res, err := TestRule(ruleJSON, requests)
	if err != nil {
		t.Fatal(err)
	}
	if res.Caught != 1 {
		t.Fatalf("caught=%d rows=%+v", res.Caught, res.Rows)
	}
	if len(res.Approximated) == 0 {
		t.Fatal("managed group must be reported as approximated")
	}
}

func TestAssembleSqliRoundTripsThroughSandbox(t *testing.T) {
	assembled, err := AssembleRule("sqli", types.HttpSummary{}, AssembleEnv{WafScope: "CLOUDFRONT", WafRegion: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(assembled.RuleJson, "<dash-sqli-signatures-ARN>") {
		t.Fatal("console rule must carry the ARN placeholder")
	}
	requests := []types.TestRequest{
		{ID: "sqli", Method: "GET", Path: "/v1/user", Query: "id=1%20OR%201=1", UserAgent: "sqlmap/1.7", IP: "203.0.113.8", Country: "RU", Benign: false},
		{ID: "ok", Method: "GET", Path: "/v1/user", Query: "id=42", UserAgent: "Mozilla/5.0 (X11) AppleWebKit/537.36", IP: "10.0.2.88", Country: "KR", Benign: true},
	}
	res, err := TestRule(assembled.SandboxRuleJson, requests)
	if err != nil {
		t.Fatal(err)
	}
	if res.Caught != 1 || res.Blocked != 0 {
		t.Fatalf("caught=%d blocked=%d rows=%+v", res.Caught, res.Blocked, res.Rows)
	}
}

func TestClassifyUa(t *testing.T) {
	cases := []struct {
		ua       string
		category ThreatCategory // "" = allowed
	}{
		{"sqlmap/1.7", CategoryScanner},
		{"nmap scripting engine", CategoryRecon},
		{"${jndi:ldap://x/a}", CategorySpoofed},
		{"curl/8.4.0", CategoryAutomation},
		{"Go-http-client/2.0", ""},
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36", ""},
		{"ELB-HealthChecker/2.0", ""},
		{"Mozilla/5.0 (compatible)", CategoryUnknown},
	}
	for _, c := range cases {
		hit := ClassifyUa(c.ua)
		if c.category == "" {
			if hit != nil {
				t.Fatalf("%q: expected allowed, got %+v", c.ua, hit)
			}
			continue
		}
		if hit == nil || hit.Category != c.category {
			t.Fatalf("%q: expected %s, got %+v", c.ua, c.category, hit)
		}
	}
}

func TestIPInCidr(t *testing.T) {
	if !IPInCidr("10.1.2.3", "10.0.0.0/8") {
		t.Fatal("10.1.2.3 in 10/8")
	}
	if IPInCidr("11.0.0.1", "10.0.0.0/8") {
		t.Fatal("11.0.0.1 not in 10/8")
	}
	if !IPInCidr("2001:db8::1", "2001:db8::/32") {
		t.Fatal("v6 prefix")
	}
	if !IsPrivateIP("192.168.0.7") || IsPrivateIP("203.0.113.5") {
		t.Fatal("private detection")
	}
}

func TestJsonDocumentsTolerantParsing(t *testing.T) {
	docs, err := ParseJsonDocuments(`{"a":1,} // comment
{"b":2}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("docs=%d", len(docs))
	}
}
