package config

// Path normalisation is shared between the rule assembler and the sandbox, so a
// disagreement here shows up as a rule that tests one way and behaves another.

import "testing"

func TestNormalizePathTransformMatchesWaf(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"traversal is resolved", "/v1/image/../../etc/passwd", "/etc/passwd"},
		{"dot segments are dropped", "/v1/./user", "/v1/user"},
		{"repeated slashes collapse", "//v1///user", "/v1/user"},
		{"traversal past the root stops at the root", "/../../..", "/"},
		// The one the two old implementations disagreed about. WAF's
		// NORMALIZE_PATH keeps it, so the sandbox has to keep it too.
		{"trailing slash is preserved", "/v1/user/", "/v1/user/"},
		{"trailing slash survives normalisation", "/v1//user/", "/v1/user/"},
		{"the root is left alone", "/", "/"},
		{"an empty path is the root", "", "/"},
		// NORMALIZE_PATH is applied to an already-isolated field, so a query
		// string is data, not a path separator.
		{"a query string is not stripped here", "/v1/user?a=1", "/v1/user?a=1"},
	}
	for _, c := range cases {
		if got := NormalizePathTransform(c.in); got != c.want {
			t.Errorf("%s: NormalizePathTransform(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestNormalizePathStripsTheQueryString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/v1/user?requestid=1", "/v1/user"},
		{"/v1/user/?requestid=1", "/v1/user/"},
		{"/v1/image/../../etc/passwd?x=1", "/etc/passwd"},
		{"/v1/user", "/v1/user"},
	}
	for _, c := range cases {
		if got := NormalizePath(c.in); got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The preserved trailing slash must not make a benign path look unfamiliar —
// these three decide whether a blocking rule may be built against a path at
// all, and a false "unknown path" here is how the served surface gets blocked.
func TestBenignPathsToleratePreservedTrailingSlash(t *testing.T) {
	for _, path := range []string{"/healthcheck", "/healthcheck/", "/health/"} {
		if !IsLowPriorityPath(path) {
			t.Errorf("%q must stay low priority", path)
		}
	}
	for _, path := range []string{"/v1/user", "/v1/user/", "/v1/product/?x=1"} {
		if !IsAppTrafficPath(path) {
			t.Errorf("%q must stay app traffic", path)
		}
	}
	if IsBenignPath("/admin/") {
		t.Error("/admin/ is not part of the served surface")
	}
}
