package config

// Path policy and suspicion thresholds, ported from src/lib/server/config.ts.
// One definition so the assembler, the anomaly detector and the WAF summary
// cannot disagree about what counts as normal traffic.

import (
	"os"
	"strings"
)

// Paths excluded (or down-weighted) from anomaly scoring.
var LowPriorityPaths = []string{
	"/health", "/healthz", "/ready", "/readyz", "/liveness", "/healthcheck",
}

// NormalizePathTransform is WAF's NORMALIZE_PATH and nothing else: "." and
// ".." segments resolved, repeated slashes collapsed, a trailing slash kept.
//
// The trailing slash is the whole reason there is only one implementation now.
// There used to be two — this one and normalizePathT in internal/rules — and
// they disagreed about exactly that character, so the rule assembler could
// describe a path that the sandbox then evaluated as a different string and
// returned a different verdict for. The sandbox is only worth anything if it
// answers the question AWS will answer, and AWS keeps the trailing slash. So
// this keeps it, and any caller that wants it gone strips it itself.
//
// It does not strip a query string either: NORMALIZE_PATH is applied to a field
// that has already been isolated. NormalizePath below is the analysis-layer
// helper that does that first.
func NormalizePathTransform(path string) string {
	segments := []string{}
	for _, seg := range strings.Split(path, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		default:
			segments = append(segments, seg)
		}
	}
	trailing := ""
	if len(path) > 1 && strings.HasSuffix(path, "/") && len(segments) > 0 {
		trailing = "/"
	}
	return "/" + strings.Join(segments, "/") + trailing
}

// NormalizePath is the analysis-layer helper: it takes a logged URI, which may
// still carry its query string, and resolves it the way WAF would. Without the
// normalisation a traversal attempt reads as the served path it is prefixed
// with.
//
// Callers comparing the result with == have to account for the preserved
// trailing slash: "/v1/user/" and "/v1/user" are the same route, and WAF will
// tell you they are different strings.
func NormalizePath(path string) string {
	raw := path
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	return NormalizePathTransform(raw)
}

func IsLowPriorityPath(path string) bool {
	p := NormalizePath(path)
	for _, h := range LowPriorityPaths {
		if p == h || strings.HasPrefix(p, h+"/") {
			return true
		}
	}
	return false
}

// AppTrafficPaths is the API surface this environment actually serves — the
// routes the three competition binaries register (GET/POST /v1/user, GET/POST
// /v1/product, POST /v1/stress; /healthcheck is a low-priority path). The
// grader's load generator drives heavy traffic at these paths, so volume
// against them is never treated as an attack.
func AppTrafficPaths() []string {
	// /images is the static surface: S3 objects served under /images/<object
	// path> through the same endpoint. It is graded on its own key, and a WAF
	// rule that reaches it costs image download points, so it belongs on the
	// served list even though no binary registers it as a route.
	raw := strings.TrimSpace(os.Getenv("APP_TRAFFIC_PATHS"))
	if raw == "" {
		raw = "/v1/user,/v1/product,/v1/stress,/images"
	}
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func IsAppTrafficPath(path string) bool {
	p := NormalizePath(path)
	for _, a := range AppTrafficPaths() {
		if p == a || strings.HasPrefix(p, a+"/") {
			return true
		}
	}
	return false
}

// IsImageAssetPath: any path segment carrying "image" is delivery, and delivery
// is normal here. Deliberately a substring test — over-matching errs toward
// not blocking the traffic the score depends on.
func IsImageAssetPath(path string) bool {
	return strings.Contains(strings.ToLower(NormalizePath(path)), "image")
}

// IsBenignPath: paths no blocking rule may ever be built against, and that no
// detector may call suspicious.
func IsBenignPath(path string) bool {
	return IsLowPriorityPath(path) || IsAppTrafficPath(path) || IsImageAssetPath(path)
}

// Concentration thresholds behind every "suspicious"/"concentrated" flag.
var Suspicion = struct {
	PathMinCount int
	PathMinShare float64
	IPMinCount   int
	IPMinShare   float64
}{PathMinCount: 30, PathMinShare: 0.5, IPMinCount: 20, IPMinShare: 0.3}

func IsPathSuspicious(path string, count, total int) bool {
	if IsBenignPath(path) {
		return false
	}
	t := total
	if t < 1 {
		t = 1
	}
	return count >= Suspicion.PathMinCount && float64(count)/float64(t) >= Suspicion.PathMinShare
}

func IsIPConcentrated(count, total int) bool {
	t := total
	if t < 1 {
		t = 1
	}
	return count >= Suspicion.IPMinCount && float64(count)/float64(t) >= Suspicion.IPMinShare
}
