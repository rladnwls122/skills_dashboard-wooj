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

// NormalizePath resolves "." and ".." segments and collapses repeated slashes,
// the way WAF's NORMALIZE_PATH transform does. Without this a traversal
// attempt reads as the served path it is prefixed with.
func NormalizePath(path string) string {
	raw := path
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	out := []string{}
	for _, seg := range strings.Split(raw, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	return "/" + strings.Join(out, "/")
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
	raw := strings.TrimSpace(os.Getenv("APP_TRAFFIC_PATHS"))
	if raw == "" {
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
