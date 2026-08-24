package service

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, config.NewSettings(st), Unavailable{})
}

func TestResolveWindowCorrectsInvalidSelection(t *testing.T) {
	// An unknown span falls back to the default rather than being rejected: a
	// stale bookmark should still render.
	got := ResolveWindow(&types.WindowSelection{WindowMin: 7, IntervalMin: 3}, 1_700_000_123_456)
	if got.WindowMin != 60 || got.IntervalMin != 1 {
		t.Fatalf("expected the 60m/1m default, got %+v", got)
	}
	// The end is floored to an interval boundary, so the last bucket is complete.
	if got.EndMs%60_000 != 0 {
		t.Fatalf("end not floored: %d", got.EndMs)
	}
	if got.EndMs-got.StartMs != 60*60_000 || got.Buckets != 60 {
		t.Fatalf("span/bucket mismatch: %+v", got)
	}
	// An interval that is not on the offered list falls back to the smallest
	// one that yields a readable bucket count for the span.
	wide := ResolveWindow(&types.WindowSelection{WindowMin: 240, IntervalMin: 2}, 1_700_000_123_456)
	if wide.IntervalMin != 1 || wide.Buckets != 240 {
		t.Fatalf("expected 240m/1m, got %+v", wide)
	}
	// 15m has no 60m interval — that would be a single bucket.
	narrow := ResolveWindow(&types.WindowSelection{WindowMin: 15, IntervalMin: 60}, 1_700_000_123_456)
	if narrow.IntervalMin != 1 || narrow.Buckets != 15 {
		t.Fatalf("expected 15m/1m, got %+v", narrow)
	}
}

func TestValidateRejectsBeforeTouchingTheCluster(t *testing.T) {
	svc := newTestService(t)
	over := 999
	cases := []struct {
		name string
		req  DeploymentPatchRequest
	}{
		{"bad namespace", DeploymentPatchRequest{Namespace: "Default!", Name: "api"}},
		{"other namespace", DeploymentPatchRequest{Namespace: "kube-system", Name: "api"}},
		{"bad name", DeploymentPatchRequest{Namespace: "default", Name: "API_1"}},
		{"replicas over max", DeploymentPatchRequest{Namespace: "default", Name: "api", Replicas: &over}},
	}
	for _, c := range cases {
		if err := svc.Validate(c.req); err == nil {
			t.Errorf("%s: expected rejection", c.name)
		}
	}
	ok := 3
	if err := svc.Validate(DeploymentPatchRequest{Namespace: "default", Name: "api", Replicas: &ok}); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestVerifyWaitsForRolloutBeforeJudging(t *testing.T) {
	svc := newTestService(t)
	now := time.UnixMilli(1_700_000_000_000)
	svc.Now = func() time.Time { return now }
	id, err := svc.Store.InsertDeployHistory("default", "api", "replicas=3", `{"trt":1,"c4xx":0,"c5xx":0,"restarts":0}`, now.UnixMilli()-10_000)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.Verify(context.Background(), id)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != "INCONCLUSIVE" || len(res.Details) != 1 || !strings.Contains(res.Details[0], "재검증") {
		t.Fatalf("expected a wait result, got %+v", res)
	}
	// Past the delay, the comparison needs metrics — which this build cannot
	// read — so it must fail loudly rather than invent a verdict.
	svc.Now = func() time.Time { return now.Add(5 * time.Minute) }
	if _, err := svc.Verify(context.Background(), id); err == nil {
		t.Fatal("expected the unavailable provider to surface an error")
	}
	if _, err := svc.Verify(context.Background(), id+999); err == nil {
		t.Fatal("expected an unknown history id to fail")
	}
}

func TestResourceHistoryReadsBackRecordedSamples(t *testing.T) {
	svc := newTestService(t)
	// Inside the writer's 6h retention, else the sweep drops what we just wrote.
	now := time.Now()
	svc.Now = func() time.Time { return now }
	pct := 55.55
	err := svc.RecordResourceSamples(
		[]types.PodResourceUsage{
			{Pod: "api-7d9", CPUPct: &pct, MemPct: nil},
			{Pod: "web-1", CPUPct: nil, MemPct: nil},
		},
		[]types.NodeResourceUsage{{Name: "ip-10-0-1-1", CPUPct: 12.3, MemPct: 40}},
		// Two minutes back: the window's end is floored to an interval boundary,
		// so a reading taken this instant is not in it yet.
		now.Add(-2*time.Minute).UnixMilli(),
	)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	hist, err := svc.ResourceHistory(nil)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist.PodCPU) != 1 || hist.PodCPU[0].Label != "api-7d9" {
		t.Fatalf("pod cpu series: %+v", hist.PodCPU)
	}
	if hist.PodCPU[0].Points[0].V != 55.6 {
		t.Fatalf("expected one decimal, got %v", hist.PodCPU[0].Points[0].V)
	}
	// A pod with no limit has no percentage; writing 0 would draw a floor that
	// reads as "idle" when it means "not measurable".
	if len(hist.PodMem) != 0 {
		t.Fatalf("expected no mem series, got %+v", hist.PodMem)
	}
	if len(hist.NodeCPU) != 1 || len(hist.NodeMem) != 1 {
		t.Fatalf("node series: %+v %+v", hist.NodeCPU, hist.NodeMem)
	}
}

func TestSettingsOverrideBeatsDefaultAndReportsSource(t *testing.T) {
	svc := newTestService(t)
	view := svc.SettingsView()
	if len(view.Rows) != len(config.Specs) {
		t.Fatalf("expected every spec rendered, got %d", len(view.Rows))
	}
	if _, err := svc.SaveSettings(map[string]string{"WAF_WEB_ACL_NAME": " other-acl ", "NOT_A_SETTING": "x"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	view = svc.SettingsView()
	for _, row := range view.Rows {
		if row.Key != "WAF_WEB_ACL_NAME" {
			continue
		}
		if row.Value != "other-acl" || row.Source != "screen" || row.DefaultValue != "skills-waf" {
			t.Fatalf("override row wrong: %+v", row)
		}
	}
	if !strings.Contains(view.EnvText, "WAF_WEB_ACL_NAME=other-acl") {
		t.Fatalf("envText should list screen overrides, got %q", view.EnvText)
	}
	if strings.Contains(view.EnvText, "NOT_A_SETTING") {
		t.Fatalf("unknown keys must be ignored, got %q", view.EnvText)
	}
}

func TestSandboxRequestSets(t *testing.T) {
	benign := DefaultTestRequests()
	if len(benign) < 3 {
		t.Fatalf("expected the served paths plus loadgen and healthcheck, got %d", len(benign))
	}
	for _, r := range benign {
		if !r.Benign {
			t.Fatalf("default set must be benign: %+v", r)
		}
	}
	for _, r := range MaliciousExampleRequests() {
		if r.Benign {
			t.Fatalf("malicious set must not be benign: %+v", r)
		}
	}
}

func TestProbeRejectsNonHttpTargets(t *testing.T) {
	svc := newTestService(t)
	for _, raw := range []string{"", "file:///etc/passwd", "gopher://x"} {
		if _, err := svc.Probe(context.Background(), raw, nil); err == nil {
			t.Errorf("%q should be rejected", raw)
		}
	}
}

// The preview path and the apply path have to reject the same requests. They
// used to run two separate copies of the rules and this one was the weaker: the
// confirm screen accepted resource quantities that the cluster then refused,
// with the operator already committed to the change.
func TestValidateEnforcesTheSameResourceRulesAsTheApplyPath(t *testing.T) {
	svc := newTestService(t)
	container := "api"
	str := func(s string) *string { return &s }
	rejected := []struct {
		name string
		req  DeploymentPatchRequest
	}{
		{"cpu quantity nonsense", DeploymentPatchRequest{
			Namespace: "default", Name: "api", ContainerName: &container, CPULimit: str("half a core")}},
		{"cpu quantity with a unit kubernetes does not take", DeploymentPatchRequest{
			Namespace: "default", Name: "api", ContainerName: &container, CPULimit: str("500mi")}},
		{"memory quantity without a unit", DeploymentPatchRequest{
			Namespace: "default", Name: "api", ContainerName: &container, MemLimit: str("256")}},
		{"resource change without a container", DeploymentPatchRequest{
			Namespace: "default", Name: "api", MemLimit: str("256Mi")}},
	}
	for _, c := range rejected {
		if err := svc.Validate(c.req); err == nil {
			t.Errorf("%s: expected rejection", c.name)
		}
	}
	accepted := []DeploymentPatchRequest{
		{Namespace: "default", Name: "api", ContainerName: &container, CPULimit: str("500m"), MemLimit: str("256Mi")},
		{Namespace: "default", Name: "api", ContainerName: &container, CPULimit: str("1")},
		{Namespace: "default", Name: "api", ContainerName: &container, CPULimit: str("1.5"), MemLimit: str("1Gi")},
	}
	for _, req := range accepted {
		if err := svc.Validate(req); err != nil {
			t.Errorf("valid request rejected: %+v: %v", req, err)
		}
	}
	// The string internal/api's tests assert on has to survive the extraction.
	err := svc.Validate(DeploymentPatchRequest{Namespace: "kube-system", Name: "api"})
	if err == nil || !strings.Contains(err.Error(), "namespace must be") {
		t.Fatalf("namespace rejection message changed: %v", err)
	}
}
