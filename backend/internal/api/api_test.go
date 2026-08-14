package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/service"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
)

func newTestApp(t *testing.T) *fiber.App {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	svc := service.New(st, config.NewSettings(st), service.Unavailable{})
	return New(svc, config.Server{AllowedOrigins: "http://localhost:3000"})
}

func post(t *testing.T, app *fiber.App, path, body string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d", path, res.StatusCode)
	}
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v (%s)", path, err, raw)
	}
	return out
}

func TestHealthz(t *testing.T) {
	res, err := newTestApp(t).Test(httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestLocalRoutesAnswerSuccessEnvelope(t *testing.T) {
	app := newTestApp(t)
	// No body at all: the no-argument actions must not require one.
	for _, path := range []string{
		"/api/settings", "/api/waf-history", "/api/deploy-history",
		"/api/test-requests/default", "/api/test-requests/malicious",
	} {
		if out := post(t, app, path, ""); out["ok"] != true {
			t.Errorf("%s: %v", path, out)
		}
	}
	if out := post(t, app, "/api/resource-history", `{"window":{"windowMin":30,"intervalMin":5}}`); out["ok"] != true {
		t.Errorf("resource-history: %v", out)
	}
}

func TestUnportedCapabilitiesFailInsideTheEnvelope(t *testing.T) {
	app := newTestApp(t)
	// A capability this build cannot serve is a handled failure — HTTP 200 with
	// ok:false — because that is what the UI already renders.
	for _, path := range []string{"/api/kube-panel", "/api/metrics-panel", "/api/waf-panel", "/api/incident-context"} {
		out := post(t, app, path, "")
		if out["ok"] != false {
			t.Errorf("%s: expected ok:false, got %v", path, out)
		}
		if msg, _ := out["error"].(string); msg == "" {
			t.Errorf("%s: expected an error message", path)
		}
	}
}

func TestValidationRejectsPatchWithoutCallingTheCluster(t *testing.T) {
	app := newTestApp(t)
	out := post(t, app, "/api/deployment/patch", `{"namespace":"kube-system","name":"api","replicas":2}`)
	if out["ok"] != false || !strings.Contains(out["error"].(string), "namespace must be") {
		t.Fatalf("expected namespace rejection, got %v", out)
	}
}

func TestMalformedBodyIsReported(t *testing.T) {
	out := post(t, newTestApp(t), "/api/probe", `{"url":`)
	if out["ok"] != false {
		t.Fatalf("expected ok:false for malformed JSON, got %v", out)
	}
}

func TestSettingsSaveRoundTrip(t *testing.T) {
	app := newTestApp(t)
	out := post(t, app, "/api/settings/save", `{"ALB_NAME":"other-alb"}`)
	if out["ok"] != true {
		t.Fatalf("save: %v", out)
	}
	data := out["data"].(map[string]any)
	rows := data["rows"].([]any)
	for _, r := range rows {
		row := r.(map[string]any)
		if row["key"] == "ALB_NAME" && (row["value"] != "other-alb" || row["source"] != "screen") {
			t.Fatalf("override not applied: %v", row)
		}
	}
}
