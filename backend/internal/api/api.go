// Package api is the HTTP surface: one route per public server action of the
// Next.js backend, each answering the same ActionResult envelope the UI already
// understands ({ok:true,data} | {ok:false,error}).
//
// Everything is POST with a JSON body, including the reads. The actions being
// replaced were POST-over-RPC too, none of them are cacheable by a proxy, and a
// uniform shape means one client helper instead of a per-route decision about
// where the arguments go.
package api

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/service"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// Envelope mirrors ActionResult<T> in src/lib/types.ts.
type Envelope struct {
	Ok   bool `json:"ok"`
	Data any  `json:"data"`
	// Omitted on success so the payload matches the discriminated union the UI
	// narrows on.
	Error string `json:"error,omitempty"`
}

var errBadBody = errors.New("요청 본문을 읽을 수 없습니다 (JSON 형식 확인)")

// A handled failure is a 200 with ok:false, not an HTTP error status: the UI
// renders the message either way, and a 500 in the browser console for
// "credentials not configured" sends whoever is debugging to the wrong place.
func fail(c *fiber.Ctx, err error) error {
	return c.JSON(Envelope{Ok: false, Error: err.Error()})
}

// handle is the whole request lifecycle: parse the body into P, run fn, wrap the
// result in the envelope. An empty body parses to the zero value, so the
// no-argument actions can be called with no payload at all.
func handle[P any, R any](fn func(c *fiber.Ctx, p P) (R, error)) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var p P
		if len(c.Body()) > 0 {
			if err := c.BodyParser(&p); err != nil {
				return fail(c, errBadBody)
			}
		}
		data, err := fn(c, p)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(Envelope{Ok: true, Data: data})
	}
}

// none is the body type of the actions that take no arguments.
type none struct{}

// windowArg is the body of every panel whose only argument is the shared window
// selection.
type windowArg struct {
	Window *types.WindowSelection `json:"window"`
}

// New builds the app. The service is already constructed, so this file has no
// knowledge of SQLite, AWS or Kubernetes.
func New(svc *service.Service, cfg config.Server) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:               "skills-dashboard-api",
		DisableStartupMessage: true,
		// Rule JSON pasted into the sandbox is capped at 64KB by the evaluator;
		// a whole WebACL export plus 50 test requests fits well under this.
		BodyLimit: 4 * 1024 * 1024,
	})
	// A panic in one handler must not take the dashboard's other panels down.
	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: cfg.AllowedOrigins,
		AllowMethods: strings.Join([]string{fiber.MethodGet, fiber.MethodPost, fiber.MethodOptions}, ","),
		AllowHeaders: "Content-Type",
	}))

	// Liveness plus the one dependency that is always required: without the
	// SQLite file there is no settings table and no history.
	app.Get("/healthz", func(c *fiber.Ctx) error {
		if err := svc.Store.Ping(); err != nil {
			return c.Status(fiber.StatusServiceUnavailable).
				JSON(fiber.Map{"status": "error", "db": err.Error()})
		}
		return c.JSON(fiber.Map{"status": "ok"})
	})

	api := app.Group("/api")

	// --- panels ---------------------------------------------------------------
	api.Post("/kube-panel", handle(func(c *fiber.Ctx, _ none) (types.KubePanel, error) {
		return svc.KubePanel(c.UserContext())
	}))
	api.Post("/metrics-panel", handle(func(c *fiber.Ctx, p windowArg) (types.MetricsPanel, error) {
		return svc.MetricsPanel(c.UserContext(), p.Window)
	}))
	api.Post("/waf-panel", handle(func(c *fiber.Ctx, p windowArg) (types.WafPanel, error) {
		return svc.WafPanel(c.UserContext(), p.Window)
	}))
	api.Post("/grading-panel", handle(func(c *fiber.Ctx, p windowArg) (types.GradingPanel, error) {
		return svc.GradingPanel(c.UserContext(), p.Window)
	}))
	api.Post("/resource-history", handle(func(c *fiber.Ctx, p windowArg) (types.ResourceHistory, error) {
		return svc.ResourceHistory(p.Window)
	}))
	api.Post("/waf-samples", handle(func(c *fiber.Ctx, _ none) ([]types.WafSampleRow, error) {
		return svc.WafSamples(c.UserContext())
	}))
	api.Post("/waf-history", handle(func(c *fiber.Ctx, _ none) ([]types.ApplyHistoryEntry, error) {
		return svc.WafHistory()
	}))

	// --- logs -----------------------------------------------------------------
	api.Post("/pod-logs", handle(func(c *fiber.Ctx, p service.PodLogsParams) (types.PodLogsResult, error) {
		return svc.PodLogs(c.UserContext(), p)
	}))
	api.Post("/request-log-rows", handle(func(c *fiber.Ctx, p service.RequestLogParams) (types.RequestLogQueryResult, error) {
		return svc.RequestLogRows(c.UserContext(), p)
	}))
	api.Post("/waf-log-rows", handle(func(c *fiber.Ctx, p service.WafLogParams) (types.WafLogQueryResult, error) {
		return svc.WafLogRows(c.UserContext(), p)
	}))

	// --- settings -------------------------------------------------------------
	api.Post("/settings", handle(func(c *fiber.Ctx, _ none) (types.SettingsView, error) {
		return svc.SettingsView(), nil
	}))
	api.Post("/settings/save", handle(func(c *fiber.Ctx, p map[string]string) (types.SettingsView, error) {
		return svc.SaveSettings(p)
	}))
	api.Post("/discover", handle(func(c *fiber.Ctx, p struct {
		Kind string `json:"kind"`
	}) (types.DiscoveryResult, error) {
		return svc.Discover(c.UserContext(), p.Kind)
	}))
	// The keys go one way only: every route here answers with the masked view,
	// and nothing on this surface can read an injected secret back out.
	api.Post("/credentials", handle(func(c *fiber.Ctx, _ none) (types.CredentialsView, error) {
		return svc.Credentials()
	}))
	api.Post("/credentials/save", handle(func(c *fiber.Ctx, p service.CredentialsInput) (types.CredentialsResult, error) {
		return svc.SaveCredentials(c.UserContext(), p)
	}))
	api.Post("/credentials/import", handle(func(c *fiber.Ctx, p service.ImportCredentialsInput) (types.CredentialsResult, error) {
		return svc.ImportCredentials(c.UserContext(), p)
	}))
	api.Post("/credentials/clear", handle(func(c *fiber.Ctx, _ none) (types.CredentialsResult, error) {
		return svc.ClearCredentials(c.UserContext())
	}))
	api.Post("/credentials/check", handle(func(c *fiber.Ctx, _ none) (types.CredentialsResult, error) {
		return svc.CheckCredentials(c.UserContext())
	}))

	// --- deployments ----------------------------------------------------------
	api.Post("/deployment", handle(func(c *fiber.Ctx, p struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}) (types.DeploymentInfo, error) {
		return svc.Deployment(c.UserContext(), p.Namespace, p.Name)
	}))
	api.Post("/deployment/preview", handle(func(c *fiber.Ctx, p service.DeploymentPatchRequest) (fiber.Map, error) {
		current, err := svc.PreviewPatch(c.UserContext(), p)
		if err != nil {
			return nil, err
		}
		return fiber.Map{"current": current}, nil
	}))
	api.Post("/deployment/patch", handle(func(c *fiber.Ctx, p service.DeploymentPatchRequest) (service.PatchResult, error) {
		return svc.PatchDeployment(c.UserContext(), p)
	}))
	api.Post("/deploy-history", handle(func(c *fiber.Ctx, _ none) ([]types.DeployChangeEntry, error) {
		return svc.ListDeployHistory()
	}))
	api.Post("/verify", handle(func(c *fiber.Ctx, p struct {
		HistoryID int `json:"historyId"`
	}) (types.VerificationResult, error) {
		return svc.Verify(c.UserContext(), p.HistoryID)
	}))

	// --- incident + sandbox ---------------------------------------------------
	api.Post("/incident-context", handle(func(c *fiber.Ctx, _ none) (types.IncidentContextResult, error) {
		return svc.IncidentContext(c.UserContext())
	}))
	api.Post("/test-requests/default", handle(func(c *fiber.Ctx, _ none) ([]types.TestRequest, error) {
		return svc.DefaultTestRequests(), nil
	}))
	api.Post("/test-requests/malicious", handle(func(c *fiber.Ctx, _ none) ([]types.TestRequest, error) {
		return svc.MaliciousTestRequests(), nil
	}))
	api.Post("/assemble-rule", handle(func(c *fiber.Ctx, p struct {
		Kind   string                 `json:"kind"`
		Window *types.WindowSelection `json:"window"`
	}) (types.AssembledRule, error) {
		return svc.AssembleRule(c.UserContext(), p.Kind, p.Window)
	}))
	api.Post("/waf-rule/update", handle(func(c *fiber.Ctx, p struct {
		RuleJson string                 `json:"ruleJson"`
		Action   *string                `json:"action"`
		Window   *types.WindowSelection `json:"window"`
	}) (types.WafRuleUpdateResult, error) {
		return svc.UpdateWafRule(c.UserContext(), p.RuleJson, p.Action, p.Window)
	}))
	api.Post("/waf-evidence", handle(func(c *fiber.Ctx, p struct {
		RuleName string                 `json:"ruleName"`
		Window   *types.WindowSelection `json:"window"`
	}) (types.CountEvidence, error) {
		return svc.CountEvidence(c.UserContext(), p.RuleName, p.Window)
	}))
	api.Post("/node-cost", handle(func(c *fiber.Ctx, _ none) (types.NodeCountProjection, error) {
		return svc.NodeCost(c.UserContext())
	}))
	api.Post("/test-rule", handle(func(c *fiber.Ctx, p service.RuleTestParams) (types.RuleTestResult, error) {
		return svc.TestRule(c.UserContext(), p)
	}))
	api.Post("/probe", handle(func(c *fiber.Ctx, p struct {
		URL          string `json:"url"`
		ExpectStatus *int   `json:"expectStatus"`
	}) (types.ProbeResult, error) {
		return svc.Probe(c.UserContext(), p.URL, p.ExpectStatus)
	}))

	return app
}
