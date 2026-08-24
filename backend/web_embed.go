//go:build embed

// The single-binary release. The built frontend is embedded so the operator
// downloads one executable and runs it — no Node, no dist/ folder to keep
// beside the binary and lose. The release workflow copies dist/ to
// backend/webdist/ before building with `-tags embed`; the default build
// (dev, `go run`, `go test`, `go build` with no tag) uses web_noembed.go and
// serves the API only, with Vite serving the UI in development.
package main

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
)

//go:embed all:webdist
var webdist embed.FS

// mountWeb serves the embedded frontend. It is registered after the API routes
// in main, so POST /api/* and GET /healthz win and everything else falls
// through here. The frontend calls the API at a relative /api, so being served
// from the same origin means there is no proxy and no CORS to configure — the
// single binary is self-contained.
func mountWeb(app *fiber.App) {
	sub, err := fs.Sub(webdist, "webdist")
	if err != nil {
		return
	}
	app.Use("/", filesystem.New(filesystem.Config{
		Root:  http.FS(sub),
		Index: "index.html",
		// The dashboard is a single-page app: /dashboard has no server route,
		// so an unmatched path serves index.html and the client router takes
		// over rather than 404-ing.
		NotFoundFile: "index.html",
	}))
}
