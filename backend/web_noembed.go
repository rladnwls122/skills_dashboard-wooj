//go:build !embed

// Default build: the API only. Vite serves the frontend in development, and a
// release build (`-tags embed`, see web_embed.go) serves it from the binary.
// This no-op keeps `go run` / `go test` / `go build` working without a built
// frontend present on disk.
package main

import "github.com/gofiber/fiber/v2"

func mountWeb(_ *fiber.App) {}
