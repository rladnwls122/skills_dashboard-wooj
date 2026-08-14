# Vite SPA and Fiber API migration

## Goal

Keep the existing dashboard React UI and CSS while making the browser entry point a Vite React TypeScript SPA. Browser requests must use the Go Fiber API rather than Next.js server actions. Existing AWS and Kubernetes provider code in `backend/` remains in place and is not reimplemented.

## Integration approach

Apply commit `3d46db6` to the current backend-bearing branch. That commit supplies only the Vite entry point and toolchain configuration, so it must be integrated with the current branch rather than used as a replacement worktree.

`src/main.tsx` renders the existing `DashboardClient`; `vite.config.ts` provides the `@` alias and proxies `/api` to Fiber in development. `src/lib/api/dashboard.ts` becomes the sole browser data boundary, using `import.meta.env.VITE_API_BASE_URL` when set and same-origin `/api` otherwise.

## Module and contract boundaries

Dashboard UI files import only `src/lib/api/dashboard.ts` for action-shaped requests and `src/lib/types.ts` for shared types. They must not import `src/app/actions/**` or `src/lib/server/**`, because those modules use Next/server-only dependencies.

Types used both by the UI and API response layer, including WAF count-evidence and node-cost projections, live in `src/lib/types.ts`. The HTTP client request payloads and each Fiber route in `backend/internal/api/api.go` are compared route-for-route. Contract-only changes are made where needed; provider behavior and cloud-mutating WAF paths are not invoked during validation.

## Validation

Add tests first for new client transport behavior or route contract adaptations. Verify the client bundle has no server-only imports, then run `pnpm typecheck`, `pnpm build`, and `cd backend && go test ./...`. The build must emit `dist/`. No AWS, Kubernetes, or WAF mutation call is executed.

## Out of scope

Rewriting the existing Go backend, adding AWS SDK/client-go integrations beyond those already present, and production static-host SPA fallback configuration are excluded.
