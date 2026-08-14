# Vite SPA and Fiber API Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the existing dashboard as a Vite React SPA that retrieves data from the existing Go Fiber API without importing Next server modules into the browser bundle.

**Architecture:** Cherry-pick the preserved Vite scaffold onto the current backend branch. Keep `DashboardClient` and its UI components intact, route browser requests through `src/lib/api/dashboard.ts`, and keep all cross-boundary types in `src/lib/types.ts`. Vite proxies same-origin `/api` traffic to Fiber during development; deployments may set `VITE_API_BASE_URL`.

**Tech Stack:** Vite, React 19, TypeScript, Tailwind CSS, Go Fiber, SQLite.

**Spec:** `docs/superpowers/specs/2026-08-15-vite-fiber-migration-design.md`

## Global Constraints

- Preserve the existing dashboard UI components and CSS.
- Do not rewrite the existing Go provider or AWS/Kubernetes integration.
- Do not execute WAF rule updates or any cloud-mutating operation during validation.
- Browser-reachable modules must not import `src/app/actions/**` or `src/lib/server/**`.
- API transport uses `VITE_API_BASE_URL` when supplied, otherwise same-origin `/api`.

---

### Task 1: Apply and verify the Vite scaffold

**Files:**
- Create: `index.html`, `src/main.tsx`, `src/vite-env.d.ts`, `vite.config.ts`
- Modify: `package.json`, `pnpm-lock.yaml`, `tsconfig.json`, `.env.example`, `.gitignore`, `README.md`

**Interfaces:**
- Produces: Vite entry point at `src/main.tsx`, output directory `dist`, development proxy from `/api` to `http://127.0.0.1:8787`.
- Consumes: existing `src/app/dashboard/ui/DashboardClient.tsx` and `src/app/globals.css`.

- [ ] **Step 1: Apply the preserved scaffold commit**

Run: `git cherry-pick 3d46db6`

Expected: Git applies the seven Vite scaffold files. If a conflict occurs, preserve current Go-related files and use the Vite version only for package scripts, TypeScript/Vite configuration, and entry files.

- [ ] **Step 2: Add environment documentation**

Add this line to `.env.example` and the Vite run section in `README.md`:

```dotenv
# Optional absolute origin for Fiber; omit in development to use Vite's /api proxy.
VITE_API_BASE_URL=http://127.0.0.1:8787
```

- [ ] **Step 3: Verify the scaffold compiles far enough to find import boundaries**

Run: `pnpm typecheck`

Expected: it may fail on remaining server imports, but must recognize Vite's `import.meta.env` declarations rather than fail because the Vite configuration is missing.

- [ ] **Step 4: Commit the scaffold integration**

```bash
git add index.html src/main.tsx src/vite-env.d.ts vite.config.ts package.json pnpm-lock.yaml tsconfig.json .env.example .gitignore README.md
git commit -m "build: migrate dashboard entry point to Vite"
```

### Task 2: Move UI-shared contracts out of server modules

**Files:**
- Modify: `src/lib/types.ts`, `src/app/dashboard/ui/AiTab.tsx`, `src/app/dashboard/ui/NodeCostPanel.tsx`
- Test: `scripts/shared-types.test.mjs`

**Interfaces:**
- Produces: `CountVerdict`, `CountMatch`, `CountEvidence`, `NodeSample`, `ScoringWindow`, `InstanceRow`, `OffSpecInstance`, and `NodeCountProjection` exported by `@/lib/types`.
- Consumes: existing type-only shapes from `src/lib/server/wafcountevidence.ts` and `src/lib/server/nodecount.ts`.

- [ ] **Step 1: Write the failing type-contract test**

Create `scripts/shared-types.test.mjs` using the project TypeScript loader. The test must read `src/lib/types.ts` and assert each of these exported declarations exists: `CountEvidence`, `NodeCountProjection`, `CountMatch`, `OffSpecInstance`.

```js
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const types = await readFile(new URL("../src/lib/types.ts", import.meta.url), "utf8");
for (const name of ["CountEvidence", "NodeCountProjection", "CountMatch", "OffSpecInstance"]) {
  assert.match(types, new RegExp(`export (?:interface|type) ${name}\\b`));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node scripts/shared-types.test.mjs`

Expected: FAIL because the Count and node projection types are only declared under `src/lib/server/`.

- [ ] **Step 3: Add identical shared type declarations and change UI type imports**

Append the shared definitions to `src/lib/types.ts`. Change the two UI imports to:

```ts
import type { CountEvidence } from "@/lib/types";
import type { NodeCountProjection } from "@/lib/types";
```

Do not import a browser module from `src/lib/server/`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `node scripts/shared-types.test.mjs`

Expected: PASS.

- [ ] **Step 5: Commit the contract move**

```bash
git add src/lib/types.ts src/app/dashboard/ui/AiTab.tsx src/app/dashboard/ui/NodeCostPanel.tsx scripts/shared-types.test.mjs
git commit -m "refactor: share dashboard API contracts"
```

### Task 3: Complete the Vite-safe HTTP client and migrate UI imports

**Files:**
- Modify: `src/lib/api/dashboard.ts`, `src/app/dashboard/ui/DashboardClient.tsx`, `src/app/dashboard/ui/AiTab.tsx`, `src/app/dashboard/ui/CredentialsCard.tsx`, `src/app/dashboard/ui/NodeCostPanel.tsx`, `src/app/dashboard/ui/RequestLogPanel.tsx`, `src/app/dashboard/ui/TrafficTab.tsx`, `src/app/dashboard/ui/WafLogPanel.tsx`
- Test: `scripts/dashboard-api-contract.test.mjs`

**Interfaces:**
- Produces: action-shaped browser functions that use `const BASE = API_ORIGIN ? `${API_ORIGIN}/api` : "/api"` and return `Promise<ActionResult<T>>`.
- Consumes: Fiber `POST /api/*` handlers in `backend/internal/api/api.go`.

- [ ] **Step 1: Write the failing client-boundary test**

Create `scripts/dashboard-api-contract.test.mjs` to read the client and UI source. Assert that `dashboard.ts` contains `import.meta.env.VITE_API_BASE_URL`, and every named UI file above lacks `@/app/actions/dashboard` and `@/lib/server/`.

```js
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const api = await readFile(new URL("../src/lib/api/dashboard.ts", import.meta.url), "utf8");
assert.match(api, /import\.meta\.env\.VITE_API_BASE_URL/);
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node scripts/dashboard-api-contract.test.mjs`

Expected: FAIL because the existing client uses `process.env.NEXT_PUBLIC_API_BASE_URL` and UI files import server actions.

- [ ] **Step 3: Implement the smallest route-aligned browser client change**

Replace the API origin calculation with:

```ts
const API_ORIGIN = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");
const BASE = API_ORIGIN ? `${API_ORIGIN}/api` : "/api";
```

Use `fetch(`${BASE}${path}`, ...)`. Move all `dashboard.ts` imports to its import block and add wrappers only for Fiber routes that exist. Replace each listed UI's server-action import with `@/lib/api/dashboard`.

- [ ] **Step 4: Compare every client export to Fiber before adding wrappers**

Run: `rg -n 'export (async )?function|api\.Post' src/lib/api/dashboard.ts backend/internal/api/api.go`

Expected: every client function resolves to exactly one `api.Post` path. For a missing handler, either add the handler only when the existing service already exposes the operation or remove the unused UI call; do not emulate provider behavior in the client.

- [ ] **Step 5: Run the boundary test to verify it passes**

Run: `node scripts/dashboard-api-contract.test.mjs`

Expected: PASS.

- [ ] **Step 6: Commit the browser boundary**

```bash
git add src/lib/api/dashboard.ts src/app/dashboard/ui scripts/dashboard-api-contract.test.mjs
git commit -m "refactor: route dashboard UI through Fiber API"
```

### Task 4: Validate compile, build, and Go API contract

**Files:**
- Modify only if validation exposes a contract or build error: files identified by the compiler or Go tests.

**Interfaces:**
- Consumes: Vite entry and the Fiber routes.
- Produces: Vite `dist/` build and passing Go test suite.

- [ ] **Step 1: Run TypeScript checking**

Run: `pnpm typecheck`

Expected: exit 0 with no TypeScript errors.

- [ ] **Step 2: Run production bundle validation**

Run: `pnpm build`

Expected: exit 0 and a generated `dist/` directory. The output must not report a `server-only` resolution error.

- [ ] **Step 3: Run Go tests**

Run: `cd backend; go test ./...`

Expected: exit 0 for all backend packages.

- [ ] **Step 4: Inspect the completed boundary and commit any fix**

Run: `rg -n 'from ["'']@/app/actions/dashboard|from ["'']@/lib/server' src/main.tsx src/lib/api src/app/dashboard/ui`

Expected: no matches. If validation required edits, commit only those edits with a focused message such as `fix: resolve Vite client bundle boundary`.
