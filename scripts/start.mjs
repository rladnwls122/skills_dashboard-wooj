// Launcher for `pnpm dev` / `pnpm start`, with an optional port so a second
// instance can run next to the first:
//
//   pnpm start              # UI 3100, API 8787, db ./data/dashboard.db
//   pnpm start -p 3110      # UI 3110, API 8797, db ./data/dashboard-3110.db
//   pnpm dev -p 3111        # same idea against the dev servers
//
// Why this file exists: `pnpm start -p 3110` used to forward `-p 3110` into
// concurrently, where -p is the prefix option — a non-string prefix then
// crashes its logger (`prev.replace is not a function`). The port has to be
// consumed here, before concurrently ever sees argv.
//
// One flag drives three settings, each still overridable by environment:
//   PORT              frontend port (vite.config.ts reads it)
//   API_ADDR          backend listen address; port offset mirrors 3100→8787
//   API_PROXY_TARGET  where vite proxies /api — must point at API_ADDR
//   DB_PATH           per-port SQLite off the default port, because two
//                     backends writing one SQLite file fight over the lock
//                     and share settings/credentials in surprising ways.

import { spawn } from "node:child_process";

import { loadDotenv } from "../backend/config/dotenv.ts";

// The launcher decides PORT / API_ADDR / DB_PATH before the backend starts, so
// it has to see .env too — otherwise a port pinned in the file would apply to
// the backend and not to the frontend proxy pointing at it.
const dotenv = loadDotenv();

const args = process.argv.slice(2);
const dev = args.includes("--dev");

let port = Number(process.env.PORT ?? 3100);
for (let i = 0; i < args.length; i++) {
  if (args[i] === "-p" || args[i] === "--port") port = Number(args[i + 1]);
}
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error(`올바르지 않은 포트: ${port} — 예: pnpm start -p 3110`);
  process.exit(1);
}

// 3100 → 8787, 3110 → 8797, 3111 → 8798 — deterministic, no second flag.
const apiPort = port + 8787 - 3100;

const env = {
  ...process.env,
  PORT: String(port),
  API_ADDR: process.env.API_ADDR ?? `127.0.0.1:${apiPort}`,
  API_PROXY_TARGET: process.env.API_PROXY_TARGET ?? `http://127.0.0.1:${apiPort}`,
  DB_PATH:
    process.env.DB_PATH ??
    (port === 3100 ? "./data/dashboard.db" : `./data/dashboard-${port}.db`),
};

// Direct commands rather than `pnpm <script>`: the extra pnpm→cmd layer is
// what turned the backend spawn into a bare "Access is denied." on Windows.
// PATH already carries node_modules/.bin because pnpm launched this file.
//
// The backend is TypeScript run straight by Node — v24 strips the types at
// load, so there is no build step and no binary to spawn. --watch restarts it
// on a source change in dev, which is what `go run` never did.
const backend = dev ? "node --watch backend/main.ts" : "node backend/main.ts";
const frontend = dev ? "vite" : "vite preview";
const command =
  `concurrently -k -p "[{name}]" -n "BACKEND,FRONTEND" -c "cyan,magenta" ` +
  `"${backend}" "${frontend}"`;

if (dotenv.path) console.log(`[start] env ${dotenv.path}`);
console.log(`[start] UI http://127.0.0.1:${port}/dashboard · API ${env.API_ADDR} · DB ${env.DB_PATH}`);

const child = spawn(command, { stdio: "inherit", shell: true, env });
child.on("exit", (code) => process.exit(code ?? 0));
