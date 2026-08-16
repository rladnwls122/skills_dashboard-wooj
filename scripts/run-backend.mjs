// Runs the built Go backend, building it first when the binary is missing.
// Was an inline `node -e` blob in package.json; as a file it survives the
// Windows cmd/pnpm quoting layers that the inline form tripped over
// ("Access is denied." before the process ever started), and it can report a
// spawn failure instead of dying silently.

import { existsSync } from "node:fs";
import { execSync, spawn } from "node:child_process";

const exe = process.platform === "win32" ? "./api.exe" : "./api";
if (!existsSync(exe)) {
  execSync("pnpm build:backend", { stdio: "inherit" });
}

const child = spawn(exe, [], { stdio: "inherit" });
child.on("error", (e) => {
  console.error(`백엔드 실행 실패 (${exe}): ${e.message}`);
  process.exit(1);
});
child.on("exit", (code) => process.exit(code ?? 0));
