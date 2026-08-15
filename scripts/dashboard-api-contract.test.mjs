import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const api = await readFile(join(root, "src/lib/api/dashboard.ts"), "utf8");
assert.match(api, /import\.meta\.env\.VITE_API_BASE_URL/);
assert.match(api, /fetch\(`\$\{BASE\}\/api\$\{path\}/);

const uiDir = join(root, "src/app/dashboard/ui");
const uiFiles = (await readdir(uiDir)).filter((name) => /\.(ts|tsx)$/.test(name));
for (const name of uiFiles) {
  const source = await readFile(join(uiDir, name), "utf8");
  assert.doesNotMatch(source, /@\/app\/actions\/dashboard/);
  assert.doesNotMatch(source, /@\/lib\/server\//);
}

console.log("dashboard browser boundary: ok");
