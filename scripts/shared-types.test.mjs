import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const types = await readFile(new URL("../src/lib/types.ts", import.meta.url), "utf8");

for (const name of ["CountEvidence", "NodeCountProjection", "CountMatch", "OffSpecInstance"]) {
  assert.match(types, new RegExp(`export (?:interface|type) ${name}\\b`));
}

console.log("shared type contracts: ok");
