import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadDotenv, parseEnv } from "./dotenv.ts";

test("parseEnv reads the shapes .env.example uses", () => {
  const pairs = parseEnv(
    [
      "# a comment",
      "",
      "AWS_REGION=ap-northeast-2",
      "export WAF_SCOPE=CLOUDFRONT",
      "  APP_LOG_GROUP = /aws/eks/app  ",
      "API_ADDR=127.0.0.1:8787 # where it listens",
      'CORS_ALLOW_ORIGINS="http://localhost:3100,http://127.0.0.1:3100"',
      "SINGLE='literal $not expanded'",
      "EMPTY=",
      "COMMENTED=  # 값 없이 메모만",
    ].join("\n"),
  );

  assert.equal(pairs.AWS_REGION, "ap-northeast-2");
  assert.equal(pairs.WAF_SCOPE, "CLOUDFRONT");
  assert.equal(pairs.APP_LOG_GROUP, "/aws/eks/app");
  assert.equal(pairs.API_ADDR, "127.0.0.1:8787");
  assert.equal(pairs.CORS_ALLOW_ORIGINS, "http://localhost:3100,http://127.0.0.1:3100");
  assert.equal(pairs.SINGLE, "literal $not expanded");
  assert.equal(pairs.EMPTY, "");
  assert.equal(pairs.COMMENTED, "");
});

test("parseEnv keeps a # that is part of a value and skips junk lines", () => {
  const pairs = parseEnv(["URL=http://h/p#frag", "not a pair", "=novalue", "1BAD=x", "OK=1"].join("\n"));
  assert.equal(pairs.URL, "http://h/p#frag");
  assert.equal(pairs.OK, "1");
  assert.equal(Object.keys(pairs).length, 2);
});

test("parseEnv strips a UTF-8 BOM from the first key", () => {
  assert.equal(parseEnv("﻿AWS_REGION=ap-northeast-2").AWS_REGION, "ap-northeast-2");
});

test("loadDotenv never overwrites the real environment, and skips blanks", () => {
  const dir = mkdtempSync(join(tmpdir(), "dotenv-"));
  const file = join(dir, ".env");
  writeFileSync(file, ["DOTENV_T_NEW=fromfile", "DOTENV_T_SET=fromfile", "DOTENV_T_BLANK="].join("\n"));

  process.env.DOTENV_T_SET = "fromenv";
  delete process.env.DOTENV_T_NEW;
  delete process.env.DOTENV_T_BLANK;
  try {
    const res = loadDotenv(file);
    assert.equal(res.path, file);
    assert.equal(process.env.DOTENV_T_NEW, "fromfile");
    assert.equal(process.env.DOTENV_T_SET, "fromenv");
    assert.equal(process.env.DOTENV_T_BLANK, undefined);
    assert.ok(res.applied.includes("DOTENV_T_NEW"));
    assert.ok(res.skipped.includes("DOTENV_T_SET"));
  } finally {
    delete process.env.DOTENV_T_NEW;
    delete process.env.DOTENV_T_SET;
  }
});

test("loadDotenv treats a missing file as normal", () => {
  const res = loadDotenv(join(mkdtempSync(join(tmpdir(), "dotenv-")), "nope.env"));
  // Falls through to the repository's own .env, which usually does not exist
  // either; either way it must not throw and must report honestly.
  assert.ok(res.path === null || res.path.endsWith(".env"));
});
