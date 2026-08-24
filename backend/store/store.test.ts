import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import { Store } from "./store.ts";

function open(t: TestContext): Store {
  const dir = mkdtempSync(join(tmpdir(), "dash-store-"));
  const s = Store.open(join(dir, "test.db"));
  t.after(() => {
    s.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return s;
}

test("deploy history round-trips, and an unknown id is an answer", (t) => {
  const s = open(t);
  const id = s.insertDeployHistory("default", "api", "replicas=3", `{"trt":1}`, 1_700_000_000_000);

  const row = s.getDeployHistory(id);
  assert.ok(row);
  assert.equal(row.verdict, "PENDING");
  assert.equal(row.change, "replicas=3");

  s.updateDeployVerdict(id, "IMPROVED");
  const list = s.listDeployHistory();
  assert.equal(list.length, 1);
  assert.equal(list[0]!.verdict, "IMPROVED");

  assert.equal(s.getDeployHistory(id + 999), undefined);
});

test("an empty setting clears the override rather than storing a blank", (t) => {
  const s = open(t);
  s.saveSetting("AWS_REGION", "us-east-1", 1);
  assert.equal(s.loadSettings().AWS_REGION, "us-east-1");

  s.saveSetting("AWS_REGION", "", 2);
  assert.ok(!("AWS_REGION" in s.loadSettings()), "empty value must clear the override");
});

test("metric samples are idempotent per key and time", (t) => {
  const s = open(t);
  const key = "res:pod:cpu:api-7d9";
  // Inside the 6h retention the writer enforces — an older sample would be
  // swept by the same call that wrote it.
  const now = Date.now();
  s.saveMetricSamples(key, [{ t: now, v: 10 }]);
  s.saveMetricSamples(key, [{ t: now, v: 42 }]);

  const rows = s.loadMetricSamples(key, 0);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.v, 42);

  assert.deepEqual(s.listMetricKeys("res:", 0), [key]);
});

test("only a successful apply can be rolled back", (t) => {
  const s = open(t);
  s.insertWafHistory("r1", "APPLY", "SUCCESS", "ok", "[]", 1_700_000_000_000);
  s.insertWafHistory("r2", "ROLLBACK", "SUCCESS", "ok", "[]", 1_700_000_001_000);
  s.insertWafHistory("r3", "APPLY", "FAILED", "boom", "[]", 1_700_000_002_000);

  const rows = s.applyHistory();
  assert.equal(rows.length, 3);
  // Newest first: failed apply, rollback, successful apply.
  assert.deepEqual(
    rows.map((r) => r.canRollback),
    [false, false, true],
  );
});

// The retention sweep is a full table scan — the primary key is (key, t) and
// there is no index on t alone — and it used to run inside every single-series
// write. The kube panel writes two series per pod every three seconds, so the
// same SQLite file the settings and credential reads go through was being
// scanned dozens of times per poll. One transaction per poll, one sweep per
// minute.
test("a metric batch writes every series at once and sweeps at most once a minute", (t) => {
  const s = open(t);
  const now = Date.now();
  const expired = now - 7 * 3600_000;

  s.saveMetricSampleBatch([
    { key: "res:pod:cpu:api-1", points: [{ t: now, v: 1 }] },
    { key: "res:pod:cpu:api-2", points: [{ t: now, v: 2 }] },
    // Older than the 6h retention: written and swept by the same call, exactly
    // as the per-series writer did.
    { key: "res:pod:cpu:api-3", points: [{ t: expired, v: 3 }] },
  ]);
  assert.deepEqual(s.listMetricKeys("res:", 0), ["res:pod:cpu:api-1", "res:pod:cpu:api-2"]);
  assert.equal(s.loadMetricSamples("res:pod:cpu:api-1", 0)[0]!.v, 1);
  assert.equal(s.loadMetricSamples("res:pod:cpu:api-2", 0)[0]!.v, 2);

  // The second write of the same poll skips the sweep, so a row past retention
  // survives for up to a minute. That is the trade this throttle is: a stale row
  // nothing can query is cheaper than a full scan per series.
  s.saveMetricSampleBatch([{ key: "res:pod:cpu:api-4", points: [{ t: expired, v: 4 }] }]);
  assert.equal(s.loadMetricSamples("res:pod:cpu:api-4", 0).length, 1);

  // An empty poll is not a reason to open a transaction.
  s.saveMetricSampleBatch([]);
});
