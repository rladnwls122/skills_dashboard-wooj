import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import { Settings, SPECS } from "../config/config.ts";
import { Store } from "../store/store.ts";
import { defaultTestRequests, maliciousExampleRequests } from "./sandbox.ts";
import { Service } from "./service.ts";
import { resolveWindow } from "./window.ts";
import type { NodeResourceUsage, PodResourceUsage } from "../../src/lib/types.ts";

function newTestService(t: TestContext): Service {
  const dir = mkdtempSync(join(tmpdir(), "dash-svc-"));
  const store = Store.open(join(dir, "test.db"));
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  // No provider: every cluster-touching capability answers with a stated
  // failure, which is what these tests want to see.
  return new Service(store, new Settings(store), null);
}

test("an invalid window selection is corrected, not rejected", () => {
  // An unknown span falls back to the default rather than being rejected: a
  // stale bookmark should still render.
  const got = resolveWindow({ windowMin: 7, intervalMin: 3 }, 1_700_000_123_456);
  assert.equal(got.windowMin, 60);
  assert.equal(got.intervalMin, 1);
  // The end is floored to an interval boundary, so the last bucket is complete.
  assert.equal(got.endMs % 60_000, 0);
  assert.equal(got.endMs - got.startMs, 60 * 60_000);
  assert.equal(got.buckets, 60);

  // An interval that is not on the offered list falls back to the smallest one
  // that yields a readable bucket count for the span.
  const wide = resolveWindow({ windowMin: 240, intervalMin: 2 }, 1_700_000_123_456);
  assert.equal(wide.intervalMin, 1);
  assert.equal(wide.buckets, 240);

  // 15m has no 60m interval — that would be a single bucket.
  const narrow = resolveWindow({ windowMin: 15, intervalMin: 60 }, 1_700_000_123_456);
  assert.equal(narrow.intervalMin, 1);
  assert.equal(narrow.buckets, 15);
});

test("a patch is rejected before the cluster is touched", (t) => {
  const svc = newTestService(t);
  const cases: [string, Parameters<Service["validate"]>[0]][] = [
    ["bad namespace", { namespace: "Default!", name: "api" }],
    ["other namespace", { namespace: "kube-system", name: "api" }],
    ["bad name", { namespace: "default", name: "API_1" }],
    ["replicas over max", { namespace: "default", name: "api", replicas: 999 }],
  ];
  for (const [name, req] of cases) {
    assert.throws(() => svc.validate(req), name);
  }
  svc.validate({ namespace: "default", name: "api", replicas: 3 });
});

test("verify waits for the rollout before judging", async (t) => {
  const svc = newTestService(t);
  const now = 1_700_000_000_000;
  svc.now = () => now;
  const id = svc.store.insertDeployHistory(
    "default",
    "api",
    "replicas=3",
    `{"trt":1,"c4xx":0,"c5xx":0,"restarts":0}`,
    now - 10_000,
  );

  const res = await svc.verify(id);
  assert.equal(res.verdict, "INCONCLUSIVE");
  assert.equal(res.details.length, 1);
  assert.ok(res.details[0]!.includes("재검증"), res.details[0]);

  // Past the delay, the comparison needs metrics — which this build cannot
  // read — so it must fail loudly rather than invent a verdict.
  svc.now = () => now + 5 * 60_000;
  await assert.rejects(svc.verify(id), "the unavailable provider must surface an error");
  await assert.rejects(svc.verify(id + 999), "an unknown history id must fail");
});

test("resourceHistory reads back what was recorded", (t) => {
  const svc = newTestService(t);
  // Inside the writer's 6h retention, else the sweep drops what we just wrote.
  const now = Date.now();
  svc.now = () => now;
  const pod = (name: string, cpuPct: number | null): PodResourceUsage => ({
    pod: name,
    containers: [],
    cpuUsageMilli: 0,
    memUsageBytes: 0,
    cpuPct,
    memPct: null,
  });
  const pods: PodResourceUsage[] = [pod("api-7d9", 55.55), pod("web-1", null)];
  const nodes: NodeResourceUsage[] = [
    {
      name: "ip-10-0-1-1",
      cpuUsageMilli: 0,
      memUsageBytes: 0,
      cpuCapacityMilli: 0,
      memCapacityBytes: 0,
      cpuPct: 12.3,
      memPct: 40,
    },
  ];
  // Two minutes back: the window's end is floored to an interval boundary, so a
  // reading taken this instant is not in it yet.
  svc.recordResourceSamples(pods, nodes, now - 2 * 60_000);

  const hist = svc.resourceHistory(null);
  assert.equal(hist.podCpu.length, 1);
  assert.equal(hist.podCpu[0]!.label, "api-7d9");
  assert.equal(hist.podCpu[0]!.points[0]!.v, 55.6, "one decimal");
  // A pod with no limit has no percentage; writing 0 would draw a floor that
  // reads as "idle" when it means "not measurable".
  assert.equal(hist.podMem.length, 0);
  assert.equal(hist.nodeCpu.length, 1);
  assert.equal(hist.nodeMem.length, 1);
});

test("a screen override beats the default and says where it came from", (t) => {
  const svc = newTestService(t);
  assert.equal(svc.settingsView().rows.length, SPECS.length);

  svc.saveSettings({ WAF_WEB_ACL_NAME: " other-acl ", NOT_A_SETTING: "x" });
  const view = svc.settingsView();
  const row = view.rows.find((r) => r.key === "WAF_WEB_ACL_NAME");
  assert.ok(row);
  assert.equal(row.value, "other-acl");
  assert.equal(row.source, "screen");
  assert.equal(row.defaultValue, "skills-waf");

  assert.ok(view.envText.includes("WAF_WEB_ACL_NAME=other-acl"), view.envText);
  assert.ok(!view.envText.includes("NOT_A_SETTING"), "unknown keys must be ignored");
});

test("the sandbox sets keep their labels", () => {
  const benign = defaultTestRequests();
  assert.ok(benign.length >= 3, "served paths plus loadgen and healthcheck");
  for (const r of benign) assert.ok(r.benign, r.id);
  for (const r of maliciousExampleRequests()) assert.ok(!r.benign, r.id);
});

test("probe refuses anything that is not http(s)", async (t) => {
  const svc = newTestService(t);
  for (const raw of ["", "file:///etc/passwd", "gopher://x"]) {
    await assert.rejects(svc.probe(raw, null), `${raw} should be rejected`);
  }
});

// The confirm screen used to run a weaker rule set than the apply behind it: no
// integer check on replicas and no quantity regexes at all. So "적용하시겠습니까?"
// was shown for a change the cluster was always going to refuse, and the
// operator found out after authorising it. Both paths now answer from
// Kube.validatePatchRequest, and this test is what says so.
test("the confirm screen refuses exactly what the apply would refuse", (t) => {
  const svc = newTestService(t);
  const rejected: [string, Parameters<Service["validate"]>[0]][] = [
    ["a fractional replica count", { namespace: "default", name: "api", replicas: 2.5 }],
    ["a non-finite replica count", { namespace: "default", name: "api", replicas: Number.NaN }],
    [
      "a CPU quantity Kubernetes cannot parse",
      { namespace: "default", name: "api", containerName: "api", cpuLimit: "500millicores" },
    ],
    [
      "a memory quantity Kubernetes cannot parse",
      { namespace: "default", name: "api", containerName: "api", memLimit: "256megs" },
    ],
    [
      "a resource change with no container named",
      { namespace: "default", name: "api", cpuLimit: "500m" },
    ],
  ];
  for (const [why, req] of rejected) {
    assert.throws(() => svc.validate(req), why);
    // previewPatch is the confirm screen's own call, and it must refuse before
    // it reads anything back.
    assert.throws(() => svc.previewPatch(req), `previewPatch: ${why}`);
  }

  // The shapes that are legal still pass, quantities included.
  svc.validate({ namespace: "default", name: "api", replicas: 0 });
  svc.validate({
    namespace: "default",
    name: "api",
    containerName: "api",
    cpuLimit: "500m",
    memLimit: "256Mi",
  });
  svc.validate({ namespace: "default", name: "api", containerName: "api", cpuLimit: "1.5" });
});
