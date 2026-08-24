import assert from "node:assert/strict";
import test from "node:test";

import {
  allowedInstanceType,
  offSpec,
  parseMatchStart,
  parseTrailEvents,
  project,
  reconstruct,
  timeWeightedAvg,
  type Sample,
  type TrailDelta,
} from "./nodecost.ts";
import type { InstanceRow, ScoringWindow } from "../../src/lib/types.ts";

test("parseMatchStart takes what a person types under time pressure", () => {
  const now = new Date(2026, 7, 14, 11, 30, 0, 0).getTime();
  const want = new Date(2026, 7, 14, 9, 0, 0, 0).getTime();

  assert.equal(parseMatchStart("09:00", now), want, "bare hh:mm");
  assert.equal(parseMatchStart("2026-08-14 09:00", now), want, "date + time");
  assert.equal(parseMatchStart("2026-08-14T09:00", now), want, "T form");
  assert.equal(parseMatchStart("", now), null, "empty should not parse");
  assert.equal(parseMatchStart("어제", now), null, "garbage should not parse");
});

test("timeWeightedAvg averages the step function, not the samples", () => {
  // A value holds until the next reading replaces it: 10 minutes at 2 then
  // 10 minutes at 4 averages 3 regardless of how many samples repeat each.
  const samples: Sample[] = [
    { t: 0, v: 2 },
    { t: 600_000, v: 4 },
  ];
  assert.equal(timeWeightedAvg(samples, 0, 1_200_000), 3);

  // The value in effect when the window opens is the last reading at or before
  // it, not the first inside it.
  assert.equal(timeWeightedAvg(samples, 300_000, 900_000), 3);

  assert.equal(timeWeightedAvg([], 0, 600_000), null, "no samples should be null");
  assert.equal(timeWeightedAvg(samples, 600_000, 600_000), null, "zero-length window");
});

test("project holds the current count to the end of the window", () => {
  const win: ScoringWindow = { startMs: 0, endMs: 2 * 3_600_000 };
  const samples: Sample[] = [{ t: 0, v: 4 }];
  // Halfway through at 4, dropping to 2 now: final = (4×1h + 2×1h) / 2h = 3.
  const p = project(samples, 2, win, 3_600_000);
  assert.equal(p.finalAvg, 3);
  assert.equal(p.marginalPerInstance, 0.5);
  assert.equal(p.elapsedMin, 60);
  assert.equal(p.remainingMin, 60);
});

test("reconstruct walks the count backwards from now", () => {
  // Current count 3, a RunInstances(+2) at t=200, a Terminate(-1) at t=400:
  // after 400 → 3; before 400 → 4; before 200 → 2.
  const deltas: TrailDelta[] = [
    { t: 200, delta: 2 },
    { t: 400, delta: -1 },
  ];
  assert.deepEqual(reconstruct(deltas, 3, 0, 1000), [
    { t: 0, v: 2 },
    { t: 200, v: 4 },
    { t: 400, v: 3 },
    { t: 1000, v: 3 },
  ]);
});

test("parseTrailEvents turns the event stream into count deltas", () => {
  const got = parseTrailEvents([
    // One RunInstances launching two instances is one +2 delta.
    {
      name: "RunInstances",
      tsMs: 100,
      body: `{"responseElements":{"instancesSet":{"items":[{},{}]}}}`,
    },
    { name: "TerminateInstances", tsMs: 200, body: "{}" },
    // A malformed body still counts one instance.
    { name: "RunInstances", tsMs: 300, body: "not json" },
    // Unrelated events are dropped.
    { name: "StopInstances", tsMs: 400, body: "{}" },
  ]);
  assert.deepEqual(got, [
    { t: 100, delta: 2 },
    { t: 200, delta: -1 },
    { t: 300, delta: 1 },
  ]);
});

test("offSpec reports facts, one reason per instance", () => {
  const allowed = allowedInstanceType();
  const row = (
    id: string,
    type: string,
    az: string,
    clusterTag: string | null,
  ): InstanceRow => ({ id, type, az, name: null, clusterTag, launchedMs: null });
  const rows: InstanceRow[] = [
    row("i-ok", allowed, "ap-northeast-2a", "owned"),
    row("i-type", "m5.large", "ap-northeast-2a", "owned"),
    row("i-region", allowed, "us-east-1a", "owned"),
    row("i-stray", allowed, "ap-northeast-2a", null),
  ];
  const got = offSpec(rows, "ap-northeast-2");
  assert.equal(got.length, 3, JSON.stringify(got));
  assert.equal(got[0]!.id, "i-type");
  assert.equal(got[0]!.reason, "타입 m5.large");
  assert.equal(got[1]!.id, "i-region");
  assert.equal(got[1]!.reason, "리전 us-east-1a");
  assert.equal(got[2]!.id, "i-stray");
  assert.equal(got[2]!.reason, "클러스터에 속하지 않음");
});
