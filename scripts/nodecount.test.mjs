// The cost panel's whole value is the arithmetic: a plain mean of samples is
// wrong whenever the poll interval is uneven, and the backfill walks the count
// backwards from the present, which is easy to get off by one event.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const {
  parseMatchStart,
  scoringWindow,
  timeWeightedAvg,
  project,
  offSpec,
  parseTrailEvents,
  reconstruct,
} = await import(`${SRC}nodecount.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const MIN = 60_000;

// --- match start -----------------------------------------------------------

const noon = new Date(2026, 7, 14, 12, 0, 0, 0).getTime();
check("bare HH:MM means today", parseMatchStart("09:00", noon), new Date(2026, 7, 14, 9, 0).getTime());
check(
  "full local timestamp",
  parseMatchStart("2026-08-14 09:00", noon),
  new Date(2026, 7, 14, 9, 0).getTime(),
);
check("empty is not a time", parseMatchStart("   ", noon), null);
check("garbage is not a time", parseMatchStart("나중에", noon), null);

const start = new Date(2026, 7, 14, 9, 0).getTime();
check("window opens at +1h and runs 2h", scoringWindow(start), {
  startMs: start + 60 * MIN,
  endMs: start + 180 * MIN,
});

// --- time-weighted average -------------------------------------------------

// Two nodes for the first minute, six for the second. A plain mean of the two
// samples also gives 4 here; the next case is the one that separates them.
check(
  "weights by duration, not by sample count",
  timeWeightedAvg(
    [
      { t: 0, v: 2 },
      { t: 60_000, v: 6 },
    ],
    0,
    120_000,
  ),
  4,
);

// Three samples at 6 in the first minute must not outvote one sample at 2 that
// held for nine.
check(
  "dense samples do not outweigh a long stretch",
  timeWeightedAvg(
    [
      { t: 0, v: 6 },
      { t: 20_000, v: 6 },
      { t: 40_000, v: 6 },
      { t: 60_000, v: 2 },
    ],
    0,
    600_000,
  ),
  (6 * 60_000 + 2 * 540_000) / 600_000,
);

check(
  "the value in effect at the window open is the last one before it",
  timeWeightedAvg([{ t: -10_000, v: 3 }], 0, 100_000),
  3,
);
check("no samples means no average", timeWeightedAvg([], 0, 100_000), null);
check("an empty window has no average", timeWeightedAvg([{ t: 0, v: 3 }], 5, 5), null);

// --- projection ------------------------------------------------------------

const win = scoringWindow(start);
const flat = [{ t: win.startMs, v: 4 }];

const mid = project(flat, 4, win, win.startMs + 72 * MIN);
check("held steady, the final average is the current count", mid.finalAvg, 4);
check("one instance moves the final average by the remaining fraction", mid.marginalPerInstance, 0.4);
check("elapsed and remaining are reported in minutes", [mid.elapsedMin, mid.remainingMin], [72, 48]);

// Four nodes for the first hour, eight from now on: half the window at each.
const jumped = project(flat, 8, win, win.startMs + 60 * MIN);
check("scaling up now lands the average between the two counts", jumped.finalAvg, 6);

const early = project([], null, win, win.startMs - 30 * MIN);
check("before the window opens nothing has elapsed", early.elapsedMin, 0);
check("a full-window marginal effect is 1", early.marginalPerInstance, 1);

const late = project(flat, 4, win, win.endMs + 30 * MIN);
check("after the window closes nothing remains", late.remainingMin, 0);
check("and one more instance no longer moves the score", late.marginalPerInstance, 0);

// --- off-spec --------------------------------------------------------------

const ok = {
  id: "i-ok",
  type: "t3.medium",
  az: "ap-northeast-2a",
  name: "node",
  clusterTag: "owned",
  launchedMs: null,
};
check("an allowed node in the right region is not off-spec", offSpec([ok], "ap-northeast-2"), []);
check(
  "a wrong type is off-spec",
  offSpec([{ ...ok, id: "i-big", type: "t3.large" }], "ap-northeast-2").map((r) => r.reason),
  ["타입 t3.large"],
);
check(
  "a wrong region is off-spec",
  offSpec([{ ...ok, id: "i-far", az: "us-east-1a" }], "ap-northeast-2").map((r) => r.reason),
  ["리전 us-east-1a"],
);
check(
  "an instance outside the cluster is off-spec",
  offSpec([{ ...ok, id: "i-idle", clusterTag: null }], "ap-northeast-2").map((r) => r.reason),
  ["클러스터에 속하지 않음"],
);
check(
  "reasons accumulate",
  offSpec([{ ...ok, id: "i-bad", type: "m5.large", clusterTag: null }], "ap-northeast-2").map(
    (r) => r.reason,
  ),
  ["타입 m5.large · 클러스터에 속하지 않음"],
);

// --- CloudTrail backfill ---------------------------------------------------

const runOf = (tMs, n) => ({
  EventName: "RunInstances",
  EventTime: new Date(tMs),
  CloudTrailEvent: JSON.stringify({
    responseElements: { instancesSet: { items: Array.from({ length: n }, () => ({})) } },
  }),
});
const termOf = (tMs, n) => ({ ...runOf(tMs, n), EventName: "TerminateInstances" });

check(
  "one RunInstances can launch several instances",
  parseTrailEvents([runOf(1000, 3)]),
  [{ t: 1000, delta: 3 }],
);
check("a terminate is a negative delta", parseTrailEvents([termOf(1000, 2)]), [
  { t: 1000, delta: -2 },
]);
check(
  "an unparseable body still counts as one instance",
  parseTrailEvents([{ EventName: "RunInstances", EventTime: new Date(5), CloudTrailEvent: "{" }]),
  [{ t: 5, delta: 1 }],
);
check("unrelated events are ignored", parseTrailEvents([{ EventName: "DescribeInstances", EventTime: new Date(1) }]), []);

// Four now; two were launched halfway; so it was two before that.
check(
  "the count is walked backwards from the present",
  reconstruct([{ t: 500, delta: 2 }], 4, 0, 1000),
  [
    { t: 0, v: 2 },
    { t: 500, v: 4 },
    { t: 1000, v: 4 },
  ],
);

// A terminate walked backwards means there were MORE before, not fewer — the
// sign is the easy thing to get inverted here.
check(
  "a terminate means the count was higher before it",
  reconstruct([{ t: 500, delta: -1 }], 3, 0, 1000),
  [
    { t: 0, v: 4 },
    { t: 500, v: 3 },
    { t: 1000, v: 3 },
  ],
);

check(
  "events outside the window are ignored",
  reconstruct([{ t: -100, delta: 5 }], 4, 0, 1000),
  [
    { t: 0, v: 4 },
    { t: 1000, v: 4 },
  ],
);

check(
  "a disagreeing trail cannot produce negative nodes",
  reconstruct([{ t: 500, delta: 9 }], 1, 0, 1000).map((s) => s.v),
  [0, 1, 1],
);

// The reconstruction has to feed the average correctly, which is the only
// reason it exists.
check(
  "backfilled samples average as a step function",
  timeWeightedAvg(reconstruct([{ t: 500, delta: 2 }], 4, 0, 1000), 0, 1000),
  3,
);

console.log(failures === 0 ? "\nall passed" : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
