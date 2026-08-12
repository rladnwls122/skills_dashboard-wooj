// The shared window's rules: only readable bucket counts are offered, the end
// lands on an interval boundary so no partial bucket enters, and bad input is
// corrected rather than thrown so a stale client still renders.
const SRC = new URL("../src/lib/server/", import.meta.url).href;
const { resolveWindow, validIntervals, windowKey, DEFAULT_WINDOW, WINDOW_CHOICES_MIN } =
  await import(`${SRC}window.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

// --- offered combinations (4..250 buckets, interval must divide the span) ---
check("15m offers only 1m", validIntervals(15), [1]);
check("30m offers 1m and 5m", validIntervals(30), [1, 5]);
check("1h offers 1m/5m/10m", validIntervals(60), [1, 5, 10]);
check("2h offers 1m/5m/10m", validIntervals(120), [1, 5, 10]);
check("4h adds 1h", validIntervals(240), [1, 5, 10, 60]);
for (const w of WINDOW_CHOICES_MIN) {
  const list = validIntervals(w);
  check(`${w}m offers at least one interval`, list.length > 0, true);
  check(
    `${w}m bucket counts stay in 4..250`,
    list.every((i) => w / i >= 4 && w / i <= 250),
    true,
  );
}

// --- the end is floored so every bucket is complete ---
const now = Date.UTC(2026, 7, 12, 13, 47, 31, 500);
const w10 = resolveWindow({ windowMin: 60, intervalMin: 10 }, now);
check("end floors to the interval boundary", new Date(w10.endMs).toISOString(), "2026-08-12T13:40:00.000Z");
check("start is exactly one span before the end", w10.endMs - w10.startMs, 60 * 60_000);
check("bucket count is span/interval", w10.buckets, 6);
check("no partial bucket can enter", w10.endMs % (10 * 60_000), 0);

const w1 = resolveWindow({ windowMin: 15, intervalMin: 1 }, now);
check("1m interval floors to the minute", new Date(w1.endMs).toISOString(), "2026-08-12T13:47:00.000Z");

// --- bad input is corrected, not thrown ---
check("unknown span falls back to the default", resolveWindow({ windowMin: 7, intervalMin: 1 }, now).windowMin, DEFAULT_WINDOW.windowMin);
check("interval that does not divide the span is corrected", resolveWindow({ windowMin: 15, intervalMin: 10 }, now).intervalMin, 1);
check("interval yielding too few buckets is corrected", resolveWindow({ windowMin: 60, intervalMin: 60 }, now).intervalMin, 1);
check("missing selection resolves to the default", resolveWindow(undefined, now).windowMin, DEFAULT_WINDOW.windowMin);
check("a corrected window is still valid", validIntervals(resolveWindow({ windowMin: 999, intervalMin: 999 }, now).windowMin).length > 0, true);

// --- the cache key follows the window ---
const a = resolveWindow({ windowMin: 60, intervalMin: 1 }, now);
const b = resolveWindow({ windowMin: 60, intervalMin: 5 }, now);
const c = resolveWindow({ windowMin: 120, intervalMin: 1 }, now);
check("different interval means a different key", windowKey(a) === windowKey(b), false);
check("different span means a different key", windowKey(a) === windowKey(c), false);
check("same window means the same key", windowKey(a), windowKey(resolveWindow({ windowMin: 60, intervalMin: 1 }, now)));
// Within one bucket the key holds, so panels refreshing seconds apart share a
// cache entry instead of each paying for its own scan.
check(
  "the key is stable inside a bucket",
  windowKey(a),
  windowKey(resolveWindow({ windowMin: 60, intervalMin: 1 }, now + 20_000)),
);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
