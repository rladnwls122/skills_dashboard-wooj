// The chart tooltip follows the cursor, so its position is recomputed on every
// mouse move and only the edges are interesting: the point of the tooltip is
// reading a value, and a tooltip drawn past the edge of the plot reads as no
// tooltip at all.
const SRC = new URL("../src/lib/", import.meta.url).href;
const { tipPosition } = await import(`${SRC}charttip.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

// 600x200 plot, 100x60 tooltip.
const at = (x, y) => tipPosition(x, y, 100, 60, 600, 200);

check("sits right of the cursor with room to spare", at(200, 100), { x: 214, y: 70 });
check("flips left near the right edge", at(500, 100), { x: 386, y: 70 });
// 486 + 14 + 100 is exactly the plot width, so that one still fits.
check("does not flip while the last pixel fits", at(486, 100), { x: 500, y: 70 });
check("flips as soon as it would overflow", at(487, 100), { x: 373, y: 70 });

// Vertical clamping keeps it over the plot area.
check("does not ride above the top", at(200, 5).y, 0);
check("does not fall below the bottom", at(200, 195).y, 140);

// A plot narrower than the tooltip has nowhere to flip to.
check("clamps to the left edge when neither side fits", tipPosition(60, 50, 200, 40, 150, 100), {
  x: 0,
  y: 30,
});

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
