// Where the chart tooltip sits relative to the cursor.
//
// Kept out of TimeChart.tsx so the edge behaviour can be tested without a
// canvas: a tooltip that runs off the right edge of a narrow card is invisible
// exactly when the cursor is over the most recent samples, which is where it is
// read most.

export interface TipBox {
  x: number;
  y: number;
}

const GAP = 14;

// Right of the cursor by default; flipped to the left when it would overflow,
// and never pushed past the left edge — on a plot narrower than the tooltip
// the flip has nowhere to go, so it clamps rather than disappearing.
//
// Vertically the tooltip is centred on the cursor and clamped to the plot, so
// it stays over the chart instead of the axis labels below it.
export function tipPosition(
  cursorX: number,
  cursorY: number,
  tipW: number,
  tipH: number,
  overW: number,
  overH: number,
): TipBox {
  const fits = cursorX + GAP + tipW <= overW;
  const x = fits ? cursorX + GAP : Math.max(cursorX - GAP - tipW, 0);
  const y = Math.min(Math.max(cursorY - tipH / 2, 0), Math.max(overH - tipH, 0));
  return { x: Math.round(x), y: Math.round(y) };
}
