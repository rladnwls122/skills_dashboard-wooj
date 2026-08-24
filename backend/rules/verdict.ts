// Three-valued logic for the rule evaluator. UNKNOWN means "this cannot be
// decided locally" and is never collapsed into a yes or no — a rule tester that
// guesses is worse than none.

export const VERDICT_FALSE = "FALSE";
export const VERDICT_TRUE = "TRUE";
export const VERDICT_UNKNOWN = "UNKNOWN";

export type Verdict3 = typeof VERDICT_FALSE | typeof VERDICT_TRUE | typeof VERDICT_UNKNOWN;

export function fromBool(b: boolean): Verdict3 {
  return b ? VERDICT_TRUE : VERDICT_FALSE;
}
