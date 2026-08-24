// Shapes the backend produces that the frontend contract (src/lib/types.ts)
// does not name.
//
// Most of the wire contract lives in src/lib/types.ts, shared with the React
// app so a field rename cannot drift between the two. These are the leftovers:
// values the API still serialises but no screen reads by name, and values that
// never leave the process at all. Go kept them in the same types package as
// everything else; here they stay out of the shared file so the frontend's
// contract is exactly what the frontend uses.

import type {
  AssembledRule,
  Confidence,
  CredentialCheck,
  CredentialsView,
  MetricsPanel,
  RuleTestResult,
  Status,
} from "../../src/lib/types.ts";

/** One row of the incident timeline. Serialised inside the metrics panel. */
export interface TimelineEntry {
  ts: string;
  source: string;
  severity: Status;
  text: string;
}

/** What the correlator concluded from a set of anomalies. */
export interface CorrelationResult {
  category: string;
  reason: string;
  evidence: string[];
  confidence: Confidence;
}

/**
 * The metrics panel as the backend builds it. The two extra fields are still
 * serialised — the incident report reads them back out of the cache — but no
 * screen renders them, so the shared contract does not name them.
 */
export interface MetricsPanelFull extends MetricsPanel {
  correlations: CorrelationResult[];
  timeline: TimelineEntry[];
}

/**
 * The assembled rule as the backend builds it. sandboxRuleJson is the same rule
 * with the real regex-set names in place of the ARN placeholders — the sandbox
 * evaluates it locally, so it needs the names the console form does not accept.
 */
export interface AssembledRuleFull extends AssembledRule {
  sandboxRuleJson: string;
}

/**
 * The sandbox result as the backend builds it. The extra three summarise the
 * run for an operator; no screen renders them yet, so the shared contract does
 * not name them.
 */
export interface RuleTestResultFull extends RuleTestResult {
  /** Requests the evaluator could not decide — an unsupported statement. */
  unknown: number;
  verdict: string;
  notes: string[];
}

/** One rule as the WebACL lists it. Inlined in WafAclInfo on the wire. */
export interface WafAclRule {
  name: string;
  priority: number;
  action: string;
}

/**
 * What the apply/promote/demote/remove button gets back: the rule the WebACL
 * now holds (or no longer holds) and the history row the rollback and the
 * verification read from.
 */
export interface WafRuleUpdateResult {
  ruleName: string;
  historyId: number;
}

/**
 * The slice of a LookupEvents result the node-count reconstruction reads. Kept
 * here so the AWS layer and the arithmetic that consumes it do not have to
 * import one another.
 */
export interface CloudTrailEvent {
  name: string;
  tsMs: number;
  body: string;
}

/** The credentials screen's whole answer: what is in force, and whether it works. */
export interface CredentialsResult {
  view: CredentialsView;
  check: CredentialCheck;
}
