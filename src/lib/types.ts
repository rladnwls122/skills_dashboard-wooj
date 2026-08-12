// Shared types. Safe to import from both server and client code.

export type Status = "NORMAL" | "WARNING" | "CRITICAL";
export type Confidence = "LOW" | "MEDIUM" | "HIGH";
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

export interface MetricPoint {
  t: string;
  v: number;
}

export interface MetricSummary {
  key: string;
  label: string;
  unit: string;
  current: number;
  previous: number;
  delta: number;
  percentChange: number | null;
  status: Status;
  points: MetricPoint[];
  // What `current` actually aggregated. The unit alone does not say it: a Sum
  // over three buckets is not a per-minute rate, and how long three buckets
  // cover depends on the window's interval.
  basis: string;
}

export type AnomalyType =
  | "4XX_SPIKE"
  | "5XX_SPIKE"
  | "LATENCY_SPIKE"
  | "WAF_BLOCK_SPIKE"
  | "TRAFFIC_ANOMALY_SUSPECTED"
  | "APPLICATION_FAILURE_SUSPECTED"
  | "DATABASE_PRESSURE_SUSPECTED"
  | "RESOURCE_EXHAUSTION_SUSPECTED"
  | "MALICIOUS_CLIENT_SUSPECTED"
  | "UNKNOWN_ANOMALY";

export interface Anomaly {
  id: string;
  type: AnomalyType;
  severity: Status;
  title: string;
  detail: string;
  evidence: string[];
  confidence: Confidence;
  detectedAt: string;
}

export interface ContainerInfo {
  name: string;
  cpuRequest: string;
  cpuLimit: string;
  memRequest: string;
  memLimit: string;
  restartCount: number;
  state: string;
  reason: string;
  message: string;
}

export interface PodInfo {
  namespace: string;
  name: string;
  phase: string;
  ready: string;
  statusLabel: string;
  containers: ContainerInfo[];
  totalRestarts: number;
  recentRestartIncrease: number;
  reason: string;
  message: string;
  podIP: string;
  nodeName: string;
}

export interface WarningEvent {
  timestamp: string;
  namespace: string;
  kind: string;
  name: string;
  reason: string;
  message: string;
  count: number;
  isPod: boolean;
  highlighted: boolean;
}

export interface FingerprintEntry {
  fingerprint: string;
  count: number;
  pods: string[];
  firstSeen: string;
  lastSeen: string;
  sample: string;
}

export interface TimelineEntry {
  ts: string;
  source: string;
  severity: Status;
  text: string;
}

export interface CorrelationResult {
  category: AnomalyType;
  reason: string;
  evidence: string[];
  confidence: Confidence;
}

export interface PathStat {
  path: string;
  count: number;
  blocked: number;
  lowPriority: boolean;
  // Server-decided (config.isPathSuspicious). Both UI tabs read this instead of
  // re-applying the concentration rule with their own thresholds.
  suspicious: boolean;
}

export interface KeyCount {
  key: string;
  count: number;
}

export interface IpStat {
  key: string;
  count: number;
  sharePct: number;
  // Server-decided (config.isIpConcentrated).
  concentrated: boolean;
}

export interface StatusDistribution {
  c2xx: number;
  c3xx: number;
  c4xx: number;
  c5xx: number;
  // Sum of the four buckets, computed server-side so panels don't re-add them.
  total: number;
}

export interface HttpSummary {
  totalSampled: number;
  windowLabel: string;
  source: string;
  byPath: PathStat[];
  byIp: IpStat[];
  byUa: KeyCount[];
  byMethod: KeyCount[];
  queryPatterns: KeyCount[];
  headerPatterns: KeyCount[];
  // Blocked count over the FULL sample, not the truncated byPath list — the two
  // have different populations, so summing byPath in the view under-counts.
  blockedTotal: number;
  statusDist: StatusDistribution | null;
  detailedStatus: KeyCount[] | null;
  // What this source cannot tell you. An empty list that reads as "none
  // observed" when it actually means "not collected" is worse than no panel.
  notes: string[];
}

// The grader's scoring surface (see server/grading.ts). Mirrors the load
// generator's rubric so a number here means what the scorer means.
export type GradingApi = "user" | "product" | "stress";

// One grading key with the value observed for it. No points: scoring belongs to
// the grader's own run, and a second score computed here would compete with it.
export interface GradingScore {
  label: string;
  pct: number;
  okCount: number;
  total: number;
}

export interface GradingPanel {
  lines: GradingScore[];
  window: ResolvedWindow;
  source: string;
  scannedBytes: number;
  notes: string[];
}

// What the client asks for; the server validates and resolves it.
export interface WindowSelection {
  windowMin: number;
  intervalMin: number;
}

// The single window every panel on the page shares. Panels label themselves
// with it, so two numbers on screen always cover the same span.
export interface ResolvedWindow extends WindowSelection {
  startMs: number;
  endMs: number;
  buckets: number;
  label: string;
}

// A regex rule assembled for one purpose (see server/ruleassemble.ts).
export type AssembleKind = "path" | "ua" | "sqli";

// A regex pattern set is a separate AWS resource, created before the rule that
// references it. Both artefacts are produced here so neither has to be
// hand-written from the other.
export interface RegexSetSpec {
  name: string;
  // One regex per line — the set's RegularExpressionList.
  patterns: string[];
  // The CLI that creates this set. Shown, never run.
  createCli: string;
  // The token standing in for this set's ARN inside ruleJson.
  arnPlaceholder: string;
}

export interface AssembledRule {
  kind: AssembleKind;
  name: string;
  // Every pattern across all sets, in order — what the panel lists.
  patterns: string[];
  // The pattern sets to create first. More than one when the pattern count
  // exceeds the per-set quota.
  sets: RegexSetSpec[];
  // The Rule to paste into the console AFTER the sets exist. References them by
  // ARN placeholder; a set name in the ARN field is rejected by AWS.
  ruleJson: string;
  // The same rule with the patterns inlined, which is the only form the local
  // sandbox can evaluate before the sets exist.
  sandboxRuleJson: string;
  // What each pattern came from, so an operator can judge it before applying.
  evidence: string[];
  // Why this field/transform combination, in the operator's language.
  notes: string[];
}

export type WafRuleKind =
  | "RATE_BASED"
  | "BYTE_MATCH"
  | "REGEX_PATTERN"
  | "IP_SET"
  | "MANAGED_GROUP"
  | "LABEL_MATCH";

export interface WafCriteria {
  path?: string;
  userAgent?: string;
  ip?: string;
  query?: string;
  header?: { name: string; value: string };
}

export interface WafRecommendation {
  id: string;
  kind: WafRuleKind;
  name: string;
  targetPattern: string;
  criteria: WafCriteria;
  threshold: number | null;
  evaluationWindowSec: number | null;
  action: "COUNT" | "BLOCK";
  confidence: Confidence;
  reason: string;
  evidence: string[];
  expectedImpact: string;
  falsePositiveRisk: RiskLevel;
  hasScopeDown: boolean;
  // The actual WAFv2 Rule object this recommendation would apply, pretty-printed
  // (SearchString decoded to plain text — same format the WAF console JSON
  // editor accepts). Shown/copied in the UI and handed to Amazon Q.
  ruleJson: string;
}

export interface WafSampleRow {
  ts: string;
  ip: string;
  country: string;
  method: string;
  path: string;
  query: string;
  userAgent: string;
  action: string;
  rule: string;
  // Only populated when WAF itself generated the response (Block with a custom
  // response, CAPTCHA, Challenge). null for ordinary ALLOW traffic.
  responseCode: number | null;
}

export interface SimulationResult {
  recommendationId: string;
  totalSampled: number;
  matchedSampled: number;
  matchRatePct: number;
  estimatedTotalRequests: number;
  estimatedMatched: number;
  estimatedFalsePositives: number;
  estimatedLegitBlocked: number;
  riskLevel: RiskLevel;
  notes: string[];
}

export interface ApplyHistoryEntry {
  id: number;
  ts: string;
  ruleName: string;
  action: string;
  status: string;
  detail: string;
  canRollback: boolean;
}

export interface WafAclInfo {
  name: string;
  id: string;
  scope: string;
  capacityUsed: number;
  ruleCount: number;
  rules: { name: string; priority: number; action: string }[];
}

export interface DeploymentContainerInfo {
  name: string;
  image: string;
  cpuRequest: string;
  cpuLimit: string;
  memRequest: string;
  memLimit: string;
}

export interface DeploymentInfo {
  namespace: string;
  name: string;
  replicas: number;
  readyReplicas: number;
  updatedReplicas: number;
  availableReplicas: number;
  containers: DeploymentContainerInfo[];
}

export type Verdict = "IMPROVED" | "NO_CHANGE" | "DEGRADED" | "INCONCLUSIVE";

export interface VerificationResult {
  actionId: number;
  verdict: Verdict;
  checkedAt: string;
  details: string[];
}

export interface DeployChangeEntry {
  id: number;
  ts: string;
  namespace: string;
  name: string;
  change: string;
  verdict: Verdict | "PENDING";
}

export interface TargetGroupMetrics {
  name: string;
  pathPattern: string;
  responseTime: MetricSummary;
  c4xx: MetricSummary;
  c5xx: MetricSummary;
}

export interface ContainerResourceUsage {
  container: string;
  cpuUsage: string;
  cpuUsageMilli: number;
  memUsage: string;
  memUsageBytes: number;
  cpuLimitMilli: number | null;
  memLimitBytes: number | null;
  cpuPct: number | null;
  memPct: number | null;
}

export interface PodResourceUsage {
  pod: string;
  containers: ContainerResourceUsage[];
  cpuUsageMilli: number;
  memUsageBytes: number;
  cpuPct: number | null;
  memPct: number | null;
}

export interface NodeResourceUsage {
  name: string;
  cpuUsageMilli: number;
  memUsageBytes: number;
  cpuCapacityMilli: number;
  memCapacityBytes: number;
  cpuPct: number;
  memPct: number;
}

export interface ScaleInfo {
  name: string;
  current: number;
  min: number | null;
  max: number | null;
  source: string;
}

export interface PodStatusBreakdown {
  running: number;
  pending: number;
  crashLoop: number;
  oom: number;
  failed: number;
  other: number;
  total: number;
}

export interface RequestLogEntry {
  ts: string;
  method: string;
  path: string;
  status: number;
  latencyMs: number;
}

export interface PathLatencyStat {
  path: string;
  count: number;
  avgLatencyMs: number;
  maxLatencyMs: number;
  nonOkCount: number;
}

export interface RequestLogAnalysis {
  entries: RequestLogEntry[];
  nonOkEntries: RequestLogEntry[];
  errorWarnLines: string[];
  avgLatencyMs: number | null;
  maxLatencyMs: number | null;
  byPath: PathLatencyStat[];
  // Backend-computed totals — independent of the (truncated) sample lists above.
  totalRequests?: number;
  nonOkTotal?: number;
  errorWarnTotal?: number;
  // What population the numbers describe (e.g. "Logs Insights 60m 전체").
  basis?: string;
}

export interface KubePanel {
  pods: PodInfo[];
  events: WarningEvent[];
  deployments: DeploymentInfo[];
  nodesReady: number;
  nodesTotal: number;
  statusBreakdown: PodStatusBreakdown;
  podResources: PodResourceUsage[];
  podResourceError: string | null;
  nodeResources: NodeResourceUsage[];
  nodeResourceError: string | null;
  podScaling: ScaleInfo[];
  nodeScaling: ScaleInfo[];
  scalingError: string | null;
}

export interface MetricsPanel {
  metrics: MetricSummary[];
  metricErrors: string[];
  targetGroupMetrics: TargetGroupMetrics[];
  targetGroupError: string | null;
  httpSummary: HttpSummary | null;
  httpSummaryError: string | null;
  anomalies: Anomaly[];
  correlations: CorrelationResult[];
  timeline: TimelineEntry[];
  // The window every number in this panel covers. Panels label themselves with
  // it so two figures on screen are never read as the same span by accident.
  window: ResolvedWindow;
}

export interface WafPanel {
  acl: WafAclInfo | null;
  aclError: string | null;
  recommendations: WafRecommendation[];
  recommendationError: string | null;
  history: ApplyHistoryEntry[];
}

export interface PodLogsResult {
  lines: string[];
  container: string;
  previous: boolean;
  fingerprints: FingerprintEntry[];
  requestLog: RequestLogAnalysis;
  // Logs Insights cost/provenance — null/absent when served by the k8s API.
  source?: "insights" | "kubernetes";
  scannedBytes?: number;
  windowLabel?: string;
}

export interface IncidentContextResult {
  markdown: string;
  json: string;
  // Category-separated hand-off packed to Amazon Q's 10,000-character prompt
  // limit — see MAX_Q_PROMPT_CHARS.
  qPrompt: string;
  generatedAt: string;
}

export type ActionResult<T> = { ok: true; data: T } | { ok: false; error: string };

export interface RequestLogRow {
  // ISO timestamp
  ts: string;
  method: string;
  path: string;
  status: number;
  latencyMs: number;
}

export interface RequestLogQueryResult {
  rows: RequestLogRow[];
  // recordsMatched — how many matched in the window, beyond the row cap
  totalMatched: number;
  scannedBytes: number;
  windowLabel: string;
  // true when the row cap hid matches
  truncated: boolean;
}

export interface TestRequest {
  // stable key for the UI row
  id: string;
  method: string;
  path: string;
  // query string without the leading "?"
  query: string;
  userAgent: string;
  ip: string;
  // ISO 3166-1 alpha-2 country code for GeoMatchStatement evaluation
  country: string;
  // false marks a deliberately malicious example — blocking it is a true
  // positive, not a false positive.
  benign: boolean;
  // Headers beyond User-Agent (Cookie, Host, X-Forwarded-For, …). Absent
  // headers evaluate as a definite no-match, so only what is listed exists.
  headers?: Record<string, string>;
  // request body, inspected by Body / JsonBody / SizeConstraint statements
  body?: string;
  // labels already on the request, for LabelMatchStatement
  labels?: string[];
}

export type RuleTestAction = "Block" | "Count" | "Allow" | "Captcha" | "Challenge" | "(none)";

export type RuleTestOutcome =
  | "PASS"
  | "BLOCKED"
  | "COUNTED"
  | "CAUGHT"
  | "CHALLENGED"
  | "MATCHED"
  | "UNKNOWN";

export interface RuleTestRow {
  requestId: string;
  // null when the statement could not be evaluated locally
  matched: boolean | null;
  outcome: RuleTestOutcome;
  reason: string;
  // the rule that decided this request; null when nothing matched
  ruleName: string | null;
}

export interface RuleTestResult {
  ruleName: string;
  action: RuleTestAction;
  // how many rules the pasted JSON contained
  ruleCount: number;
  // statement types encountered that cannot be evaluated locally
  unsupported: string[];
  // statement types answered by a local approximation of AWS behaviour
  approximated: string[];
  rows: RuleTestRow[];
  passed: number;
  blocked: number;
  counted: number;
  // matched by a Captcha/Challenge rule
  challenged: number;
  // matched by a rule that carries no action
  matched: number;
  // malicious examples the rule blocked (true positives)
  caught: number;
  // malicious examples the rule let through
  missed: number;
  unknown: number;
  verdict: "SAFE" | "FALSE_POSITIVE_RISK" | "INCONCLUSIVE";
  notes: string[];
}
