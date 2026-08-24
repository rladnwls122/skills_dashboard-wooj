// Shared types. Safe to import from both server and client code.

export type Status = "NORMAL" | "WARNING" | "CRITICAL";
export type Confidence = "LOW" | "MEDIUM" | "HIGH";

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

// One User-Agent's verdict split on the served API surface: how much of its
// traffic the WebACL is currently letting through, and how much it is already
// cutting. `allowed` is the false-positive guard — a client with allowed
// service traffic is carrying requests the score depends on.
export interface UaActionStat {
  key: string;
  allowed: number;
  blocked: number;
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
  // Per-UA verdict split on the served API surface. Empty when the summary came
  // from sampled requests, which cannot answer "was this client's ordinary
  // traffic being allowed" — only the full log can.
  uaActions: UaActionStat[];
  // Arrival counts per surface. null in sampled mode, where a count is a
  // sample and would understate every total it is put next to.
  surface: SurfaceCounts | null;
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
  // Where this line's numbers came from. Not decoration: the keys are
  // measurable from different places — the app log answers the three APIs'
  // 로드 처리 keys, but the 403 keys (Email Request Validation, 비정상 요청
  // 처리율) are what the WAF blocked and never reached the app. A ratio
  // without its source reads as more certain than it is.
  source: string;
  // Set when the figure is a proxy — e.g. a numerator whose denominator the
  // grader keeps to itself (how many bad-email requests it injected).
  approximate?: boolean;
}

// What the WAF log says arrived at each part of the surface, taken from the
// full path×action fold rather than a second query. This is the only source
// that sees requests the origin never answered.
export interface SurfaceCounts {
  imageArrived: number;
  imageBlocked: number;
  undefinedArrived: number;
  undefinedBlocked: number;
}

export interface GradingPanel {
  lines: GradingScore[];
  window: ResolvedWindow;
  source: string;
  scannedBytes: number;
  notes: string[];
}

// One traffic probe (see server/probe.ts). A failed probe is still a completed
// probe, so a failure rides here with ok=false rather than as an error result.
export interface ProbeResult {
  url: string;
  ok: boolean;
  status: number | null;
  elapsedMs: number;
  at: string;
  error: string | null;
  // What counted as healthy. A red verdict cannot be read without also reading
  // what it was compared against.
  expect: string;
  // Where a redirect chain ended, when it moved.
  finalUrl: string | null;
}

// --- settings (see server/settings.ts) -------------------------------------

// Where a value in force actually came from. A dashboard that shows
// "skills-waf" without saying whether that is the operator's choice, the .env
// file, or a built-in default cannot be debugged when it points at the wrong
// account's resources.
export type SettingSource = "screen" | "env" | "default";

// Which AWS listing can fill a field in, when one can.
export type DiscoverKind = "webacl" | "waflog" | "alb" | "eks" | "rdsproxy" | "loggroup";

export interface SettingSpec {
  key: string;
  label: string;
  hint: string;
  discover: DiscoverKind | null;
}

export interface SettingRow extends SettingSpec {
  value: string;
  source: SettingSource;
  // What .env alone would have produced, so an operator can see what a screen
  // override is shadowing before they clear it.
  envValue: string;
  defaultValue: string;
}

export interface SettingsView {
  rows: SettingRow[];
  // The overridden values as .env lines, for making a screen change permanent.
  envText: string;
}

// --- AWS credentials (see server/credentials.ts) ----------------------------

// How the injected keys were obtained. "cli" is the only one that can be
// refreshed on its own, which is why the screen distinguishes them.
export type CredentialOrigin = "paste" | "cli";

// Never carries a secret. The access key id is masked, the secret and the
// session token are reported as presence and length only — the screen has to
// say which key is in force without being a place to read one out of.
export interface CredentialsView {
  // 화면 주입 > .env > SDK 기본 체인(~/.aws · IRSA · 인스턴스 역할).
  source: "screen" | "env" | "chain";
  origin: CredentialOrigin | null;
  // false = 이 프로세스 메모리에만 있음 (재시작하면 사라짐).
  persisted: boolean;
  // The aws CLI profile a "cli" import came from.
  profile: string;
  accessKeyIdMasked: string;
  secretMasked: string;
  hasSessionToken: boolean;
  // ASIA… — a temporary key, which is the shape that expires mid-exercise.
  temporary: boolean;
  expiration: string;
  // Negative once expired; null when the key does not expire or said nothing.
  expiresInMs: number | null;
  envAccessKeyIdMasked: string;
  defaultProfile: string;
}

// The answer to "do these keys work, and as whom".
export interface CredentialCheck {
  // AUTH_FAIL is the credentials being rejected; DENIED is them being accepted
  // and the probe call not being allowed, which still proves they are valid.
  status: "OK" | "DENIED" | "AUTH_FAIL" | "NO_CREDENTIALS";
  account: string;
  region: string;
  detail: string;
}

// One candidate from an AWS listing.
export interface DiscoveredResource {
  // The value that would be written into the setting.
  id: string;
  // What to show beside it — an ARN, a scope, a state.
  detail: string;
  // Set when this candidate is the one already in force.
  current?: boolean;
}

export interface DiscoveryResult {
  kind: DiscoverKind;
  resources: DiscoveredResource[];
  // What was tried and what could not be reached. A short list that says
  // nothing about a denied call reads as "the account has none of these".
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
// No "path": an undefined path already gets a 404 from the ALB, and blocking it
// in the WAF would return 403 instead (04).
export type AssembleKind = "ua";

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
  // What each pattern came from, so an operator can judge it before applying.
  evidence: string[];
  // Why this field/transform combination, in the operator's language.
  notes: string[];
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

// One labelled line on a chart. The label is the pod or node name as recorded.
export interface NamedSeries {
  label: string;
  points: MetricPoint[];
}

// Pod/node usage over the shared window, recorded by this dashboard itself
// (see server/reshistory.ts) because metrics.k8s.io keeps no history. A gap in
// a line means the dashboard was not running, not that usage was zero.
export interface ResourceHistory {
  podCpu: NamedSeries[];
  podMem: NamedSeries[];
  nodeCpu: NamedSeries[];
  nodeMem: NamedSeries[];
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
  clientIp?: string;
  requestId?: string;
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
  // The window every number in this panel covers. Panels label themselves with
  // it so two figures on screen are never read as the same span by accident.
  window: ResolvedWindow;
}

export interface WafPanel {
  acl: WafAclInfo | null;
  aclError: string | null;
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
  // What gin resolved as the client (after X-Forwarded-For) — the binaries'
  // access line carries it, so it is shown; it is not a blocking key (the
  // grader's load comes from one IP).
  clientIp: string;
  // The task's own request id, carried in the query string and written to the
  // app log — the key that lines this row up with the WAF's record of the same
  // request. Empty on POST/PUT, which the app does not read it from.
  requestId: string;
  // As the app logged it, or joined from the WAF log on requestId. Empty when
  // neither had it — a normal answer, not a failure.
  userAgent: string;
  // Where the User-Agent came from, so a joined value is never mistaken for
  // something the app logged.
  uaSource: "app" | "waf" | "";
  // The whole log line, masked. The parsed columns are a guess at which fields
  // matter; this is where the headers nobody predicted stay readable.
  raw: string;
}

export interface RequestLogQueryResult {
  rows: RequestLogRow[];
  // recordsMatched — how many matched in the window, beyond the row cap
  totalMatched: number;
  scannedBytes: number;
  windowLabel: string;
  // true when the row cap hid matches
  truncated: boolean;
  // How many rows got their User-Agent from the WAF log, and why the rest did
  // not — the join is only as good as the requestId both sides carry.
  uaJoined: number;
  uaJoinNote: string;
}

// One request as the WAF recorded it. The app log's counterpart, from the other
// side of the same hop: this one has the User-Agent and the verdict, and it
// exists even for requests the app never saw because they were blocked.
export interface WafLogRow {
  ts: string;
  action: string;
  // The WebACL rule that ended the request — a managed group reports the group
  // name here, which is why the sub-rule is worth showing next to it.
  rule: string;
  subRule: string;
  ip: string;
  country: string;
  method: string;
  uri: string;
  args: string;
  requestId: string;
  userAgent: string;
  // What WAF sent when it answered the request itself (Block/CAPTCHA). null for
  // requests it passed to the origin.
  responseCode: number | null;
}

export interface WafLogQueryResult {
  rows: WafLogRow[];
  totalMatched: number;
  scannedBytes: number;
  windowLabel: string;
  truncated: boolean;
  logGroup: string;
}


export interface TestRequest {
  id: string;
  method: string;
  path: string;
  query: string;
  userAgent: string;
  ip: string;
  country: string;
  benign: boolean;
  headers?: Record<string, string>;
  body?: string;
  labels?: string[];
}

export interface RuleTestRow {
  requestId: string;
  matched: boolean | null;
  outcome: string;
  reason: string;
  ruleName: string | null;
}

export interface RuleTestResult {
  ruleName: string;
  action: string;
  ruleCount: number;
  unsupported: string[];
  approximated: string[];
  rows: RuleTestRow[];
  passed: number;
  blocked: number;
  counted: number;
  challenged: number;
  matched: number;
  caught: number;
  missed: number;
}

// Shared WAF count-evidence and node-cost projections.
export type CountVerdict = "normal" | "abnormal" | "unjoinable";

export interface CountMatch {
  ts: string;
  method: string;
  uri: string;
  args: string;
  requestId: string | null;
  status: number | null;
  latencyMs: number | null;
  verdict: CountVerdict;
}

export interface CountEvidence {
  ruleName: string;
  total: number;
  normal: number;
  abnormal: number;
  unjoinable: number;
  matches: CountMatch[];
  bytesScanned: number;
  notes: string[];
}

export interface ScoringWindow {
  startMs: number;
  endMs: number;
}

export interface InstanceRow {
  id: string;
  type: string;
  az: string;
  name: string | null;
  clusterTag: string | null;
  launchedMs: number | null;
}

export interface OffSpecInstance extends InstanceRow {
  reason: string;
}

export interface NodeCountProjection {
  window: ScoringWindow | null;
  current: number | null;
  elapsedMin: number | null;
  remainingMin: number | null;
  cumulativeAvg: number | null;
  finalAvg: number | null;
  marginalPerInstance: number | null;
  offSpec: OffSpecInstance[];
  notes: string[];
}
