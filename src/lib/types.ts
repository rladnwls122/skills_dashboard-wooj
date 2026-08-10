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
}

export interface KeyCount {
  key: string;
  count: number;
}

export interface StatusDistribution {
  c2xx: number;
  c3xx: number;
  c4xx: number;
  c5xx: number;
}

export interface HttpSummary {
  totalSampled: number;
  windowLabel: string;
  source: string;
  byPath: PathStat[];
  byIp: KeyCount[];
  byUa: KeyCount[];
  byMethod: KeyCount[];
  queryPatterns: KeyCount[];
  headerPatterns: KeyCount[];
  statusDist: StatusDistribution | null;
  detailedStatus: KeyCount[] | null;
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
  generatedAt: string;
}

export type ActionResult<T> = { ok: true; data: T } | { ok: false; error: string };
