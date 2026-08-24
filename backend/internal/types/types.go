// Package types mirrors src/lib/types.ts field for field.
//
// The UI is unchanged, so the JSON these structs marshal to is a contract, not
// an implementation detail. Two rules keep it honest:
//
//   - A TypeScript `T[] | null` is a nil-able Go slice: nil marshals to null,
//     an allocated empty slice marshals to []. Anything the UI iterates over
//     must therefore be allocated even when empty.
//   - A TypeScript `number | null` / `string | null` is a pointer. Zero is a
//     real value in this dashboard ("0 requests" is not "no data"), so it can
//     never stand in for absence.
package types

// --- primitives -------------------------------------------------------------

type Status = string // "NORMAL" | "WARNING" | "CRITICAL"

type Confidence = string // "LOW" | "MEDIUM" | "HIGH"

type MetricPoint struct {
	T string  `json:"t"`
	V float64 `json:"v"`
}

type MetricSummary struct {
	Key           string        `json:"key"`
	Label         string        `json:"label"`
	Unit          string        `json:"unit"`
	Current       float64       `json:"current"`
	Previous      float64       `json:"previous"`
	Delta         float64       `json:"delta"`
	PercentChange *float64      `json:"percentChange"`
	Status        Status        `json:"status"`
	Points        []MetricPoint `json:"points"`
	Basis         string        `json:"basis"`
}

type Anomaly struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Severity   Status     `json:"severity"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	Evidence   []string   `json:"evidence"`
	Confidence Confidence `json:"confidence"`
	DetectedAt string     `json:"detectedAt"`
}

type ContainerInfo struct {
	Name         string `json:"name"`
	CPURequest   string `json:"cpuRequest"`
	CPULimit     string `json:"cpuLimit"`
	MemRequest   string `json:"memRequest"`
	MemLimit     string `json:"memLimit"`
	RestartCount int    `json:"restartCount"`
	State        string `json:"state"`
	Reason       string `json:"reason"`
	Message      string `json:"message"`
}

type PodInfo struct {
	Namespace             string          `json:"namespace"`
	Name                  string          `json:"name"`
	Phase                 string          `json:"phase"`
	Ready                 string          `json:"ready"`
	StatusLabel           string          `json:"statusLabel"`
	Containers            []ContainerInfo `json:"containers"`
	TotalRestarts         int             `json:"totalRestarts"`
	RecentRestartIncrease int             `json:"recentRestartIncrease"`
	Reason                string          `json:"reason"`
	Message               string          `json:"message"`
	PodIP                 string          `json:"podIP"`
	NodeName              string          `json:"nodeName"`
}

type WarningEvent struct {
	Timestamp   string `json:"timestamp"`
	Namespace   string `json:"namespace"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Reason      string `json:"reason"`
	Message     string `json:"message"`
	Count       int    `json:"count"`
	IsPod       bool   `json:"isPod"`
	Highlighted bool   `json:"highlighted"`
}

type FingerprintEntry struct {
	Fingerprint string   `json:"fingerprint"`
	Count       int      `json:"count"`
	Pods        []string `json:"pods"`
	FirstSeen   string   `json:"firstSeen"`
	LastSeen    string   `json:"lastSeen"`
	Sample      string   `json:"sample"`
}

type TimelineEntry struct {
	Ts       string `json:"ts"`
	Source   string `json:"source"`
	Severity Status `json:"severity"`
	Text     string `json:"text"`
}

type CorrelationResult struct {
	Category   string     `json:"category"`
	Reason     string     `json:"reason"`
	Evidence   []string   `json:"evidence"`
	Confidence Confidence `json:"confidence"`
}

type PathStat struct {
	Path        string `json:"path"`
	Count       int    `json:"count"`
	Blocked     int    `json:"blocked"`
	LowPriority bool   `json:"lowPriority"`
	Suspicious  bool   `json:"suspicious"`
}

type KeyCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type IpStat struct {
	Key          string `json:"key"`
	Count        int    `json:"count"`
	SharePct     int    `json:"sharePct"`
	Concentrated bool   `json:"concentrated"`
}

type StatusDistribution struct {
	C2xx  float64 `json:"c2xx"`
	C3xx  float64 `json:"c3xx"`
	C4xx  float64 `json:"c4xx"`
	C5xx  float64 `json:"c5xx"`
	Total float64 `json:"total"`
}

type HttpSummary struct {
	TotalSampled   int                 `json:"totalSampled"`
	WindowLabel    string              `json:"windowLabel"`
	Source         string              `json:"source"`
	ByPath         []PathStat          `json:"byPath"`
	ByIp           []IpStat            `json:"byIp"`
	ByUa           []KeyCount          `json:"byUa"`
	ByMethod       []KeyCount          `json:"byMethod"`
	QueryPatterns  []KeyCount          `json:"queryPatterns"`
	HeaderPatterns []KeyCount          `json:"headerPatterns"`
	BlockedTotal   int                 `json:"blockedTotal"`
	StatusDist     *StatusDistribution `json:"statusDist"`
	DetailedStatus []KeyCount          `json:"detailedStatus"`
	Notes          []string            `json:"notes"`
}

// --- grading ----------------------------------------------------------------

type GradingScore struct {
	Label   string  `json:"label"`
	Pct     float64 `json:"pct"`
	OkCount int     `json:"okCount"`
	Total   int     `json:"total"`
	// Where this line's numbers came from — the keys are measured in different
	// places (app log for the three APIs, WAF log for what never reached the
	// app), and a ratio without its source reads as more certain than it is.
	Source string `json:"source"`
	// Set when the figure is a proxy — e.g. a numerator whose denominator is
	// not observable — rather than a confirmed count.
	Approximate bool `json:"approximate,omitempty"`
	// The scoring band this value currently sits in, and the next one up. The
	// sheet pays per threshold crossed (90 / 87.5 / 85 / … ), so "86.2%" on its
	// own does not tell the operator whether the next point is worth chasing —
	// "지금 85% 구간, 87.5% 까지 1.3%p" does. nil when total is 0 or the value is
	// below the lowest rung. Pointers so JSON null is expressible.
	Tier     *string `json:"tier"`
	NextTier *string `json:"nextTier"`
}

type GradingPanel struct {
	Lines        []GradingScore `json:"lines"`
	Window       ResolvedWindow `json:"window"`
	Source       string         `json:"source"`
	ScannedBytes int64          `json:"scannedBytes"`
	Notes        []string       `json:"notes"`
}

// --- probe ------------------------------------------------------------------

type ProbeResult struct {
	URL       string  `json:"url"`
	Ok        bool    `json:"ok"`
	Status    *int    `json:"status"`
	ElapsedMs int64   `json:"elapsedMs"`
	At        string  `json:"at"`
	Error     *string `json:"error"`
	Expect    string  `json:"expect"`
	FinalURL  *string `json:"finalUrl"`
}

// --- settings ---------------------------------------------------------------

type SettingSpec struct {
	Key      string  `json:"key"`
	Label    string  `json:"label"`
	Hint     string  `json:"hint"`
	Discover *string `json:"discover"`
}

type SettingRow struct {
	SettingSpec
	Value        string `json:"value"`
	Source       string `json:"source"`
	EnvValue     string `json:"envValue"`
	DefaultValue string `json:"defaultValue"`
}

type SettingsView struct {
	Rows    []SettingRow `json:"rows"`
	EnvText string       `json:"envText"`
}

type DiscoveredResource struct {
	ID      string `json:"id"`
	Detail  string `json:"detail"`
	Current *bool  `json:"current,omitempty"`
}

type DiscoveryResult struct {
	Kind      string               `json:"kind"`
	Resources []DiscoveredResource `json:"resources"`
	Notes     []string             `json:"notes"`
}

// --- window -----------------------------------------------------------------

type WindowSelection struct {
	WindowMin   int `json:"windowMin"`
	IntervalMin int `json:"intervalMin"`
}

type ResolvedWindow struct {
	WindowMin   int    `json:"windowMin"`
	IntervalMin int    `json:"intervalMin"`
	StartMs     int64  `json:"startMs"`
	EndMs       int64  `json:"endMs"`
	Buckets     int    `json:"buckets"`
	Label       string `json:"label"`
}

// --- rule assembly ----------------------------------------------------------

type RegexSetSpec struct {
	Name           string   `json:"name"`
	Patterns       []string `json:"patterns"`
	CreateCli      string   `json:"createCli"`
	ArnPlaceholder string   `json:"arnPlaceholder"`
}

type AssembledRule struct {
	Kind            string         `json:"kind"`
	Name            string         `json:"name"`
	Patterns        []string       `json:"patterns"`
	Sets            []RegexSetSpec `json:"sets"`
	RuleJson        string         `json:"ruleJson"`
	SandboxRuleJson string         `json:"sandboxRuleJson"`
	Evidence        []string       `json:"evidence"`
	Notes           []string       `json:"notes"`
}

// --- WAF --------------------------------------------------------------------

type WafSampleRow struct {
	Ts           string `json:"ts"`
	IP           string `json:"ip"`
	Country      string `json:"country"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Query        string `json:"query"`
	UserAgent    string `json:"userAgent"`
	Action       string `json:"action"`
	Rule         string `json:"rule"`
	ResponseCode *int   `json:"responseCode"`
}

type ApplyHistoryEntry struct {
	ID          int    `json:"id"`
	Ts          string `json:"ts"`
	RuleName    string `json:"ruleName"`
	Action      string `json:"action"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	CanRollback bool   `json:"canRollback"`
}

type WafAclRule struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Action   string `json:"action"`
}

type WafAclInfo struct {
	Name         string       `json:"name"`
	ID           string       `json:"id"`
	Scope        string       `json:"scope"`
	CapacityUsed int64        `json:"capacityUsed"`
	RuleCount    int          `json:"ruleCount"`
	Rules        []WafAclRule `json:"rules"`
}

// WafRuleUpdateResult is what the apply/promote/demote/remove button gets back:
// the rule the WebACL now holds (or no longer holds) and the history row the
// rollback and the verification read from.
type WafRuleUpdateResult struct {
	RuleName  string `json:"ruleName"`
	HistoryID int    `json:"historyId"`
}

// --- COUNT evidence ----------------------------------------------------------

// CountMatch is one request a COUNT rule matched, joined to what the
// application answered. status/latencyMs stay null when the join key is absent
// — a POST carries no requestid in its query string.
type CountMatch struct {
	Ts        string   `json:"ts"`
	Method    string   `json:"method"`
	URI       string   `json:"uri"`
	Args      string   `json:"args"`
	RequestID *string  `json:"requestId"`
	Status    *int     `json:"status"`
	LatencyMs *float64 `json:"latencyMs"`
	Verdict   string   `json:"verdict"`
}

type CountEvidence struct {
	RuleName     string       `json:"ruleName"`
	Total        int          `json:"total"`
	Normal       int          `json:"normal"`
	Abnormal     int          `json:"abnormal"`
	Unjoinable   int          `json:"unjoinable"`
	Matches      []CountMatch `json:"matches"`
	BytesScanned int64        `json:"bytesScanned"`
	Notes        []string     `json:"notes"`
}

// --- node count / cost -------------------------------------------------------

type ScoringWindow struct {
	StartMs int64 `json:"startMs"`
	EndMs   int64 `json:"endMs"`
}

type InstanceRow struct {
	ID   string  `json:"id"`
	Type string  `json:"type"`
	AZ   string  `json:"az"`
	Name *string `json:"name"`
	// The `kubernetes.io/cluster/<name>` tag both EKS managed nodegroups and
	// Karpenter put on the instances they create. Absent means the instance is
	// running outside the cluster.
	ClusterTag *string `json:"clusterTag"`
	LaunchedMs *int64  `json:"launchedMs"`
}

type OffSpecInstance struct {
	InstanceRow
	Reason string `json:"reason"`
}

type NodeCountProjection struct {
	// null when the match start time has not been set.
	Window              *ScoringWindow    `json:"window"`
	Current             *int              `json:"current"`
	ElapsedMin          *int              `json:"elapsedMin"`
	RemainingMin        *int              `json:"remainingMin"`
	CumulativeAvg       *float64          `json:"cumulativeAvg"`
	FinalAvg            *float64          `json:"finalAvg"`
	MarginalPerInstance *float64          `json:"marginalPerInstance"`
	OffSpec             []OffSpecInstance `json:"offSpec"`
	Notes               []string          `json:"notes"`
}

// CloudTrailEvent is the slice of a LookupEvents result the node-count
// reconstruction reads. Kept here so the AWS layer and the arithmetic that
// consumes it do not have to import one another.
type CloudTrailEvent struct {
	Name string
	TsMs int64
	Body string
}

// --- AWS credentials ---------------------------------------------------------

// CredentialsView never carries a secret. The access key id is masked, the
// secret and the session token are reported as presence and length only — the
// screen has to say which key is in force without being a place to read one
// out of.
type CredentialsView struct {
	// 화면 주입 > 환경변수 > SDK 기본 체인(~/.aws · IRSA · 인스턴스 역할).
	Source string `json:"source"`
	// "paste" | "cli", or null when nothing is injected.
	Origin *string `json:"origin"`
	// false = 이 프로세스 메모리에만 있음 (재시작하면 사라짐).
	Persisted            bool   `json:"persisted"`
	Profile              string `json:"profile"`
	AccessKeyIDMasked    string `json:"accessKeyIdMasked"`
	SecretMasked         string `json:"secretMasked"`
	HasSessionToken      bool   `json:"hasSessionToken"`
	Temporary            bool   `json:"temporary"`
	Expiration           string `json:"expiration"`
	ExpiresInMs          *int64 `json:"expiresInMs"`
	EnvAccessKeyIDMasked string `json:"envAccessKeyIdMasked"`
	DefaultProfile       string `json:"defaultProfile"`
}

// CredentialCheck is the answer to "do these keys work, and as whom".
type CredentialCheck struct {
	// AUTH_FAIL is the credentials being rejected; DENIED is them being accepted
	// and the probe call not being allowed, which still proves they are valid.
	Status  string `json:"status"`
	Account string `json:"account"`
	Region  string `json:"region"`
	Detail  string `json:"detail"`
}

type CredentialsResult struct {
	View  CredentialsView `json:"view"`
	Check CredentialCheck `json:"check"`
}

// --- deployments ------------------------------------------------------------

type DeploymentContainerInfo struct {
	Name       string `json:"name"`
	Image      string `json:"image"`
	CPURequest string `json:"cpuRequest"`
	CPULimit   string `json:"cpuLimit"`
	MemRequest string `json:"memRequest"`
	MemLimit   string `json:"memLimit"`
}

type DeploymentInfo struct {
	Namespace         string                    `json:"namespace"`
	Name              string                    `json:"name"`
	Replicas          int                       `json:"replicas"`
	ReadyReplicas     int                       `json:"readyReplicas"`
	UpdatedReplicas   int                       `json:"updatedReplicas"`
	AvailableReplicas int                       `json:"availableReplicas"`
	Containers        []DeploymentContainerInfo `json:"containers"`
}

type VerificationResult struct {
	ActionID  int      `json:"actionId"`
	Verdict   string   `json:"verdict"`
	CheckedAt string   `json:"checkedAt"`
	Details   []string `json:"details"`
}

type DeployChangeEntry struct {
	ID        int    `json:"id"`
	Ts        string `json:"ts"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Change    string `json:"change"`
	Verdict   string `json:"verdict"`
}

type TargetGroupMetrics struct {
	Name         string        `json:"name"`
	PathPattern  string        `json:"pathPattern"`
	ResponseTime MetricSummary `json:"responseTime"`
	C4xx         MetricSummary `json:"c4xx"`
	C5xx         MetricSummary `json:"c5xx"`
}

// --- resources --------------------------------------------------------------

type ContainerResourceUsage struct {
	Container     string   `json:"container"`
	CPUUsage      string   `json:"cpuUsage"`
	CPUUsageMilli float64  `json:"cpuUsageMilli"`
	MemUsage      string   `json:"memUsage"`
	MemUsageBytes float64  `json:"memUsageBytes"`
	CPULimitMilli *float64 `json:"cpuLimitMilli"`
	MemLimitBytes *float64 `json:"memLimitBytes"`
	CPUPct        *float64 `json:"cpuPct"`
	MemPct        *float64 `json:"memPct"`
}

type PodResourceUsage struct {
	Pod           string                   `json:"pod"`
	Containers    []ContainerResourceUsage `json:"containers"`
	CPUUsageMilli float64                  `json:"cpuUsageMilli"`
	MemUsageBytes float64                  `json:"memUsageBytes"`
	CPUPct        *float64                 `json:"cpuPct"`
	MemPct        *float64                 `json:"memPct"`
}

type NodeResourceUsage struct {
	Name             string  `json:"name"`
	CPUUsageMilli    float64 `json:"cpuUsageMilli"`
	MemUsageBytes    float64 `json:"memUsageBytes"`
	CPUCapacityMilli float64 `json:"cpuCapacityMilli"`
	MemCapacityBytes float64 `json:"memCapacityBytes"`
	CPUPct           float64 `json:"cpuPct"`
	MemPct           float64 `json:"memPct"`
}

type NamedSeries struct {
	Label  string        `json:"label"`
	Points []MetricPoint `json:"points"`
}

type ResourceHistory struct {
	PodCPU  []NamedSeries `json:"podCpu"`
	PodMem  []NamedSeries `json:"podMem"`
	NodeCPU []NamedSeries `json:"nodeCpu"`
	NodeMem []NamedSeries `json:"nodeMem"`
}

type ScaleInfo struct {
	Name    string `json:"name"`
	Current int    `json:"current"`
	Min     *int   `json:"min"`
	Max     *int   `json:"max"`
	Source  string `json:"source"`
}

type PodStatusBreakdown struct {
	Running   int `json:"running"`
	Pending   int `json:"pending"`
	CrashLoop int `json:"crashLoop"`
	Oom       int `json:"oom"`
	Failed    int `json:"failed"`
	Other     int `json:"other"`
	Total     int `json:"total"`
}

// --- request log ------------------------------------------------------------

type RequestLogEntry struct {
	Ts        string  `json:"ts"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Status    int     `json:"status"`
	LatencyMs float64 `json:"latencyMs"`
	// What gin resolved as the client (after X-Forwarded-For).
	ClientIP string `json:"clientIp,omitempty"`
	// The grader's requestid when the request carried it in the query string.
	RequestID string `json:"requestId,omitempty"`
}

type PathLatencyStat struct {
	Path         string  `json:"path"`
	Count        int     `json:"count"`
	AvgLatencyMs float64 `json:"avgLatencyMs"`
	MaxLatencyMs float64 `json:"maxLatencyMs"`
	NonOkCount   int     `json:"nonOkCount"`
}

type RequestLogAnalysis struct {
	Entries        []RequestLogEntry `json:"entries"`
	NonOkEntries   []RequestLogEntry `json:"nonOkEntries"`
	ErrorWarnLines []string          `json:"errorWarnLines"`
	AvgLatencyMs   *float64          `json:"avgLatencyMs"`
	MaxLatencyMs   *float64          `json:"maxLatencyMs"`
	ByPath         []PathLatencyStat `json:"byPath"`
	TotalRequests  *int              `json:"totalRequests,omitempty"`
	NonOkTotal     *int              `json:"nonOkTotal,omitempty"`
	ErrorWarnTotal *int              `json:"errorWarnTotal,omitempty"`
	Basis          *string           `json:"basis,omitempty"`
}

type RequestLogRow struct {
	Ts        string  `json:"ts"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Status    int     `json:"status"`
	LatencyMs float64 `json:"latencyMs"`
	ClientIP  string  `json:"clientIp"`
	// The task's own request id, carried in the query string and therefore in
	// the gin access line — the key that lines this row up with the WAF's
	// record of the same request. Empty on POST, where it travels in the body.
	RequestID string `json:"requestId"`
	// Joined from the WAF log on RequestID; the app never logs a User-Agent.
	UserAgent string `json:"userAgent"`
	// "waf" when UserAgent was joined, "" otherwise.
	UaSource string `json:"uaSource"`
	// The whole log line, masked.
	Raw string `json:"raw"`
}

type RequestLogQueryResult struct {
	Rows         []RequestLogRow `json:"rows"`
	TotalMatched int64           `json:"totalMatched"`
	ScannedBytes int64           `json:"scannedBytes"`
	WindowLabel  string          `json:"windowLabel"`
	Truncated    bool            `json:"truncated"`
	// How many rows got their User-Agent from the WAF log, and why the rest
	// did not — the join is only as good as the requestid both sides carry.
	UaJoined   int    `json:"uaJoined"`
	UaJoinNote string `json:"uaJoinNote"`
}

type WafLogRow struct {
	Ts           string `json:"ts"`
	Action       string `json:"action"`
	Rule         string `json:"rule"`
	SubRule      string `json:"subRule"`
	IP           string `json:"ip"`
	Country      string `json:"country"`
	Method       string `json:"method"`
	URI          string `json:"uri"`
	Args         string `json:"args"`
	RequestID    string `json:"requestId"`
	UserAgent    string `json:"userAgent"`
	ResponseCode *int   `json:"responseCode"`
}

type WafLogQueryResult struct {
	Rows         []WafLogRow `json:"rows"`
	TotalMatched int64       `json:"totalMatched"`
	ScannedBytes int64       `json:"scannedBytes"`
	WindowLabel  string      `json:"windowLabel"`
	Truncated    bool        `json:"truncated"`
	LogGroup     string      `json:"logGroup"`
}

// --- panels -----------------------------------------------------------------

type KubePanel struct {
	Pods              []PodInfo           `json:"pods"`
	Events            []WarningEvent      `json:"events"`
	Deployments       []DeploymentInfo    `json:"deployments"`
	NodesReady        int                 `json:"nodesReady"`
	NodesTotal        int                 `json:"nodesTotal"`
	StatusBreakdown   PodStatusBreakdown  `json:"statusBreakdown"`
	PodResources      []PodResourceUsage  `json:"podResources"`
	PodResourceError  *string             `json:"podResourceError"`
	NodeResources     []NodeResourceUsage `json:"nodeResources"`
	NodeResourceError *string             `json:"nodeResourceError"`
	PodScaling        []ScaleInfo         `json:"podScaling"`
	NodeScaling       []ScaleInfo         `json:"nodeScaling"`
	ScalingError      *string             `json:"scalingError"`
}

type MetricsPanel struct {
	Metrics           []MetricSummary      `json:"metrics"`
	MetricErrors      []string             `json:"metricErrors"`
	TargetGroupMetric []TargetGroupMetrics `json:"targetGroupMetrics"`
	TargetGroupError  *string              `json:"targetGroupError"`
	HttpSummary       *HttpSummary         `json:"httpSummary"`
	HttpSummaryError  *string              `json:"httpSummaryError"`
	Anomalies         []Anomaly            `json:"anomalies"`
	Correlations      []CorrelationResult  `json:"correlations"`
	Timeline          []TimelineEntry      `json:"timeline"`
	Window            ResolvedWindow       `json:"window"`
}

type WafPanel struct {
	Acl      *WafAclInfo         `json:"acl"`
	AclError *string             `json:"aclError"`
	History  []ApplyHistoryEntry `json:"history"`
}

type PodLogsResult struct {
	Lines        []string           `json:"lines"`
	Container    string             `json:"container"`
	Previous     bool               `json:"previous"`
	Fingerprints []FingerprintEntry `json:"fingerprints"`
	RequestLog   RequestLogAnalysis `json:"requestLog"`
	Source       string             `json:"source,omitempty"`
	ScannedBytes *int64             `json:"scannedBytes,omitempty"`
	WindowLabel  string             `json:"windowLabel,omitempty"`
}

type IncidentContextResult struct {
	Markdown    string `json:"markdown"`
	Json        string `json:"json"`
	QPrompt     string `json:"qPrompt"`
	GeneratedAt string `json:"generatedAt"`
}

// --- rule sandbox -----------------------------------------------------------

type TestRequest struct {
	ID        string            `json:"id"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Query     string            `json:"query"`
	UserAgent string            `json:"userAgent"`
	IP        string            `json:"ip"`
	Country   string            `json:"country"`
	Benign    bool              `json:"benign"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Labels    []string          `json:"labels,omitempty"`
}

type RuleTestRow struct {
	RequestID string  `json:"requestId"`
	Matched   *bool   `json:"matched"`
	Outcome   string  `json:"outcome"`
	Reason    string  `json:"reason"`
	RuleName  *string `json:"ruleName"`
}

type RuleTestResult struct {
	RuleName     string        `json:"ruleName"`
	Action       string        `json:"action"`
	RuleCount    int           `json:"ruleCount"`
	Unsupported  []string      `json:"unsupported"`
	Approximated []string      `json:"approximated"`
	Rows         []RuleTestRow `json:"rows"`
	Passed       int           `json:"passed"`
	Blocked      int           `json:"blocked"`
	Counted      int           `json:"counted"`
	Challenged   int           `json:"challenged"`
	Matched      int           `json:"matched"`
	Caught       int           `json:"caught"`
	Missed       int           `json:"missed"`
	Unknown      int           `json:"unknown"`
	Verdict      string        `json:"verdict"`
	Notes        []string      `json:"notes"`
}

// --- helpers ----------------------------------------------------------------

func Ptr[T any](v T) *T { return &v }
