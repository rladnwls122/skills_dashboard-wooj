// Package kube is the Kubernetes-touching layer, ported from
// src/lib/server/k8s.ts and resources.ts. In-cluster config when running in a
// pod, kubeconfig otherwise; clients are built once and reused.
package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/analysis"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/creds"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type Kube struct {
	Settings *config.Settings
	Store    *store.Store
	// The credentials the 설정 screen injected, when there are any. This layer
	// has to know about them because an EKS kubeconfig authenticates by running
	// `aws eks get-token` as a child process, and a child process sees the
	// environment, not this dashboard's in-memory credential manager.
	Credentials *creds.Manager

	mu      sync.Mutex
	cs      kubernetes.Interface
	metrics metricsclient.Interface
	// What the memoized clients were built from, kept so an authentication
	// failure can be explained instead of merely reported.
	usesExecAuthentication bool
	builtWithInjectedKeys  bool
}

func New(settings *config.Settings, st *store.Store, credentials *creds.Manager) *Kube {
	return &Kube{Settings: settings, Store: st, Credentials: credentials}
}

// Reset drops the memoized clients so the next call rebuilds them.
//
// Without this, injecting credentials on the settings screen fixed the AWS
// panels and left Kubernetes broken forever: awsx.Reset() rebuilt the SDK
// clients, but the clients here were built once and reused, and the exec plugin
// behind them had already been handed its environment. Re-injecting could not
// help either, because nothing ever asked for a new client. The whole point of
// the 설정 screen is that a wrong or expired key is recoverable without a
// restart, and that promise is only kept if every memoized client is dropped.
func (k *Kube) Reset() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cs = nil
	k.metrics = nil
	k.usesExecAuthentication = false
	k.builtWithInjectedKeys = false
}

func (k *Kube) clients() (kubernetes.Interface, metricsclient.Interface, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cs != nil {
		return k.cs, k.metrics, nil
	}
	var cfg *rest.Config
	var err error
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		cfg, err = rest.InClusterConfig()
	} else {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("kubeconfig 로드 실패: %w", err)
	}
	k.usesExecAuthentication = cfg.ExecProvider != nil
	k.builtWithInjectedKeys = applyInjectedCredentials(cfg, k.Credentials)
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	mc, err := metricsclient.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	k.cs, k.metrics = cs, mc
	return cs, mc, nil
}

// applyInjectedCredentials hands the keys from the 설정 screen to the exec
// credential plugin, and reports whether it had any to hand over.
//
// client-go runs the plugin with this process's environment plus ExecConfig.Env,
// so this is the whole mechanism: no fork of client-go, no rewriting of the
// user's kubeconfig on disk. The three variables are set together, the session
// token included even when it is empty, because a new access key paired with a
// leftover AWS_SESSION_TOKEN from the environment fails with an
// InvalidClientTokenId that reads like a bad key rather than a stale token.
func applyInjectedCredentials(cfg *rest.Config, credentials *creds.Manager) bool {
	if cfg.ExecProvider == nil || credentials == nil {
		return false
	}
	injected := credentials.Injected()
	if injected == nil || injected.AccessKeyID == "" || injected.SecretAccessKey == "" {
		return false
	}
	// The kubeconfig is shared state read from disk; the clone keeps this
	// dashboard from writing credentials into anyone else's view of it.
	provider := cfg.ExecProvider.DeepCopy()
	overrides := map[string]string{
		"AWS_ACCESS_KEY_ID":     injected.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": injected.SecretAccessKey,
		"AWS_SESSION_TOKEN":     injected.SessionToken,
	}
	kept := make([]clientcmdapi.ExecEnvVar, 0, len(provider.Env)+len(overrides))
	for _, entry := range provider.Env {
		if _, replaced := overrides[entry.Name]; !replaced {
			kept = append(kept, entry)
		}
	}
	// A stable order so two runs of the same configuration produce the same
	// exec invocation; client-go caches credentials keyed on it.
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		kept = append(kept, clientcmdapi.ExecEnvVar{Name: name, Value: overrides[name]})
	}
	provider.Env = kept
	cfg.ExecProvider = provider
	return true
}

// Errors that mean "the cluster would not accept who we are", as opposed to
// "the thing you asked for is not there". Matched on text because they arrive
// from three unrelated places — the API server, client-go's exec machinery and
// the aws CLI itself — with no shared error type between them.
var authenticationFailureRe = regexp.MustCompile(
	`(?i)unauthorized|forbidden|401|403|getting credentials|exec plugin|credential|expiredtoken|invalidclienttokenid|you must be logged in|signaturedoesnotmatch`)

// explainAuthenticationFailure appends what the operator cannot see from the
// error alone: which identity this connection is actually using.
//
// Credentials injected on the settings screen only reach `aws eks get-token`
// because clients() puts them in the plugin's environment — and only for
// clients built after the injection. If one of those clients is still failing,
// the plugin is resolving an identity from somewhere else (an AWS_PROFILE, an
// explicit --profile in the kubeconfig's exec args, an SSO cache), and no
// amount of re-injecting on this screen will change that. Saying so is the
// difference between a fixable minute and an unexplained dead panel.
func (k *Kube) explainAuthenticationFailure(err error) error {
	if err == nil || !authenticationFailureRe.MatchString(err.Error()) {
		return err
	}
	k.mu.Lock()
	usesExec := k.usesExecAuthentication
	injected := k.builtWithInjectedKeys
	k.mu.Unlock()
	if !usesExec {
		return err
	}
	if injected {
		return fmt.Errorf("%w — kubeconfig 가 exec 인증(`aws eks get-token`)을 사용합니다. "+
			"설정 화면에서 주입한 키를 이 플러그인의 환경변수로 전달했는데도 인증에 실패했다면, "+
			"kubeconfig 의 exec 인자에 --profile 이 박혀 있거나 AWS_PROFILE·SSO 캐시가 우선하고 있을 가능성이 큽니다. "+
			"그 경우 키를 환경변수에 넣은 상태로 이 프로세스를 재시작해야 합니다", err)
	}
	return fmt.Errorf("%w — kubeconfig 가 exec 인증(`aws eks get-token`)을 사용합니다. "+
		"이 경로는 프로세스 환경변수의 자격증명을 사용하므로, 설정 화면에 키를 주입한 뒤 이 메시지가 계속 보이면 "+
		"키를 환경변수에 넣은 상태로 이 프로세스를 재시작하세요", err)
}

var highlightReasons = regexp.MustCompile(`(?i)(failed|backoff|failedmount|failedscheduling|unhealthy|oom|evicted|killing)`)

func containerState(cs corev1.ContainerStatus) (state, reason, message string) {
	switch {
	case cs.State.Waiting != nil:
		return "Waiting", cs.State.Waiting.Reason, cs.State.Waiting.Message
	case cs.State.Terminated != nil:
		return "Terminated", cs.State.Terminated.Reason, cs.State.Terminated.Message
	case cs.State.Running != nil:
		return "Running", "", ""
	default:
		return "Unknown", "", ""
	}
}

func podStatusLabel(pod corev1.Pod) string {
	statuses := pod.Status.ContainerStatuses
	for _, cs := range statuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return cs.State.Waiting.Reason
		}
		if cs.LastTerminationState.Terminated != nil &&
			cs.LastTerminationState.Terminated.Reason == "OOMKilled" &&
			cs.RestartCount > 0 && !cs.Ready {
			return "OOMKilled"
		}
	}
	phase := string(pod.Status.Phase)
	if phase == "" {
		phase = "Unknown"
	}
	if phase == "Running" {
		allReady := len(statuses) > 0
		for _, cs := range statuses {
			if !cs.Ready {
				allReady = false
				break
			}
		}
		if allReady {
			return "Running"
		}
		return "NotReady"
	}
	return phase
}

func quantityString(list corev1.ResourceList, name corev1.ResourceName) string {
	if q, ok := list[name]; ok {
		return q.String()
	}
	return "-"
}

func specContainer(pod corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	return nil
}

func (k *Kube) ListPods(ctx context.Context) ([]types.PodInfo, error) {
	cs, _, err := k.clients()
	if err != nil {
		return nil, err
	}
	ns := k.Settings.TargetNamespace()
	res, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		// This is the error that takes the whole Kubernetes panel down, so it
		// is the one that has to carry the explanation.
		return nil, k.explainAuthenticationFailure(err)
	}
	nowMs := time.Now().UnixMilli()
	out := make([]types.PodInfo, 0, len(res.Items))
	for _, pod := range res.Items {
		statuses := pod.Status.ContainerStatuses
		containers := make([]types.ContainerInfo, 0, len(statuses))
		totalRestarts := 0
		for _, cs := range statuses {
			spec := specContainer(pod, cs.Name)
			state, reason, message := containerState(cs)
			info := types.ContainerInfo{
				Name:         cs.Name,
				CPURequest:   "-",
				CPULimit:     "-",
				MemRequest:   "-",
				MemLimit:     "-",
				RestartCount: int(cs.RestartCount),
				State:        state,
				Reason:       reason,
				Message:      message,
			}
			if spec != nil {
				info.CPURequest = quantityString(spec.Resources.Requests, corev1.ResourceCPU)
				info.CPULimit = quantityString(spec.Resources.Limits, corev1.ResourceCPU)
				info.MemRequest = quantityString(spec.Resources.Requests, corev1.ResourceMemory)
				info.MemLimit = quantityString(spec.Resources.Limits, corev1.ResourceMemory)
			}
			containers = append(containers, info)
			totalRestarts += int(cs.RestartCount)
		}
		podKey := pod.Namespace + "/" + pod.Name
		recentIncrease, err := k.Store.TrackRestarts(podKey, totalRestarts, nowMs)
		if err != nil {
			recentIncrease = 0
		}
		readyCount := 0
		for _, cs := range statuses {
			if cs.Ready {
				readyCount++
			}
		}
		reason := pod.Status.Reason
		message := pod.Status.Message
		for _, c := range containers {
			if reason == "" && c.Reason != "" {
				reason = c.Reason
			}
			if message == "" && c.Message != "" {
				message = c.Message
			}
		}
		namespace := pod.Namespace
		if namespace == "" {
			namespace = ns
		}
		phase := string(pod.Status.Phase)
		if phase == "" {
			phase = "Unknown"
		}
		out = append(out, types.PodInfo{
			Namespace:             namespace,
			Name:                  pod.Name,
			Phase:                 phase,
			Ready:                 fmt.Sprintf("%d/%d", readyCount, len(statuses)),
			StatusLabel:           podStatusLabel(pod),
			Containers:            containers,
			TotalRestarts:         totalRestarts,
			RecentRestartIncrease: recentIncrease,
			Reason:                reason,
			Message:               message,
			PodIP:                 pod.Status.PodIP,
			NodeName:              pod.Spec.NodeName,
		})
	}
	return out, nil
}

func eventTimestamp(ev corev1.Event) string {
	if !ev.LastTimestamp.IsZero() {
		return ev.LastTimestamp.UTC().Format(time.RFC3339)
	}
	if !ev.EventTime.IsZero() {
		return ev.EventTime.UTC().Format(time.RFC3339)
	}
	if !ev.FirstTimestamp.IsZero() {
		return ev.FirstTimestamp.UTC().Format(time.RFC3339)
	}
	return ""
}

func (k *Kube) ListWarningEvents(ctx context.Context) ([]types.WarningEvent, error) {
	cs, _, err := k.clients()
	if err != nil {
		return nil, err
	}
	ns := k.Settings.TargetNamespace()
	res, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{FieldSelector: "type=Warning"})
	if err != nil {
		return nil, err
	}
	events := make([]types.WarningEvent, 0, len(res.Items))
	for _, ev := range res.Items {
		count := int(ev.Count)
		if count == 0 {
			count = 1
		}
		namespace := ev.Namespace
		if namespace == "" {
			namespace = ns
		}
		events = append(events, types.WarningEvent{
			Timestamp:   eventTimestamp(ev),
			Namespace:   namespace,
			Kind:        ev.InvolvedObject.Kind,
			Name:        ev.InvolvedObject.Name,
			Reason:      ev.Reason,
			Message:     ev.Message,
			Count:       count,
			IsPod:       ev.InvolvedObject.Kind == "Pod",
			Highlighted: highlightReasons.MatchString(ev.Reason),
		})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp > events[j].Timestamp })
	return events, nil
}

// NodeCapacity is a node's allocatable resources — the denominator every node
// percentage on the 성능 panel is divided by.
type NodeCapacity struct {
	CPUMilli float64
	MemBytes float64
}

// NodeListing is one CoreV1().Nodes().List() and everything the panel derives
// from it.
//
// The list used to be fetched twice per poll — once by CountReadyNodes for the
// header count, once by GetNodeResourceUsage for the capacity denominators —
// for identical data. Under EKS exec-auth every call carries an `aws eks
// get-token` round trip, so the duplicate was one of the reasons a 3-second
// cache never went warm.
//
// Err is carried in the struct rather than returned separately because both
// consumers have to react to it, and each reacts differently: the header shows
// zero nodes, and the resource table has to refuse to draw at all — with an
// empty capacity map every percentage divides by zero, is clamped away, and the
// panel paints a completely idle cluster, which is the most dangerous thing
// this screen can say while the cluster is on fire.
type NodeListing struct {
	Ready    int
	Total    int
	Capacity map[string]NodeCapacity
	Err      error
}

// ListNodes fetches the node list once for whoever needs it this poll.
func (k *Kube) ListNodes(ctx context.Context) NodeListing {
	cs, _, err := k.clients()
	if err != nil {
		return NodeListing{Err: err}
	}
	res, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return NodeListing{Err: k.explainAuthenticationFailure(err)}
	}
	listing := NodeListing{Total: len(res.Items), Capacity: map[string]NodeCapacity{}}
	for _, node := range res.Items {
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				listing.Ready++
				break
			}
		}
		cpuQty := node.Status.Allocatable[corev1.ResourceCPU]
		memQty := node.Status.Allocatable[corev1.ResourceMemory]
		listing.Capacity[node.Name] = NodeCapacity{
			CPUMilli: float64(cpuQty.MilliValue()),
			MemBytes: float64(memQty.Value()),
		}
	}
	return listing
}

// CountReadyNodes is the single-caller form, kept for callers that want only
// the header numbers and are not sharing a poll with the resource table.
func (k *Kube) CountReadyNodes(ctx context.Context) (ready, total int, err error) {
	listing := k.ListNodes(ctx)
	if listing.Err != nil {
		return 0, 0, listing.Err
	}
	return listing.Ready, listing.Total, nil
}

func deploymentInfo(fallbackNs string, d *appsv1.Deployment) types.DeploymentInfo {
	namespace := d.Namespace
	if namespace == "" {
		namespace = fallbackNs
	}
	replicas := 0
	if d.Spec.Replicas != nil {
		replicas = int(*d.Spec.Replicas)
	}
	containers := make([]types.DeploymentContainerInfo, 0, len(d.Spec.Template.Spec.Containers))
	for _, c := range d.Spec.Template.Spec.Containers {
		containers = append(containers, types.DeploymentContainerInfo{
			Name:       c.Name,
			Image:      c.Image,
			CPURequest: quantityString(c.Resources.Requests, corev1.ResourceCPU),
			CPULimit:   quantityString(c.Resources.Limits, corev1.ResourceCPU),
			MemRequest: quantityString(c.Resources.Requests, corev1.ResourceMemory),
			MemLimit:   quantityString(c.Resources.Limits, corev1.ResourceMemory),
		})
	}
	return types.DeploymentInfo{
		Namespace:         namespace,
		Name:              d.Name,
		Replicas:          replicas,
		ReadyReplicas:     int(d.Status.ReadyReplicas),
		UpdatedReplicas:   int(d.Status.UpdatedReplicas),
		AvailableReplicas: int(d.Status.AvailableReplicas),
		Containers:        containers,
	}
}

func (k *Kube) ListDeployments(ctx context.Context) ([]types.DeploymentInfo, error) {
	cs, _, err := k.clients()
	if err != nil {
		return nil, err
	}
	ns := k.Settings.TargetNamespace()
	res, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]types.DeploymentInfo, 0, len(res.Items))
	for i := range res.Items {
		out = append(out, deploymentInfo(ns, &res.Items[i]))
	}
	return out, nil
}

func (k *Kube) GetDeployment(ctx context.Context, namespace, name string) (types.DeploymentInfo, error) {
	cs, _, err := k.clients()
	if err != nil {
		return types.DeploymentInfo{}, err
	}
	d, err := cs.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return types.DeploymentInfo{}, err
	}
	return deploymentInfo(namespace, d), nil
}

// GetPodLogs is the direct Kubernetes tail — previous-container forensics and
// the fallback when Insights is unavailable. Lines are masked before leaving.
func (k *Kube) GetPodLogs(ctx context.Context, pod, container string, previous bool, tailLines int) ([]string, error) {
	cs, _, err := k.clients()
	if err != nil {
		return nil, err
	}
	if tailLines < 10 {
		tailLines = 10
	}
	if tailLines > 2000 {
		tailLines = 2000
	}
	tail := int64(tailLines)
	raw, err := cs.CoreV1().Pods(k.Settings.TargetNamespace()).GetLogs(pod, &corev1.PodLogOptions{
		Container:  container,
		Previous:   previous,
		TailLines:  &tail,
		Timestamps: true,
	}).DoRaw(ctx)
	if err != nil {
		return nil, k.explainAuthenticationFailure(err)
	}
	lines := []string{}
	for _, l := range strings.Split(string(raw), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return analysis.MaskLines(lines), nil
}

// --- patch -------------------------------------------------------------------

type PatchRequest struct {
	Namespace     string
	Name          string
	Replicas      *int
	ContainerName *string
	CPULimit      *string
	MemLimit      *string
}

// ValidatePatch rejects before touching the API (spec §22).
//
// The rules that need no cluster live in config.ValidateDeploymentPatch and are
// checked first, so this path and the preview path in internal/service reject
// exactly the same requests — they used to be two copies and the preview one
// was the weaker of the two. What is left here is the part only the cluster can
// answer: the deployment has to exist, and the container named has to be one of
// its containers.
func (k *Kube) ValidatePatch(ctx context.Context, req PatchRequest) (types.DeploymentInfo, int, error) {
	if err := k.Settings.ValidateDeploymentPatch(config.DeploymentPatchFields{
		Namespace:     req.Namespace,
		Name:          req.Name,
		Replicas:      req.Replicas,
		ContainerName: req.ContainerName,
		CPULimit:      req.CPULimit,
		MemLimit:      req.MemLimit,
	}); err != nil {
		return types.DeploymentInfo{}, -1, err
	}

	deployment, err := k.GetDeployment(ctx, req.Namespace, req.Name)
	if err != nil {
		return types.DeploymentInfo{}, -1, err
	}

	containerIndex := -1
	if req.CPULimit != nil || req.MemLimit != nil {
		for i, c := range deployment.Containers {
			if c.Name == *req.ContainerName {
				containerIndex = i
				break
			}
		}
		if containerIndex < 0 {
			return types.DeploymentInfo{}, -1, fmt.Errorf("container not found: %s", *req.ContainerName)
		}
	}
	return deployment, containerIndex, nil
}

type jsonPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func (k *Kube) PatchDeployment(ctx context.Context, req PatchRequest) (types.DeploymentInfo, error) {
	cs, _, err := k.clients()
	if err != nil {
		return types.DeploymentInfo{}, err
	}
	_, containerIndex, err := k.ValidatePatch(ctx, req)
	if err != nil {
		return types.DeploymentInfo{}, err
	}

	ops := []jsonPatchOp{}
	if req.Replicas != nil {
		ops = append(ops, jsonPatchOp{Op: "replace", Path: "/spec/replicas", Value: *req.Replicas})
	}
	if containerIndex >= 0 {
		current, err := cs.AppsV1().Deployments(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
		if err != nil {
			return types.DeploymentInfo{}, err
		}
		if containerIndex >= len(current.Spec.Template.Spec.Containers) {
			return types.DeploymentInfo{}, fmt.Errorf("container disappeared during validation")
		}
		container := current.Spec.Template.Spec.Containers[containerIndex]
		requests := map[string]string{}
		for name, q := range container.Resources.Requests {
			requests[string(name)] = q.String()
		}
		limits := map[string]string{}
		for name, q := range container.Resources.Limits {
			limits[string(name)] = q.String()
		}
		if req.CPULimit != nil {
			limits["cpu"] = *req.CPULimit
		}
		if req.MemLimit != nil {
			limits["memory"] = *req.MemLimit
		}
		ops = append(ops, jsonPatchOp{
			Op:   "add",
			Path: fmt.Sprintf("/spec/template/spec/containers/%d/resources", containerIndex),
			Value: map[string]any{
				"requests": requests,
				"limits":   limits,
			},
		})
	}
	if len(ops) == 0 {
		return types.DeploymentInfo{}, fmt.Errorf("no changes requested")
	}

	payload, err := json.Marshal(ops)
	if err != nil {
		return types.DeploymentInfo{}, err
	}
	patched, err := cs.AppsV1().Deployments(req.Namespace).Patch(ctx, req.Name, k8stypes.JSONPatchType, payload, metav1.PatchOptions{})
	if err != nil {
		return types.DeploymentInfo{}, err
	}
	return deploymentInfo(req.Namespace, patched), nil
}

// --- resource usage (metrics.k8s.io) -----------------------------------------

func pct1(usage, limit float64) *float64 {
	if limit <= 0 {
		return nil
	}
	v := roundTenth(usage / limit * 100)
	return &v
}

func roundTenth(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

func parseCPUMilli(qty string) float64 {
	q, err := resource.ParseQuantity(qty)
	if err != nil {
		return 0
	}
	return float64(q.MilliValue())
}

func parseMemBytes(qty string) float64 {
	q, err := resource.ParseQuantity(qty)
	if err != nil {
		return 0
	}
	return float64(q.Value())
}

func (k *Kube) GetPodResourceUsage(ctx context.Context, pods []types.PodInfo) ([]types.PodResourceUsage, *string) {
	_, mc, err := k.clients()
	if err != nil {
		return []types.PodResourceUsage{}, types.Ptr(err.Error() + " (metrics-server addon 필요)")
	}
	res, err := mc.MetricsV1beta1().PodMetricses(k.Settings.TargetNamespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return []types.PodResourceUsage{}, types.Ptr(err.Error() + " (metrics-server addon 필요)")
	}
	podByName := map[string]types.PodInfo{}
	for _, p := range pods {
		podByName[p.Name] = p
	}
	data := make([]types.PodResourceUsage, 0, len(res.Items))
	for _, pm := range res.Items {
		podInfo, hasInfo := podByName[pm.Name]
		containers := make([]types.ContainerResourceUsage, 0, len(pm.Containers))
		cpuTotal, memTotal := 0.0, 0.0
		cpuLimitTotal, memLimitTotal := 0.0, 0.0
		allCPULimits, allMemLimits := true, true
		for _, cm := range pm.Containers {
			var cpuLimit, memLimit *float64
			if hasInfo {
				for _, c := range podInfo.Containers {
					if c.Name != cm.Name {
						continue
					}
					if c.CPULimit != "" && c.CPULimit != "-" {
						cpuLimit = types.Ptr(parseCPUMilli(c.CPULimit))
					}
					if c.MemLimit != "" && c.MemLimit != "-" {
						memLimit = types.Ptr(parseMemBytes(c.MemLimit))
					}
				}
			}
			cpuQty := cm.Usage[corev1.ResourceCPU]
			memQty := cm.Usage[corev1.ResourceMemory]
			cpuUsage := float64(cpuQty.MilliValue())
			memUsage := float64(memQty.Value())
			usage := types.ContainerResourceUsage{
				Container:     cm.Name,
				CPUUsage:      cpuQty.String(),
				CPUUsageMilli: cpuUsage,
				MemUsage:      memQty.String(),
				MemUsageBytes: memUsage,
				CPULimitMilli: cpuLimit,
				MemLimitBytes: memLimit,
			}
			if cpuLimit != nil {
				usage.CPUPct = pct1(cpuUsage, *cpuLimit)
				cpuLimitTotal += *cpuLimit
			} else {
				allCPULimits = false
			}
			if memLimit != nil {
				usage.MemPct = pct1(memUsage, *memLimit)
				memLimitTotal += *memLimit
			} else {
				allMemLimits = false
			}
			containers = append(containers, usage)
			cpuTotal += cpuUsage
			memTotal += memUsage
		}
		row := types.PodResourceUsage{
			Pod:           pm.Name,
			Containers:    containers,
			CPUUsageMilli: cpuTotal,
			MemUsageBytes: memTotal,
		}
		if allCPULimits && len(containers) > 0 {
			row.CPUPct = pct1(cpuTotal, cpuLimitTotal)
		}
		if allMemLimits && len(containers) > 0 {
			row.MemPct = pct1(memTotal, memLimitTotal)
		}
		data = append(data, row)
	}
	return data, nil
}

// GetNodeResourceUsage fetches its own node listing. Callers that already have
// one for this poll should use GetNodeResourceUsageFrom instead.
func (k *Kube) GetNodeResourceUsage(ctx context.Context) ([]types.NodeResourceUsage, *string) {
	return k.GetNodeResourceUsageFrom(ctx, k.ListNodes(ctx))
}

// GetNodeResourceUsageFrom joins metrics-server's per-node usage against a node
// listing the caller already has.
//
// A failed listing is reported, never swallowed. Continuing with an empty
// capacity map produces rows whose CPUPct and MemPct are both left at zero —
// every node reading 0%, a cluster that looks completely idle — which is
// exactly the wrong thing to show, and shows it without a single word of
// warning.
func (k *Kube) GetNodeResourceUsageFrom(ctx context.Context, listing NodeListing) ([]types.NodeResourceUsage, *string) {
	_, mc, err := k.clients()
	if err != nil {
		return []types.NodeResourceUsage{}, types.Ptr(err.Error() + " (metrics-server addon 필요)")
	}
	if listing.Err != nil {
		return []types.NodeResourceUsage{}, types.Ptr(listing.Err.Error() + " (노드 목록 조회 실패 — 노드별 사용률을 계산할 수 없습니다)")
	}
	metricsRes, err := mc.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return []types.NodeResourceUsage{}, types.Ptr(err.Error() + " (metrics-server addon 필요)")
	}
	data := make([]types.NodeResourceUsage, 0, len(metricsRes.Items))
	for _, nm := range metricsRes.Items {
		nodeCap := listing.Capacity[nm.Name]
		cpuQty := nm.Usage[corev1.ResourceCPU]
		memQty := nm.Usage[corev1.ResourceMemory]
		cpuUsage := float64(cpuQty.MilliValue())
		memUsage := float64(memQty.Value())
		row := types.NodeResourceUsage{
			Name:             nm.Name,
			CPUUsageMilli:    cpuUsage,
			MemUsageBytes:    memUsage,
			CPUCapacityMilli: nodeCap.CPUMilli,
			MemCapacityBytes: nodeCap.MemBytes,
		}
		if nodeCap.CPUMilli > 0 {
			row.CPUPct = roundTenth(cpuUsage / nodeCap.CPUMilli * 100)
		}
		if nodeCap.MemBytes > 0 {
			row.MemPct = roundTenth(memUsage / nodeCap.MemBytes * 100)
		}
		data = append(data, row)
	}
	return data, nil
}

// GetPodScaling reads HPAs; a deployment without one reports its fixed
// replica count.
func (k *Kube) GetPodScaling(ctx context.Context, deployments []types.DeploymentInfo) []types.ScaleInfo {
	type hpaInfo struct {
		target  string
		min     int
		max     int
		current int
	}
	hpas := []hpaInfo{}
	if cs, _, err := k.clients(); err == nil {
		if res, err := cs.AutoscalingV2().HorizontalPodAutoscalers(k.Settings.TargetNamespace()).List(ctx, metav1.ListOptions{}); err == nil {
			for _, h := range res.Items {
				min := 1
				if h.Spec.MinReplicas != nil {
					min = int(*h.Spec.MinReplicas)
				}
				current := int(h.Status.CurrentReplicas)
				if current == 0 {
					current = int(h.Status.DesiredReplicas)
				}
				hpas = append(hpas, hpaInfo{
					target:  h.Spec.ScaleTargetRef.Name,
					min:     min,
					max:     int(h.Spec.MaxReplicas),
					current: current,
				})
			}
		}
	}
	out := make([]types.ScaleInfo, 0, len(deployments))
	for _, d := range deployments {
		var hpa *hpaInfo
		for i := range hpas {
			if hpas[i].target == d.Name {
				hpa = &hpas[i]
				break
			}
		}
		if hpa != nil {
			out = append(out, types.ScaleInfo{
				Name: d.Name, Current: hpa.current,
				Min: types.Ptr(hpa.min), Max: types.Ptr(hpa.max), Source: "HPA",
			})
		} else {
			out = append(out, types.ScaleInfo{
				Name: d.Name, Current: d.Replicas,
				Min: nil, Max: nil, Source: "HPA 없음 (고정 replicas)",
			})
		}
	}
	return out
}

// SummarizePodStatus mirrors resources.ts summarizePodStatus.
func SummarizePodStatus(pods []types.PodInfo) types.PodStatusBreakdown {
	b := types.PodStatusBreakdown{Total: len(pods)}
	for _, p := range pods {
		switch {
		case p.StatusLabel == "CrashLoopBackOff":
			b.CrashLoop++
		case p.StatusLabel == "OOMKilled":
			b.Oom++
		case p.StatusLabel == "Running":
			b.Running++
		case p.StatusLabel == "Pending" || p.StatusLabel == "ContainerCreating" || p.StatusLabel == "PodInitializing":
			b.Pending++
		case p.Phase == "Failed":
			b.Failed++
		default:
			b.Other++
		}
	}
	return b
}
