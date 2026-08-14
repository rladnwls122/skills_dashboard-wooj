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
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/analysis"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

type Kube struct {
	Settings *config.Settings
	Store    *store.Store

	mu      sync.Mutex
	cs      kubernetes.Interface
	metrics metricsclient.Interface
}

func New(settings *config.Settings, st *store.Store) *Kube {
	return &Kube{Settings: settings, Store: st}
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
		return nil, err
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

func (k *Kube) CountReadyNodes(ctx context.Context) (ready, total int, err error) {
	cs, _, err := k.clients()
	if err != nil {
		return 0, 0, err
	}
	res, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, 0, err
	}
	for _, node := range res.Items {
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				ready++
				break
			}
		}
	}
	return ready, len(res.Items), nil
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
		return nil, err
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

var (
	nameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	cpuRe  = regexp.MustCompile(`^\d+m$|^\d+(\.\d+)?$`)
	memRe  = regexp.MustCompile(`^\d+(Mi|Gi|M|G)$`)
)

type PatchRequest struct {
	Namespace     string
	Name          string
	Replicas      *int
	ContainerName *string
	CPULimit      *string
	MemLimit      *string
}

// ValidatePatch rejects before touching the API (spec §22).
func (k *Kube) ValidatePatch(ctx context.Context, req PatchRequest) (types.DeploymentInfo, int, error) {
	if !nameRe.MatchString(req.Namespace) {
		return types.DeploymentInfo{}, -1, fmt.Errorf("invalid namespace: %s", req.Namespace)
	}
	if target := k.Settings.TargetNamespace(); req.Namespace != target {
		return types.DeploymentInfo{}, -1, fmt.Errorf("namespace must be %s", target)
	}
	if !nameRe.MatchString(req.Name) {
		return types.DeploymentInfo{}, -1, fmt.Errorf("invalid deployment name: %s", req.Name)
	}

	deployment, err := k.GetDeployment(ctx, req.Namespace, req.Name)
	if err != nil {
		return types.DeploymentInfo{}, -1, err
	}

	if req.Replicas != nil {
		max := k.Settings.MaxReplicas()
		if *req.Replicas < 0 || *req.Replicas > max {
			return types.DeploymentInfo{}, -1, fmt.Errorf("replicas out of safe range 0..%d", max)
		}
	}

	containerIndex := -1
	if req.CPULimit != nil || req.MemLimit != nil {
		if req.ContainerName == nil || *req.ContainerName == "" {
			return types.DeploymentInfo{}, -1, fmt.Errorf("containerName required for resource change")
		}
		for i, c := range deployment.Containers {
			if c.Name == *req.ContainerName {
				containerIndex = i
				break
			}
		}
		if containerIndex < 0 {
			return types.DeploymentInfo{}, -1, fmt.Errorf("container not found: %s", *req.ContainerName)
		}
		if req.CPULimit != nil && !cpuRe.MatchString(*req.CPULimit) {
			return types.DeploymentInfo{}, -1, fmt.Errorf("invalid CPU quantity: %s (e.g. 500m, 1)", *req.CPULimit)
		}
		if req.MemLimit != nil && !memRe.MatchString(*req.MemLimit) {
			return types.DeploymentInfo{}, -1, fmt.Errorf("invalid memory quantity: %s (e.g. 256Mi, 1Gi)", *req.MemLimit)
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

func (k *Kube) GetNodeResourceUsage(ctx context.Context) ([]types.NodeResourceUsage, *string) {
	cs, mc, err := k.clients()
	if err != nil {
		return []types.NodeResourceUsage{}, types.Ptr(err.Error() + " (metrics-server addon 필요)")
	}
	metricsRes, err := mc.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return []types.NodeResourceUsage{}, types.Ptr(err.Error() + " (metrics-server addon 필요)")
	}
	nodesRes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return []types.NodeResourceUsage{}, types.Ptr(err.Error() + " (metrics-server addon 필요)")
	}
	type capacity struct{ cpuMilli, memBytes float64 }
	capByName := map[string]capacity{}
	for _, n := range nodesRes.Items {
		cpuQty := n.Status.Allocatable[corev1.ResourceCPU]
		memQty := n.Status.Allocatable[corev1.ResourceMemory]
		capByName[n.Name] = capacity{
			cpuMilli: float64(cpuQty.MilliValue()),
			memBytes: float64(memQty.Value()),
		}
	}
	data := make([]types.NodeResourceUsage, 0, len(metricsRes.Items))
	for _, nm := range metricsRes.Items {
		nodeCap := capByName[nm.Name]
		cpuQty := nm.Usage[corev1.ResourceCPU]
		memQty := nm.Usage[corev1.ResourceMemory]
		cpuUsage := float64(cpuQty.MilliValue())
		memUsage := float64(memQty.Value())
		row := types.NodeResourceUsage{
			Name:             nm.Name,
			CPUUsageMilli:    cpuUsage,
			MemUsageBytes:    memUsage,
			CPUCapacityMilli: nodeCap.cpuMilli,
			MemCapacityBytes: nodeCap.memBytes,
		}
		if nodeCap.cpuMilli > 0 {
			row.CPUPct = roundTenth(cpuUsage / nodeCap.cpuMilli * 100)
		}
		if nodeCap.memBytes > 0 {
			row.MemPct = roundTenth(memUsage / nodeCap.memBytes * 100)
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
