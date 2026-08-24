package config

// The cluster-free half of deployment-patch validation (spec §22), in one
// place.
//
// It used to live twice: internal/service/service.go validated the namespace,
// the name and the replica count, and internal/kube/kube.go validated those
// again plus the container name and the CPU/memory quantity formats. The
// preview path ran the weaker copy, so the confirm screen happily accepted
// cpuLimit="500" or memLimit="256M B" and the operator only found out when the
// apply — the copy that checks — rejected it, after they had committed to the
// change. Under match conditions that is the worst possible moment to discover
// a typo.
//
// It lives in config rather than in either caller because config is what both
// of them already import and because every limit these rules read
// (TARGET_NAMESPACE, MAX_REPLICAS) is a setting. Anything that needs the
// cluster — does this deployment exist, does it have a container by that name —
// stays in kube, which is the only layer that can answer it.

import (
	"fmt"
	"regexp"
)

var (
	// RFC 1123 label: what Kubernetes accepts as a namespace or object name.
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	// "500m" or "1" / "1.5" — the two forms the console and kubectl print.
	cpuQuantityPattern = regexp.MustCompile(`^\d+m$|^\d+(\.\d+)?$`)
	memQuantityPattern = regexp.MustCompile(`^\d+(Mi|Gi|M|G)$`)
)

// DeploymentPatchFields is the request as far as it can be judged without
// talking to the API server.
type DeploymentPatchFields struct {
	Namespace     string
	Name          string
	Replicas      *int
	ContainerName *string
	CPULimit      *string
	MemLimit      *string
}

// ValidateDeploymentPatch returns the first reason the patch may not be sent.
// The error strings are English on purpose: they are the same strings the HTTP
// layer's tests assert on and the same ones the apply path has always returned.
func (s *Settings) ValidateDeploymentPatch(fields DeploymentPatchFields) error {
	if !dnsLabelPattern.MatchString(fields.Namespace) {
		return fmt.Errorf("invalid namespace: %s", fields.Namespace)
	}
	// The namespace is pinned, not merely well-formed: this dashboard may only
	// touch the workload it was pointed at.
	if target := s.TargetNamespace(); fields.Namespace != target {
		return fmt.Errorf("namespace must be %s", target)
	}
	if !dnsLabelPattern.MatchString(fields.Name) {
		return fmt.Errorf("invalid deployment name: %s", fields.Name)
	}
	if fields.Replicas != nil {
		max := s.MaxReplicas()
		if *fields.Replicas < 0 || *fields.Replicas > max {
			return fmt.Errorf("replicas out of safe range 0..%d: %d", max, *fields.Replicas)
		}
	}
	if fields.CPULimit != nil || fields.MemLimit != nil {
		if fields.ContainerName == nil || *fields.ContainerName == "" {
			return fmt.Errorf("containerName required for resource change")
		}
		if fields.CPULimit != nil && !cpuQuantityPattern.MatchString(*fields.CPULimit) {
			return fmt.Errorf("invalid CPU quantity: %s (e.g. 500m, 1)", *fields.CPULimit)
		}
		if fields.MemLimit != nil && !memQuantityPattern.MatchString(*fields.MemLimit) {
			return fmt.Errorf("invalid memory quantity: %s (e.g. 256Mi, 1Gi)", *fields.MemLimit)
		}
	}
	return nil
}
