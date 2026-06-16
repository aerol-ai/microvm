// Package validate mirrors Terraform locals.tf node-arch derivation and the
// homogeneous-cluster precondition so mixed-arch tfvars fail in offline tests
// without a live AWS plan.
package validate

import (
	"regexp"
	"strings"
)

// gravitonInstanceRE matches AWS Graviton instance families (see locals.tf).
var gravitonInstanceRE = regexp.MustCompile(`([a-z][0-9]+g|a1|t4g)\.`)

// NodeArch returns amd64 or arm64 from an explicit arch field or instance type.
func NodeArch(explicit, instanceType string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return explicit
	}
	if gravitonInstanceRE.MatchString(instanceType) {
		return "arm64"
	}
	return "amd64"
}

// FirecrackerUpstreamArch maps cluster arch to Firecracker release bucket arch.
func FirecrackerUpstreamArch(clusterArch string) string {
	if clusterArch == "arm64" {
		return "aarch64"
	}
	return "x86_64"
}

// HomogeneousClusterArch returns the single arch when all nodes agree, or "".
func HomogeneousClusterArch(nodeArch map[string]string) string {
	if len(nodeArch) == 0 {
		return "amd64"
	}
	var distinct []string
	seen := map[string]bool{}
	for _, arch := range nodeArch {
		if seen[arch] {
			continue
		}
		seen[arch] = true
		distinct = append(distinct, arch)
	}
	if len(distinct) != 1 {
		return ""
	}
	return distinct[0]
}
