package containerd

import "github.com/aerol-ai/microvm/internal/rootpolicy"

// validateSandboxID restricts the sandbox ID to a filesystem-safe charset
// before it is used to build host paths (per-sandbox host-file dir, task log).
// Defense in depth against path traversal: the ID can arrive attacker-
// controlled via the X-Cluster-Create-ID header, and host writes happen before
// containerd's own ID validation. Mirrors pkg/docker/readysock.go and
// internal/runtime/firecracker's validators. The rule is rootpolicy's, the
// same one the root helper's gate applies to container and cgroup names.
func validateSandboxID(id string) error {
	return rootpolicy.ValidateID(id)
}
