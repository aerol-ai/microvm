package containerd

import (
	"errors"
	"fmt"
)

// validateSandboxID restricts the sandbox ID to a filesystem-safe charset
// before it is used to build host paths (per-sandbox host-file dir, task log).
// Defense in depth against path traversal: the ID can arrive attacker-
// controlled via the X-Cluster-Create-ID header, and host writes happen before
// containerd's own ID validation. Mirrors pkg/docker/readysock.go and
// internal/runtime/firecracker's validators.
func validateSandboxID(id string) error {
	if id == "" {
		return errors.New("sandbox ID is required")
	}
	if len(id) > 128 {
		return fmt.Errorf("sandbox ID exceeds 128 chars (%d)", len(id))
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return fmt.Errorf("invalid character %q in sandbox ID %q", r, id)
		}
	}
	return nil
}
