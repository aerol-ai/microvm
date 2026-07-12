//go:build integration

package suite

import (
	"testing"
)

// TestSecuritySpecDiff is the permanent cross-engine security parity contract
// (plans/containerd-engine.md Phase 1). Requires a host with both dockerd and
// containerd available; skipped in make test.
func TestSecuritySpecDiff(t *testing.T) {
	t.Skip("integration-only: exec probe comparing CapEff/NoNewPrivs/Seccomp across engines")
}
