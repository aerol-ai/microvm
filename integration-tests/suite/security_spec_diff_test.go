//go:build integration

package suite

import (
	"os"
	"testing"
)

// TestSecuritySpecDiff is the permanent cross-engine security-parity contract
// from plans/containerd-engine.md §6/§8: create the SAME minimal sandbox under
// both engines on a host where both are available, exec a probe that prints
// /proc/self/status (CapEff, NoNewPrivs, Seccomp) plus mountinfo for the masked
// paths, and FAIL if the containerd spec is strictly weaker than dockerd's.
//
// It is intentionally gated: the offline regression net for the security
// envelope lives in internal/runtime/containerd (TestSecuritySpecOptsEnvelope),
// which asserts the assembled OCI spec carries seccomp / NoNewPrivileges / the
// masked-path list / the capped capability set. This integration test is the
// belt-and-suspenders on-host contract and requires:
//   - a host running BOTH dockerd and native containerd (coexistence topology),
//   - Phase 2 container networking so a containerd sandbox can actually boot
//     and be exec'd into.
//
// Until the two-engine bench topology exists it skips rather than asserts, so
// the file compiles under the `integration` tag and documents the contract.
func TestSecuritySpecDiff(t *testing.T) {
	if os.Getenv("AEROL_SPEC_DIFF_DUAL_ENGINE") == "" {
		t.Skip("spec-diff parity contract requires a dual-engine (dockerd+containerd) host; set AEROL_SPEC_DIFF_DUAL_ENGINE=1 on the coexistence bench topology (plans/containerd-engine.md §8)")
	}
	t.Fatal("dual-engine spec-diff harness not yet implemented; see plans/containerd-engine.md §6 Phase 1 / §8 gate")
}
