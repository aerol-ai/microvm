package service

import (
	"testing"
)

// TestSetIngressRouteLagZeroWhenInstalledAhead pins that lag clamps to zero
// when the reconciler has installed a version at-or-beyond what the FSM
// reports. Without this, a stale FSM read could drive lag negative (which
// expvar can't represent) or, worse, flip the sign and confuse an operator
// dashboard that watches "lag > 0 ⇒ falling behind".
func TestSetIngressRouteLagZeroWhenInstalledAhead(t *testing.T) {
	// Reset the gauges this test owns. The expvar package is process-global
	// so tests sharing a binary see each others' state.
	ingressPlacementVersionMax.Set(100)
	ingressRouteLagVersions.Set(-1) // sentinel

	SetIngressRouteLag(50) // FSM behind installed — should clamp to 0.

	if got := ingressRouteLagVersions.Value(); got != 0 {
		t.Fatalf("lag = %d, want 0 when installed (100) >= fsm (50)", got)
	}
}

// TestSetIngressRouteLagComputesDelta pins the steady-state lag computation:
// lag = fsmVersion - installedVersion. Operators read this gauge directly;
// the contract is "N raft applies have not yet hit my ingress routes."
func TestSetIngressRouteLagComputesDelta(t *testing.T) {
	ingressPlacementVersionMax.Set(100)
	SetIngressRouteLag(143)

	if got := ingressRouteLagVersions.Value(); got != 43 {
		t.Fatalf("lag = %d, want 43 (143 - 100)", got)
	}
}

// TestSetIngressRouteLagZeroWhenFSMVersionUnknown pins the boot-window case:
// fsmVersion=0 means "no apply has happened on this node yet" (cold start
// before raft replays). We must publish 0, not "-installedVersion" — which
// could happen if the reconciler had stored a max-version from a previous
// boot (it can't with expvar but the guard is cheap and self-documenting).
func TestSetIngressRouteLagZeroWhenFSMVersionUnknown(t *testing.T) {
	ingressPlacementVersionMax.Set(42)
	SetIngressRouteLag(0)

	if got := ingressRouteLagVersions.Value(); got != 0 {
		t.Fatalf("lag = %d, want 0 when fsmVersion=0", got)
	}
}

// TestRecordRouteMissIncrements pins the route-miss counter contract used by
// pkg/api/v1's clusterForwardWrap. Without this counter monotonic-incrementing,
// operator dashboards have no way to spot "gossip convergence is wedged" —
// individual 503s are noisy at scale and an aggregate counter is the
// canonical signal.
func TestRecordRouteMissIncrements(t *testing.T) {
	before := ingressRouteMissesTotal.Value()
	RecordRouteMiss()
	RecordRouteMiss()
	RecordRouteMiss()
	if got := ingressRouteMissesTotal.Value() - before; got != 3 {
		t.Fatalf("route miss delta = %d, want 3", got)
	}
}
