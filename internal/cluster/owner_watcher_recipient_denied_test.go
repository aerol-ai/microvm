package cluster

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// TestOwnerWatcherStopsReassignOnRecipientDenied pins outside-voice #7:
// a recipient-denied open must not walk the fleet via reassign-after-K-failures.
func TestOwnerWatcherStopsReassignOnRecipientDenied(t *testing.T) {
	recreator := newRecordingRecreator()
	recreator.setOutcome(true, secrets.ErrRecipientDenied)

	fsm := newPlacementFSM()
	c := &Cluster{
		nodeID: "node-denied",
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		recreateFailures: &recreateFailureTracker{
			counts:    make(map[string]int),
			permanent: make(map[string]struct{}),
		},
		fsm: fsm,
	}
	c.AttachRecreator(recreator)

	spec := &models.CreateSandboxRequest{
		Image:    "alpine",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	p := Placement{
		SandboxID:   "sb-denied",
		OwnerNodeID: "node-denied",
		Spec:        spec,
		State:       PlacementStatePlaced,
	}
	fsm.mu.Lock()
	if err := fsm.storePlacementLocked("sb-denied", p); err != nil {
		fsm.mu.Unlock()
		t.Fatalf("storePlacementLocked: %v", err)
	}
	fsm.claimOwnerLocked("sb-denied", p)
	fsm.mu.Unlock()

	c.recreateOwnedSandboxes(context.Background())
	if !c.recreateFailures.isPermanent("sb-denied") {
		t.Fatal("expected permanent failure after recipient denied")
	}
	if _, ok := recreator.get("sb-denied"); !ok {
		t.Fatal("expected one recreate attempt before permanent mark")
	}

	// Subsequent ticks must skip entirely — no reassign churn.
	before := len(recreator.calls)
	for i := 0; i < maxRecreateFailuresBeforeReassign+2; i++ {
		c.recreateOwnedSandboxes(context.Background())
	}
	recreator.mu.Lock()
	after := len(recreator.calls)
	recreator.mu.Unlock()
	if after != before {
		t.Fatalf("recreate calls grew from %d to %d after permanent mark", before, after)
	}
}
