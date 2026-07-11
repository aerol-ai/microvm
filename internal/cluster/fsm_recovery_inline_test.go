package cluster

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// normalizePlacementTimes zeroes the wall-clock fields so placements applied
// in different test runs (or across a second boundary) compare equal.
func normalizePlacementTimes(p Placement) Placement {
	p.CreatedUnix = 0
	p.UpdatedUnix = 0
	return p
}

// TestFSMInlinePlaceSplitsPayloadToLocalStore pins the failover contract for
// inline commands (the only kind that exists): applying an opPlace splits the
// payload into the voter's LOCAL recovery store under a content-addressed
// ref, so a later failover recreate reads it locally without any peer traffic.
func TestFSMInlinePlaceSplitsPayloadToLocalStore(t *testing.T) {
	fsm := newPlacementFSMWithRecoveryStore(newPlacementRecoveryMemoryStore())
	if got := applyOp(t, fsm, command{
		Op:            opPlace,
		SandboxID:     "sb-split",
		OwnerNodeID:   "node-a",
		OwnerAPIURL:   "http://a",
		Spec:          &models.CreateSandboxRequest{Name: "split", Image: "alpine:3.20"},
		SecretRef:     "provider-ref",
		SecretVersion: 2,
	}); got != nil {
		t.Fatalf("apply: %v", got)
	}
	p, ok := fsm.get("sb-split")
	if !ok {
		t.Fatal("placement missing")
	}
	if p.RecoveryRef == "" {
		t.Fatal("inline apply did not split payload into the local recovery store")
	}
	rec, ok, err := fsm.recoveryStore.Get(p.RecoveryRef)
	if err != nil || !ok {
		t.Fatalf("recovery payload missing locally after inline apply: ok=%v err=%v", ok, err)
	}
	if rec.Spec == nil || rec.Spec.Image != "alpine:3.20" || rec.SecretRef != "provider-ref" || rec.SecretVersion != 2 {
		t.Fatalf("stored recovery payload diverged from the command: %+v", rec)
	}
}

// TestFSMInlineSpecEnforcesNameUniqueness pins that the cluster-wide name
// index derives from the inline spec, so duplicate names are rejected at the
// FSM regardless of which node emitted the create.
func TestFSMInlineSpecEnforcesNameUniqueness(t *testing.T) {
	fsm := newPlacementFSMWithRecoveryStore(newPlacementRecoveryMemoryStore())
	if got := applyOp(t, fsm, command{
		Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "node-a",
		Spec: &models.CreateSandboxRequest{Name: "uniq", Image: "alpine"},
	}); got != nil {
		t.Fatalf("first place: %v", got)
	}
	got := applyOp(t, fsm, command{
		Op: opPlace, SandboxID: "sb-2", OwnerNodeID: "node-b",
		Spec: &models.CreateSandboxRequest{Name: "uniq", Image: "alpine"},
	})
	err, ok := got.(error)
	if !ok || !errors.Is(err, ErrNameConflict) {
		t.Fatalf("duplicate name via inline spec = %v, want ErrNameConflict", got)
	}
}

// TestFSMReplayInlineEntries pins the replay contract: a restarted FSM
// replaying the same inline entries against the same recovery store converges
// to identical state, and a payload-free promote (the realistic
// RecordPlacement-after-reserve shape) preserves the reservation's spec.
func TestFSMReplayInlineEntries(t *testing.T) {
	store := newPlacementRecoveryMemoryStore()
	expiry := time.Now().Add(5 * time.Minute).Unix()
	entries := []command{
		{
			Op: opReserve, SandboxID: "sb-a", OwnerNodeID: "node-a", ExpiresUnix: expiry,
			Spec: &models.CreateSandboxRequest{Name: "a", Image: "alpine:3.20"}, SecretRef: "ra", SecretVersion: 1,
		},
		{
			Op: opReserve, SandboxID: "sb-b", OwnerNodeID: "node-b", ExpiresUnix: expiry,
			Spec: &models.CreateSandboxRequest{Name: "b", Image: "debian:12"},
		},
		{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "node-a"},
		{Op: opPlace, SandboxID: "sb-b", OwnerNodeID: "node-b"},
	}

	replay := func() (Placement, Placement) {
		fsm := newPlacementFSMWithRecoveryStore(store)
		for i, cmd := range entries {
			if got := applyOp(t, fsm, cmd); got != nil {
				t.Fatalf("entry %d apply: %v", i, got)
			}
		}
		a, ok := fsm.get("sb-a")
		if !ok {
			t.Fatal("sb-a missing")
		}
		b, ok := fsm.get("sb-b")
		if !ok {
			t.Fatal("sb-b missing")
		}
		return a, b
	}

	a1, b1 := replay()
	a2, b2 := replay() // restart: fresh FSM, same store, same log

	if !reflect.DeepEqual(normalizePlacementTimes(a1), normalizePlacementTimes(a2)) {
		t.Fatalf("sb-a diverged across replay:\nfirst:  %+v\nsecond: %+v", a1, a2)
	}
	if !reflect.DeepEqual(normalizePlacementTimes(b1), normalizePlacementTimes(b2)) {
		t.Fatalf("sb-b diverged across replay:\nfirst:  %+v\nsecond: %+v", b1, b2)
	}
	if a1.State != PlacementStatePlaced || a1.Spec == nil || a1.Spec.Image != "alpine:3.20" {
		t.Fatalf("inline-reserved spec not preserved through promote: %+v", a1)
	}
	if a1.SecretRef != "ra" || a1.SecretVersion != 1 {
		t.Fatalf("secret handle not preserved through promote: %+v", a1)
	}
	if b1.State != PlacementStatePlaced || b1.Spec == nil || b1.Spec.Image != "debian:12" {
		t.Fatalf("sb-b spec not preserved through promote: %+v", b1)
	}
}
