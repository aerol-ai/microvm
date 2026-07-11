package cluster

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// refCommandForTest replays the pre-Tier-2 externalize behavior byte-for-byte:
// store the payload as a blob and strip it from the command. This is exactly
// what an old-version emitter produces, so tests built on it double as the
// mixed-version compatibility proof (old emitter → new voter).
func refCommandForTest(t *testing.T, store placementRecoveryStore, cmd command) command {
	t.Helper()
	blob, err := newRecoveryBlob(cmd.SandboxID, placementRecovery{
		Spec:          cmd.Spec,
		SecretRef:     cmd.SecretRef,
		SecretVersion: cmd.SecretVersion,
		SealedSecrets: cloneBytes(cmd.SealedSecrets),
	})
	if err != nil {
		t.Fatalf("newRecoveryBlob: %v", err)
	}
	if ref, err := store.Put(blob.SandboxID, blob.recovery()); err != nil || ref != blob.Ref {
		t.Fatalf("seed blob: ref=%q err=%v, want %q", ref, err, blob.Ref)
	}
	cmd.Name = commandName(cmd)
	cmd.RecoveryRef = blob.Ref
	cmd.Spec = nil
	cmd.SecretRef = ""
	cmd.SecretVersion = 0
	cmd.SealedSecrets = nil
	return cmd
}

// normalizePlacementTimes zeroes the wall-clock fields so placements applied
// in different test runs (or across a second boundary) compare equal.
func normalizePlacementTimes(p Placement) Placement {
	p.CreatedUnix = 0
	p.UpdatedUnix = 0
	return p
}

// TestFSMInlineAndRefPlaceProduceIdenticalState is the Tier 2 determinism
// gate: the same create carried inline vs pre-externalized as a ref must
// materialize identical FSM rows — including the content-addressed
// RecoveryRef, because storePlacementLocked splits an inline payload into the
// voter's local recovery store under the same ref the blob path would use.
func TestFSMInlineAndRefPlaceProduceIdenticalState(t *testing.T) {
	base := command{
		Op:            opPlace,
		SandboxID:     "sb-parity",
		OwnerNodeID:   "node-a",
		OwnerAPIURL:   "http://a",
		Spec:          &models.CreateSandboxRequest{Name: "parity", Image: "alpine:3.20"},
		SecretRef:     "provider-ref",
		SecretVersion: 2,
	}

	inlineFSM := newPlacementFSMWithRecoveryStore(newPlacementRecoveryMemoryStore())
	if got := applyOp(t, inlineFSM, base); got != nil {
		t.Fatalf("inline apply: %v", got)
	}

	refStore := newPlacementRecoveryMemoryStore()
	refFSM := newPlacementFSMWithRecoveryStore(refStore)
	if got := applyOp(t, refFSM, refCommandForTest(t, refStore, base)); got != nil {
		t.Fatalf("ref apply: %v", got)
	}

	a, ok := inlineFSM.get("sb-parity")
	if !ok {
		t.Fatal("inline placement missing")
	}
	b, ok := refFSM.get("sb-parity")
	if !ok {
		t.Fatal("ref placement missing")
	}
	if !reflect.DeepEqual(normalizePlacementTimes(a), normalizePlacementTimes(b)) {
		t.Fatalf("inline vs ref placement diverged:\ninline: %+v\nref:    %+v", a, b)
	}
	if a.RecoveryRef == "" {
		t.Fatal("inline apply did not split payload into the local recovery store")
	}
	// The failover contract: after an inline apply the voter holds the blob
	// locally, same as if the blob mesh had pre-replicated it.
	if _, ok, err := inlineFSM.recoveryStore.Get(a.RecoveryRef); err != nil || !ok {
		t.Fatalf("recovery blob missing locally after inline apply: ok=%v err=%v", ok, err)
	}
}

// TestFSMInlineSpecEnforcesNameUniqueness pins that the cluster-wide name
// index derives from the inline spec (commandName falls back to specName), so
// inline commands get the same duplicate-name rejection as ref commands.
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

// TestFSMReplayMixedInlineAndRefEntries pins the replay contract for a log
// that interleaves inline and ref entries (the steady state of a
// mixed-version cluster): a restarted FSM replaying the same entries against
// the same recovery store converges to identical state.
func TestFSMReplayMixedInlineAndRefEntries(t *testing.T) {
	store := newPlacementRecoveryMemoryStore()
	expiry := time.Now().Add(5 * time.Minute).Unix()
	entries := []command{
		{
			Op: opReserve, SandboxID: "sb-a", OwnerNodeID: "node-a", ExpiresUnix: expiry,
			Spec: &models.CreateSandboxRequest{Name: "a", Image: "alpine:3.20"}, SecretRef: "ra", SecretVersion: 1,
		},
		refCommandForTest(t, store, command{
			Op: opReserve, SandboxID: "sb-b", OwnerNodeID: "node-b", ExpiresUnix: expiry,
			Spec: oversizedSpec("b"),
		}),
		// Promotes carry no payload — the realistic RecordPlacement-after-
		// reserve shape; the spec must be preserved from the reservation row.
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
	if b1.State != PlacementStatePlaced || b1.Spec == nil || len(b1.Spec.Image) <= inlineRecoveryMaxBytes {
		t.Fatalf("ref-reserved spec not preserved through promote: %+v", b1)
	}
}

// TestFSMThresholdCrossingReserveAndPlaceConverge pins the §5 edge: a
// sandbox whose payload crosses inlineRecoveryMaxBytes between reserve and
// place (or the reverse) still converges — both shapes are valid per-command.
func TestFSMThresholdCrossingReserveAndPlaceConverge(t *testing.T) {
	store := newPlacementRecoveryMemoryStore()
	fsm := newPlacementFSMWithRecoveryStore(store)
	expiry := time.Now().Add(5 * time.Minute).Unix()

	// Inline reserve → ref place.
	if got := applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-x", OwnerNodeID: "node-a", ExpiresUnix: expiry,
		Spec: &models.CreateSandboxRequest{Name: "cross-x", Image: "alpine:3.20"},
	}); got != nil {
		t.Fatalf("inline reserve: %v", got)
	}
	if got := applyOp(t, fsm, refCommandForTest(t, store, command{
		Op: opPlace, SandboxID: "sb-x", OwnerNodeID: "node-a",
		Spec: oversizedSpec("cross-x"),
	})); got != nil {
		t.Fatalf("ref place: %v", got)
	}
	if p, _ := fsm.get("sb-x"); p.State != PlacementStatePlaced || p.Spec == nil || len(p.Spec.Image) <= inlineRecoveryMaxBytes {
		t.Fatalf("inline→ref crossing did not converge on the placed spec: %+v", p)
	}

	// Ref reserve → inline place.
	if got := applyOp(t, fsm, refCommandForTest(t, store, command{
		Op: opReserve, SandboxID: "sb-y", OwnerNodeID: "node-b", ExpiresUnix: expiry,
		Spec: oversizedSpec("cross-y"),
	})); got != nil {
		t.Fatalf("ref reserve: %v", got)
	}
	if got := applyOp(t, fsm, command{
		Op: opPlace, SandboxID: "sb-y", OwnerNodeID: "node-b",
		Spec: &models.CreateSandboxRequest{Name: "cross-y", Image: "alpine:3.20"},
	}); got != nil {
		t.Fatalf("inline place: %v", got)
	}
	if p, _ := fsm.get("sb-y"); p.State != PlacementStatePlaced || p.Spec == nil || p.Spec.Image != "alpine:3.20" {
		t.Fatalf("ref→inline crossing did not converge on the placed spec: %+v", p)
	}
}
