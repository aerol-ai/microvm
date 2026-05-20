package cluster

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// applyOp is a helper that encodes + applies one command and returns the
// Apply result (nil on success, error otherwise). Mirrors the pattern in
// fsm_test.go but folds the encode + assert noise into one line so the
// reservation tests stay focused on state transitions.
func applyOp(t *testing.T, fsm *placementFSM, cmd command) any {
	t.Helper()
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return fsm.Apply(&raft.Log{Data: payload})
}

// TestFSMReserveWritesReservedState pins the basic write contract: a fresh
// opReserve creates a Placement with State=Reserved, ExpiresUnix populated,
// and the redacted spec + sealed secrets carried in the command preserved.
// Without this, the promote step (opPlace with nil Spec) would have nothing
// to inherit and we'd silently lose the create payload.
func TestFSMReserveWritesReservedState(t *testing.T) {
	fsm := newPlacementFSM()
	expiry := time.Now().Add(120 * time.Second).Unix()
	spec := &models.CreateSandboxRequest{Image: "alpine", Name: "demo", CPU: 2, MemoryMB: 1024}
	sealed := []byte("sealed-bag")

	if got := applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", OwnerAPIURL: "http://b",
		Spec: spec, SealedSecrets: sealed, ExpiresUnix: expiry,
	}); got != nil {
		t.Fatalf("opReserve returned %v, want nil", got)
	}

	p, ok := fsm.get("sb1")
	if !ok {
		t.Fatal("expected reservation row")
	}
	if !p.IsReserved() {
		t.Fatalf("State = %q, want %q", p.State, PlacementStateReserved)
	}
	if p.ExpiresUnix != expiry {
		t.Fatalf("ExpiresUnix = %d, want %d", p.ExpiresUnix, expiry)
	}
	if p.OwnerNodeID != "B" {
		t.Fatalf("OwnerNodeID = %q, want B", p.OwnerNodeID)
	}
	if p.Spec == nil || p.Spec.Image != "alpine" {
		t.Fatalf("Spec = %+v, want preserved alpine spec", p.Spec)
	}
	if string(p.SealedSecrets) != "sealed-bag" {
		t.Fatalf("SealedSecrets = %q, want sealed-bag", string(p.SealedSecrets))
	}
	pending := fsm.pendingReservationsByNode(time.Now().Unix())
	if got := pending["B"]; got.CPU != 2 || got.MemoryMB != 1024 {
		t.Fatalf("pending capacity for B = %+v, want CPU=2 MemoryMB=1024", got)
	}
}

// TestFSMReserveIdempotentRefreshesExpiry pins the retry contract: a
// re-reserve from the same owner before the original expires must succeed
// and bump ExpiresUnix to the new value. Without this, a router that retries
// a forward (e.g. transient network blip) would either get spurious 409s or
// keep the stale shorter TTL — both leak headroom.
func TestFSMReserveIdempotentRefreshesExpiry(t *testing.T) {
	fsm := newPlacementFSM()
	first := time.Now().Add(60 * time.Second).Unix()
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", ExpiresUnix: first})

	later := time.Now().Add(120 * time.Second).Unix()
	if got := applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", ExpiresUnix: later}); got != nil {
		t.Fatalf("re-reserve returned %v, want nil", got)
	}

	p, _ := fsm.get("sb1")
	if p.ExpiresUnix != later {
		t.Fatalf("ExpiresUnix = %d, want refreshed to %d", p.ExpiresUnix, later)
	}
	if !p.IsReserved() {
		t.Fatalf("State = %q, want still reserved", p.State)
	}
}

// TestFSMReserveRejectsPlacedRow pins the safety property the router relies
// on: once a sandbox is Placed, no router can race in and reserve over it.
// A stale router whose SelectPlacement view points at a sandbox that has
// already completed must see ErrReservationConflict, not silently overwrite.
func TestFSMReserveRejectsPlacedRow(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A"})

	got := applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", ExpiresUnix: time.Now().Add(60 * time.Second).Unix()})
	err, ok := got.(error)
	if !ok || !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("opReserve over placed row = %v, want ErrReservationConflict", got)
	}
}

// TestFSMReserveRejectsLiveReservationByDifferentOwner pins the cluster-wide
// mutual exclusion the reservation flow gives us: two routers that both pick
// the same sandbox ID + different owners can't both succeed, even before
// either reaches the promote step.
func TestFSMReserveRejectsLiveReservationByDifferentOwner(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", ExpiresUnix: time.Now().Add(60 * time.Second).Unix()})

	got := applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "C", ExpiresUnix: time.Now().Add(60 * time.Second).Unix()})
	err, ok := got.(error)
	if !ok || !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("opReserve by different owner = %v, want ErrReservationConflict", got)
	}
}

// TestFSMReserveOverwritesExpiredReservation pins the GC race-resolution
// contract: an opReserve that arrives after the previous reservation's TTL
// elapsed (but before the GC sweep cancelled it) must be allowed to overwrite,
// otherwise stuck reservations would deny placements until the next GC tick.
func TestFSMReserveOverwritesExpiredReservation(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", ExpiresUnix: time.Now().Add(-time.Second).Unix()})

	freshExpiry := time.Now().Add(120 * time.Second).Unix()
	if got := applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "C", ExpiresUnix: freshExpiry}); got != nil {
		t.Fatalf("opReserve over expired reservation = %v, want nil", got)
	}

	p, _ := fsm.get("sb1")
	if p.OwnerNodeID != "C" {
		t.Fatalf("OwnerNodeID = %q, want C (expired reservation should be overwritten)", p.OwnerNodeID)
	}
	if p.ExpiresUnix != freshExpiry {
		t.Fatalf("ExpiresUnix = %d, want %d", p.ExpiresUnix, freshExpiry)
	}
}

// TestFSMReserveRejectsNameCollision pins B10's name-uniqueness invariant for
// the reservation path: two reservations with the same Name on different
// sandbox IDs must conflict at reservation time, before any docker side
// effect. Without this, the conflict would only surface at promote time —
// after both targets had already pulled images and possibly raced into
// docker create.
func TestFSMReserveRejectsNameCollision(t *testing.T) {
	fsm := newPlacementFSM()
	first := &models.CreateSandboxRequest{Name: "duplicate"}
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", Spec: first, ExpiresUnix: time.Now().Add(60 * time.Second).Unix()})

	second := &models.CreateSandboxRequest{Name: "duplicate"}
	got := applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb2", OwnerNodeID: "C", Spec: second, ExpiresUnix: time.Now().Add(60 * time.Second).Unix()})
	err, ok := got.(error)
	if !ok || !errors.Is(err, ErrNameConflict) {
		t.Fatalf("opReserve with duplicate Name = %v, want ErrNameConflict", got)
	}
}

func TestFSMReserveBatchWritesReservationsAtomically(t *testing.T) {
	fsm := newPlacementFSM()
	expiry := time.Now().Add(60 * time.Second).Unix()
	got := applyOp(t, fsm, command{
		Op: opReserveBatch,
		Reservations: []reservationCommand{
			{SandboxID: "sb-batch-1", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{Name: "batch-a", CPU: 1}, ExpiresUnix: expiry},
			{SandboxID: "sb-batch-2", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{Name: "batch-b", CPU: 2}, ExpiresUnix: expiry},
		},
	})
	if got != nil {
		t.Fatalf("opReserveBatch returned %v, want nil", got)
	}
	if p, ok := fsm.get("sb-batch-1"); !ok || !p.IsReserved() || p.OwnerNodeID != "worker-a" {
		t.Fatalf("sb-batch-1 = %+v ok=%v, want reserved on worker-a", p, ok)
	}
	if p, ok := fsm.get("sb-batch-2"); !ok || !p.IsReserved() || p.OwnerNodeID != "worker-a" {
		t.Fatalf("sb-batch-2 = %+v ok=%v, want reserved on worker-a", p, ok)
	}
	if got := fsm.pendingReservationsByNode(time.Now().Unix())["worker-a"].CPU; got != 3 {
		t.Fatalf("pending CPU after batch = %v, want 3", got)
	}
}

func TestFSMReserveBatchRejectsDuplicateNameWithoutPartialWrite(t *testing.T) {
	fsm := newPlacementFSM()
	expiry := time.Now().Add(60 * time.Second).Unix()
	got := applyOp(t, fsm, command{
		Op: opReserveBatch,
		Reservations: []reservationCommand{
			{SandboxID: "sb-batch-1", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{Name: "same"}, ExpiresUnix: expiry},
			{SandboxID: "sb-batch-2", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{Name: "same"}, ExpiresUnix: expiry},
		},
	})
	err, ok := got.(error)
	if !ok || !errors.Is(err, ErrNameConflict) {
		t.Fatalf("opReserveBatch duplicate name = %v, want ErrNameConflict", got)
	}
	if _, ok := fsm.get("sb-batch-1"); ok {
		t.Fatal("first batch row was written despite duplicate-name rejection")
	}
	if _, ok := fsm.get("sb-batch-2"); ok {
		t.Fatal("second batch row was written despite duplicate-name rejection")
	}
}

// TestFSMPlacePromotesReservationInheritsSpec pins the central invariant of
// the reservation→placed transition: opPlace with nil Spec/SealedSecrets must
// (a) clear State and ExpiresUnix and (b) preserve the Spec + SealedSecrets
// the reservation step replicated. This is the property that lets the
// router-side reserve avoid duplicating the payload on the wire when the
// target promotes.
func TestFSMPlacePromotesReservationInheritsSpec(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Image: "alpine", Name: "demo"}
	sealed := []byte("sealed-bag")
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B",
		Spec: spec, SealedSecrets: sealed,
		ExpiresUnix: time.Now().Add(60 * time.Second).Unix(),
	})

	if got := applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "B"}); got != nil {
		t.Fatalf("opPlace promote = %v, want nil", got)
	}

	p, _ := fsm.get("sb1")
	if p.IsReserved() {
		t.Fatalf("State = %q, want placed after promote", p.State)
	}
	if p.ExpiresUnix != 0 {
		t.Fatalf("ExpiresUnix = %d, want cleared after promote", p.ExpiresUnix)
	}
	if p.Spec == nil || p.Spec.Image != "alpine" {
		t.Fatalf("Spec = %+v, want inherited from reservation", p.Spec)
	}
	if string(p.SealedSecrets) != "sealed-bag" {
		t.Fatalf("SealedSecrets lost during promote: %q", string(p.SealedSecrets))
	}
}

func TestFSMPlacePromotesReservationInheritsSecretRef(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Image: "alpine", Name: "demo-ref"}
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-ref", OwnerNodeID: "B",
		Spec:          spec,
		SecretRef:     "cluster-secret://sandbox/sb-ref/v1",
		SecretVersion: 1,
		SealedSecrets: []byte("must-not-enter-reservation"),
		ExpiresUnix:   time.Now().Add(60 * time.Second).Unix(),
	})
	reserved, _ := fsm.get("sb-ref")
	if reserved.SecretRef != "cluster-secret://sandbox/sb-ref/v1" || reserved.SecretVersion != 1 {
		t.Fatalf("reservation secret handle = (%q,%d)", reserved.SecretRef, reserved.SecretVersion)
	}
	if len(reserved.SealedSecrets) != 0 {
		t.Fatalf("reservation stored legacy sealed payload with ref: %q", string(reserved.SealedSecrets))
	}

	if got := applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-ref", OwnerNodeID: "B"}); got != nil {
		t.Fatalf("opPlace promote = %v, want nil", got)
	}

	p, _ := fsm.get("sb-ref")
	if p.IsReserved() {
		t.Fatalf("State = %q, want placed after promote", p.State)
	}
	if p.SecretRef != "cluster-secret://sandbox/sb-ref/v1" || p.SecretVersion != 1 {
		t.Fatalf("promoted secret handle = (%q,%d)", p.SecretRef, p.SecretVersion)
	}
	if len(p.SealedSecrets) != 0 {
		t.Fatalf("promote stored legacy sealed payload with ref: %q", string(p.SealedSecrets))
	}
}

// TestFSMCancelReserveRemovesReservedRow pins the rollback contract: opCancel
// removes a Reserved row entirely, freeing both the slot and the name index
// claim so a retry with the same Name can succeed.
func TestFSMCancelReserveRemovesReservedRow(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Name: "demo"}
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", Spec: spec, ExpiresUnix: time.Now().Add(60 * time.Second).Unix()})

	if got := applyOp(t, fsm, command{Op: opCancelReserve, SandboxID: "sb1"}); got != nil {
		t.Fatalf("opCancelReserve = %v, want nil", got)
	}

	if _, ok := fsm.get("sb1"); ok {
		t.Fatal("reservation should be gone after cancel")
	}
	// Name index should be free — a fresh reservation with the same Name on a
	// different sandbox ID must succeed.
	if got := applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb2", OwnerNodeID: "C", Spec: &models.CreateSandboxRequest{Name: "demo"}, ExpiresUnix: time.Now().Add(60 * time.Second).Unix()}); got != nil {
		t.Fatalf("re-reserve under same Name after cancel = %v, want nil (name should be released)", got)
	}
}

// TestFSMCancelReserveNoOpOnPlacedRow pins the safety property the router
// relies on for rollback: a stale opCancelReserve that arrives after the
// target successfully promoted MUST NOT delete the placed row. Without this,
// a network-retry race would silently destroy a working sandbox's FSM entry.
func TestFSMCancelReserveNoOpOnPlacedRow(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A"})

	if got := applyOp(t, fsm, command{Op: opCancelReserve, SandboxID: "sb1"}); got != nil {
		t.Fatalf("opCancelReserve on placed row = %v, want nil (no-op)", got)
	}

	p, ok := fsm.get("sb1")
	if !ok {
		t.Fatal("placed row was destroyed by stale cancel — must be preserved")
	}
	if p.IsReserved() {
		t.Fatalf("State = %q, want placed (cancel must not flip state)", p.State)
	}
}

// TestFSMCancelReserveNoOpOnMissingRow pins the idempotency guarantee: cancel
// on a row that never existed (TTL GC racing a successful promote that
// already deleted, etc) must be a clean no-op.
func TestFSMCancelReserveNoOpOnMissingRow(t *testing.T) {
	fsm := newPlacementFSM()
	if got := applyOp(t, fsm, command{Op: opCancelReserve, SandboxID: "sb-missing"}); got != nil {
		t.Fatalf("opCancelReserve on missing row = %v, want nil", got)
	}
}

// TestFSMSnapshotRoundTripPreservesReservedState pins back-compat with the
// raft snapshot envelope: a Reserved row's State and ExpiresUnix must survive
// Snapshot → Restore exactly. Without this, a leader cold-restart would lose
// every in-flight reservation and silently allow double-booking immediately
// after recovery.
func TestFSMSnapshotRoundTripPreservesReservedState(t *testing.T) {
	src := newPlacementFSM()
	expiry := time.Now().Add(120 * time.Second).Unix()
	applyOp(t, src, command{
		Op: opReserve, SandboxID: "sb-r", OwnerNodeID: "B",
		Spec:          &models.CreateSandboxRequest{Image: "alpine", Name: "named-reservation"},
		SealedSecrets: []byte("sealed"),
		ExpiresUnix:   expiry,
	})
	applyOp(t, src, command{Op: opPlace, SandboxID: "sb-p", OwnerNodeID: "A"})

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}

	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, ok := dst.get("sb-r")
	if !ok {
		t.Fatal("reserved row missing after restore")
	}
	if !got.IsReserved() {
		t.Fatalf("State after restore = %q, want reserved", got.State)
	}
	if got.ExpiresUnix != expiry {
		t.Fatalf("ExpiresUnix after restore = %d, want %d", got.ExpiresUnix, expiry)
	}
	pending := dst.pendingReservationsByNode(time.Now().Unix())
	if got := pending["B"]; got.CPU != models.DefaultCPU || got.MemoryMB != models.DefaultMemoryMB {
		t.Fatalf("restored pending capacity for B = %+v, want default request from reserved spec", got)
	}
	if got.Spec == nil || got.Spec.Name != "named-reservation" {
		t.Fatalf("Spec lost during restore: %+v", got.Spec)
	}
	if string(got.SealedSecrets) != "sealed" {
		t.Fatalf("SealedSecrets lost during restore: %q", string(got.SealedSecrets))
	}
	// Placed row alongside it must restore as Placed (zero-value State), not
	// accidentally promoted-to-reserved by a back-compat shim.
	placed, _ := dst.get("sb-p")
	if placed.IsReserved() {
		t.Fatalf("placed row restored as reserved: %+v", placed)
	}
}

// TestFSMPendingReservationsByNodeSumsAndExcludesExpired pins the input the
// reservation-aware SelectPlacement reads: the map sums per-owner capacity
// across every live reservation and excludes expired ones (so the GC race
// can't double-count headroom that's about to be reclaimed).
func TestFSMPendingReservationsByNodeSumsAndExcludesExpired(t *testing.T) {
	fsm := newPlacementFSM()
	now := time.Now()

	live1 := &models.CreateSandboxRequest{CPU: 2, MemoryMB: 1024, DiskGB: 10}
	live2 := &models.CreateSandboxRequest{CPU: 1, MemoryMB: 512, DiskGB: 5}
	expired := &models.CreateSandboxRequest{CPU: 8, MemoryMB: 8192, DiskGB: 100}

	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", Spec: live1, ExpiresUnix: now.Add(60 * time.Second).Unix()})
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb2", OwnerNodeID: "B", Spec: live2, ExpiresUnix: now.Add(60 * time.Second).Unix()})
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb3", OwnerNodeID: "B", Spec: expired, ExpiresUnix: now.Add(-time.Second).Unix()})
	// Placed rows must be excluded — they're already in the gossip ledger.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb4", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 4}})

	got := fsm.pendingReservationsByNode(now.Unix())
	bSum := got["B"]
	if bSum.CPU != 3 {
		t.Fatalf("B CPU = %v, want 3 (live1+live2 only, exclude expired and placed)", bSum.CPU)
	}
	if bSum.MemoryMB != 1536 {
		t.Fatalf("B MemoryMB = %d, want 1536", bSum.MemoryMB)
	}
	if bSum.DiskGB != 15 {
		t.Fatalf("B DiskGB = %v, want 15", bSum.DiskGB)
	}
	if _, present := got["other"]; present {
		t.Fatalf("got entry for other unowned node: %+v", got)
	}
	if _, ok := fsm.pendingReservationClaims["sb3"]; ok {
		t.Fatalf("expired reservation remains in pending index after read")
	}
}

func TestFSMExpiredReservationIDsSurviveCapacityPrune(t *testing.T) {
	fsm := newPlacementFSM()
	now := time.Now()
	applyOp(t, fsm, command{
		Op:          opReserve,
		SandboxID:   "sb-expired",
		OwnerNodeID: "B",
		Spec:        &models.CreateSandboxRequest{CPU: 2},
		ExpiresUnix: now.Add(-time.Second).Unix(),
	})

	if got := fsm.pendingReservationsByNode(now.Unix()); len(got) != 0 {
		t.Fatalf("expired reservation counted as pending capacity: %+v", got)
	}
	ids := fsm.expiredReservationIDs(now.Unix())
	if len(ids) != 1 || ids[0] != "sb-expired" {
		t.Fatalf("expiredReservationIDs = %+v, want [sb-expired]", ids)
	}

	applyOp(t, fsm, command{Op: opCancelReserve, SandboxID: "sb-expired"})
	if ids := fsm.expiredReservationIDs(now.Unix()); len(ids) != 0 {
		t.Fatalf("expired reservation remained after cancel: %+v", ids)
	}
}

func TestFSMPendingReservationIndexReleasesOnStateTransitions(t *testing.T) {
	fsm := newPlacementFSM()
	expiry := time.Now().Add(60 * time.Second).Unix()

	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 2}, ExpiresUnix: expiry})
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb2", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 1}, ExpiresUnix: expiry})
	if got := fsm.pendingReservationsByNode(time.Now().Unix())["B"].CPU; got != 3 {
		t.Fatalf("pending CPU after two reservations = %v, want 3", got)
	}

	if got := applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "B"}); got != nil {
		t.Fatalf("promote sb1: %v", got)
	}
	if got := fsm.pendingReservationsByNode(time.Now().Unix())["B"].CPU; got != 1 {
		t.Fatalf("pending CPU after promote = %v, want only sb2=1", got)
	}
	if _, ok := fsm.pendingReservationClaims["sb1"]; ok {
		t.Fatalf("promoted reservation sb1 still has a pending claim")
	}

	if got := applyOp(t, fsm, command{Op: opCancelReserve, SandboxID: "sb2"}); got != nil {
		t.Fatalf("cancel sb2: %v", got)
	}
	if _, ok := fsm.pendingReservationsByNode(time.Now().Unix())["B"]; ok {
		t.Fatalf("owner B still has pending capacity after cancel")
	}

	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb3", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 4}, ExpiresUnix: expiry})
	if got := applyOp(t, fsm, command{Op: opReassign, SandboxID: "sb3", OwnerNodeID: "C"}); got != nil {
		t.Fatalf("reassign sb3: %v", got)
	}
	pending := fsm.pendingReservationsByNode(time.Now().Unix())
	if _, ok := pending["B"]; ok {
		t.Fatalf("old owner B still has pending capacity after reservation reassign: %+v", pending)
	}
	if got := pending["C"].CPU; got != 4 {
		t.Fatalf("new owner C pending CPU = %v, want 4", got)
	}
	if got := applyOp(t, fsm, command{Op: opDelete, SandboxID: "sb3"}); got != nil {
		t.Fatalf("delete sb3: %v", got)
	}
	if len(fsm.pendingReservationsByNode(time.Now().Unix())) != 0 {
		t.Fatalf("pending capacity not empty after deleting last reservation: %+v", fsm.pendingReservationsByNode(time.Now().Unix()))
	}
}

func TestFSMPendingReservationIndexRefreshesExpiryWithoutDoubleCounting(t *testing.T) {
	fsm := newPlacementFSM()
	now := time.Now()
	first := now.Add(10 * time.Second).Unix()
	later := now.Add(60 * time.Second).Unix()
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 2}, ExpiresUnix: first})
	if got := applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", ExpiresUnix: later}); got != nil {
		t.Fatalf("refresh reserve: %v", got)
	}

	beforeLater := fsm.pendingReservationsByNode(now.Add(20 * time.Second).Unix())
	if got := beforeLater["B"].CPU; got != 2 {
		t.Fatalf("pending CPU after stale expiry passed = %v, want 2 without double-counting", got)
	}
	afterLater := fsm.pendingReservationsByNode(now.Add(90 * time.Second).Unix())
	if _, ok := afterLater["B"]; ok {
		t.Fatalf("pending capacity remained after refreshed expiry elapsed: %+v", afterLater)
	}
}

func TestFSMPendingReservationIndexUpdatesOnReservedSpecUpsert(t *testing.T) {
	fsm := newPlacementFSM()
	expiry := time.Now().Add(60 * time.Second).Unix()
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 512}, ExpiresUnix: expiry})
	if got := applyOp(t, fsm, command{Op: opUpsertSpec, SandboxID: "sb1", Spec: &models.CreateSandboxRequest{CPU: 3, MemoryMB: 2048}}); got != nil {
		t.Fatalf("upsert reserved spec: %v", got)
	}
	got := fsm.pendingReservationsByNode(time.Now().Unix())["B"]
	if got.CPU != 3 || got.MemoryMB != 2048 {
		t.Fatalf("pending after reserved spec upsert = %+v, want CPU=3 MemoryMB=2048", got)
	}
}
