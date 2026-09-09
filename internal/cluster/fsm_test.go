package cluster

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	secretspkg "github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/hashicorp/raft"
)

func TestFSMApplyPlace(t *testing.T) {
	fsm := newPlacementFSM()
	cmd := command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a:8080"}
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got := fsm.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("apply returned %v, want nil", got)
	}
	p, ok := fsm.get("sb1")
	if !ok {
		t.Fatal("expected placement for sb1, got none")
	}
	if p.OwnerNodeID != "nodeA" || p.OwnerAPIURL != "http://a:8080" {
		t.Fatalf("unexpected placement: %+v", p)
	}
}

func TestFSMInitialPlacementPreservesSecretSealGeneration(t *testing.T) {
	fsm := newPlacementFSM()
	cmd := command{
		Op: opPlace, SandboxID: "sb-secret-gen", OwnerNodeID: "node-a",
		IncarnationID: "inc-secret-gen", SecretRef: testSecretRef("sb-secret-gen", "inc-secret-gen"), SecretVersion: secretspkg.RefVersion,
		SecretSealGeneration: 7,
	}
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got := fsm.Apply(&raft.Log{Index: 1, Data: payload}); got != nil {
		t.Fatalf("apply returned %v", got)
	}
	placement, ok := fsm.get("sb-secret-gen")
	if !ok || placement.SecretSealGeneration != 7 {
		t.Fatalf("placement = %+v, want seal generation 7", placement)
	}
	handle := secretsFromPlacement(placement)
	if handle.SealGeneration != 7 {
		t.Fatalf("handle = %+v, want seal generation 7", handle)
	}
}

func TestFSMPlaceIdempotent(t *testing.T) {
	fsm := newPlacementFSM()
	cmd := command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a:8080", IncarnationID: "inc-1"}
	payload, _ := encodeCommand(cmd)
	fsm.Apply(&raft.Log{Data: payload})
	first, _ := fsm.get("sb1")
	// Re-apply same command — version should not bump for the placement,
	// even though the FSM-wide version counter does.
	cmd.ExpectedIncarnationID = "inc-1"
	payload, _ = encodeCommand(cmd)
	fsm.Apply(&raft.Log{Data: payload})
	second, _ := fsm.get("sb1")
	if first.Version != second.Version {
		t.Fatalf("idempotent re-place changed placement version: %d -> %d", first.Version, second.Version)
	}
	if first.UpdatedUnix != second.UpdatedUnix {
		t.Fatalf("idempotent re-place changed UpdatedUnix: %d -> %d", first.UpdatedUnix, second.UpdatedUnix)
	}
}

func TestFSMReassignOwner(t *testing.T) {
	fsm := newPlacementFSM()
	c1, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", OwnerAPIURL: "http://a", IncarnationID: "inc-1"})
	c2, _ := encodeCommand(command{Op: opReassign, SandboxID: "sb1", OwnerNodeID: "B", OwnerAPIURL: "http://b", ExpectedIncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Data: c1})
	createdFirst, _ := fsm.get("sb1")
	time.Sleep(time.Second) // allow CreatedUnix preservation to be observable
	fsm.Apply(&raft.Log{Data: c2})
	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "B" {
		t.Fatalf("expected owner B, got %q", got.OwnerNodeID)
	}
	if got.CreatedUnix != createdFirst.CreatedUnix {
		t.Fatalf("CreatedUnix should be preserved across reassign: was %d, now %d", createdFirst.CreatedUnix, got.CreatedUnix)
	}
}

func TestFSMPlaceCannotOverwriteActiveOwner(t *testing.T) {
	fsm := newPlacementFSM()
	first, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", OwnerAPIURL: "http://a", IncarnationID: "inc-1"})
	if got := fsm.Apply(&raft.Log{Data: first}); got != nil {
		t.Fatalf("first place: %v", got)
	}
	overwrite, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "B", OwnerAPIURL: "http://b", IncarnationID: "inc-1", ExpectedIncarnationID: "inc-1"})
	got := fsm.Apply(&raft.Log{Data: overwrite})
	err, _ := got.(error)
	if err == nil || !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("overwrite = %v, want ErrReservationConflict", got)
	}
	p, _ := fsm.get("sb1")
	if p.OwnerNodeID != "A" {
		t.Fatalf("owner changed after rejected overwrite: %+v", p)
	}
}

func TestFSMOrphanOwnerBatchesPlacedRowsAndCancelsReservations(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(idx uint64, cmd command) interface{} {
		t.Helper()
		payload, _ := encodeCommand(cmd)
		return fsm.Apply(&raft.Log{Index: idx, Data: payload})
	}
	if got := apply(1, command{Op: opPlace, SandboxID: "sb-dead-1", OwnerNodeID: "dead", OwnerAPIURL: "http://dead"}); got != nil {
		t.Fatalf("place dead 1: %v", got)
	}
	if got := apply(2, command{Op: opPlace, SandboxID: "sb-live", OwnerNodeID: "live", OwnerAPIURL: "http://live"}); got != nil {
		t.Fatalf("place live: %v", got)
	}
	if got := apply(3, command{Op: opReserve, SandboxID: "sb-dead-reserved", OwnerNodeID: "dead", Spec: &models.CreateSandboxRequest{Name: "held"}, ExpiresUnix: time.Now().Add(time.Hour).Unix()}); got != nil {
		t.Fatalf("reserve dead: %v", got)
	}

	if got := apply(4, command{Op: opOrphanOwner, NodeID: "dead"}); got != nil {
		t.Fatalf("opOrphanOwner: %v", got)
	}
	orphan, ok := fsm.get("sb-dead-1")
	if !ok || !orphan.IsOrphaned() || orphan.OrphanedOwnerNodeID != "dead" || orphan.OrphanedUnix == 0 {
		t.Fatalf("dead placement not orphaned with metadata: %+v ok=%v", orphan, ok)
	}
	if got := fsm.idsOwnedBy("dead"); len(got) != 0 {
		t.Fatalf("dead owner index still has ids: %+v", got)
	}
	if _, ok := fsm.get("sb-dead-reserved"); ok {
		t.Fatal("dead owner's pending reservation was not cancelled")
	}
	if got, ok := fsm.sandboxIDByName("held"); ok {
		t.Fatalf("cancelled reservation still owns name as %q", got)
	}
	live, _ := fsm.get("sb-live")
	if live.OwnerNodeID != "live" || live.IsOrphaned() {
		t.Fatalf("live owner was disturbed: %+v", live)
	}
}

func TestFSMClaimOrphanRequiresPreviousOwner(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(idx uint64, cmd command) interface{} {
		t.Helper()
		payload, _ := encodeCommand(cmd)
		return fsm.Apply(&raft.Log{Index: idx, Data: payload})
	}
	if got := apply(1, command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "dead", IncarnationID: "inc-claim", Spec: &models.CreateSandboxRequest{Name: "original", Image: "alpine"}}); got != nil {
		t.Fatalf("place: %v", got)
	}
	if got := apply(2, command{Op: opOrphanOwner, NodeID: "dead"}); got != nil {
		t.Fatalf("orphan: %v", got)
	}
	got := apply(3, command{Op: opClaimOrphan, SandboxID: "sb1", OwnerNodeID: "other", OwnerAPIURL: "http://other", IncarnationID: "inc-claim"})
	err, _ := got.(error)
	if err == nil || !errors.Is(err, ErrOrphanClaimConflict) {
		t.Fatalf("wrong-owner claim = %v, want ErrOrphanClaimConflict", got)
	}
	if got := apply(4, command{Op: opClaimOrphan, SandboxID: "sb1", OwnerNodeID: "dead", OwnerAPIURL: "http://dead-new", IncarnationID: "inc-claim", Spec: &models.CreateSandboxRequest{Name: "original", Image: "alpine:new"}}); got != nil {
		t.Fatalf("previous-owner claim: %v", got)
	}
	p, _ := fsm.get("sb1")
	if p.OwnerNodeID != "dead" || p.OwnerAPIURL != "http://dead-new" || p.IsOrphaned() || p.OrphanedOwnerNodeID != "" || p.OrphanedUnix != 0 {
		t.Fatalf("claim did not restore active owner and clear orphan metadata: %+v", p)
	}
	if p.Spec == nil || p.Spec.Image != "alpine:new" {
		t.Fatalf("claim did not update supplied spec: %+v", p.Spec)
	}
}

func TestFSMDelete(t *testing.T) {
	fsm := newPlacementFSM()
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", IncarnationID: "inc-delete"})
	fsm.Apply(&raft.Log{Data: c})
	d, _ := encodeCommand(command{Op: opDelete, SandboxID: "sb1", ExpectedIncarnationID: "inc-delete"})
	fsm.Apply(&raft.Log{Data: d})
	if _, ok := fsm.get("sb1"); ok {
		t.Fatal("placement should be gone after delete")
	}
	// Idempotent.
	fsm.Apply(&raft.Log{Data: d})
}

func TestFSMDeleteIsIncarnationFencedAcrossIDReuse(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(index uint64, cmd command) interface{} {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return fsm.Apply(&raft.Log{Index: index, Data: payload})
	}
	if got := apply(1, command{Op: opPlace, SandboxID: "sb-reused", OwnerNodeID: "node-new", IncarnationID: "inc-new"}); got != nil {
		t.Fatal(got)
	}
	if got := apply(2, command{Op: opDelete, SandboxID: "sb-reused", ExpectedIncarnationID: "inc-old"}); got != nil {
		t.Fatalf("stale delete = %v, want acknowledged no-op", got)
	}
	if p, ok := fsm.get("sb-reused"); !ok || p.IncarnationID != "inc-new" {
		t.Fatalf("stale delete removed replacement placement: %+v ok=%v", p, ok)
	}
	if got := apply(3, command{Op: opDelete, SandboxID: "sb-reused"}); !errors.Is(got.(error), ErrIncarnationConflict) {
		t.Fatalf("unfenced delete = %v, want ErrIncarnationConflict", got)
	}
	if _, ok := fsm.get("sb-reused"); !ok {
		t.Fatal("unfenced delete removed placement")
	}
}

func TestFSMDeleteIsOwnerFencedAcrossConcurrentReassignment(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(index uint64, cmd command) interface{} {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return fsm.Apply(&raft.Log{Index: index, Data: payload})
	}
	if got := apply(1, command{Op: opPlace, SandboxID: "sb-reassigned", OwnerNodeID: "node-new", IncarnationID: "inc-same"}); got != nil {
		t.Fatal(got)
	}
	if got := apply(2, command{
		Op: opDelete, SandboxID: "sb-reassigned", ExpectedIncarnationID: "inc-same", ExpectedOwnerNodeID: "node-old",
	}); got != nil {
		t.Fatalf("stale-owner delete = %v, want acknowledged no-op", got)
	}
	if p, ok := fsm.get("sb-reassigned"); !ok || p.OwnerNodeID != "node-new" {
		t.Fatalf("stale owner removed reassigned placement: %+v ok=%v", p, ok)
	}
	if got := apply(3, command{
		Op: opDelete, SandboxID: "sb-reassigned", ExpectedIncarnationID: "inc-same", ExpectedOwnerNodeID: "node-new",
	}); got != nil {
		t.Fatalf("current-owner delete: %v", got)
	}
	if _, ok := fsm.get("sb-reassigned"); ok {
		t.Fatal("current owner could not delete placement")
	}
}

func TestFSMBeginDeleteFencesLifecycleWideCleanup(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(index uint64, cmd command) interface{} {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return fsm.Apply(&raft.Log{Index: index, Data: payload})
	}
	if got := apply(1, command{Op: opPlace, SandboxID: "sb-delete-fence", OwnerNodeID: "node-a", IncarnationID: "inc-a"}); got != nil {
		t.Fatal(got)
	}
	if got := apply(2, command{
		Op: opBeginDelete, SandboxID: "sb-delete-fence", ExpectedOwnerNodeID: "node-b", ExpectedOwnerNodeIDSet: true,
		ExpectedIncarnationID: "inc-a", ExpiresUnix: 100,
	}); !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("wrong-owner begin delete = %v", got)
	}
	if got := apply(3, command{
		Op: opBeginDelete, SandboxID: "sb-delete-fence", ExpectedOwnerNodeID: "node-a", ExpectedOwnerNodeIDSet: true,
		ExpectedIncarnationID: "inc-a", ExpiresUnix: 100,
	}); got != nil {
		t.Fatalf("begin delete: %v", got)
	}
	p, ok := fsm.get("sb-delete-fence")
	if !ok || !p.IsDeleting() || p.ExpiresUnix != 100 {
		t.Fatalf("deleting placement = %+v, ok=%v", p, ok)
	}
	if got := apply(4, command{
		Op: opReassign, SandboxID: "sb-delete-fence", OwnerNodeID: "node-b", ExpectedIncarnationID: "inc-a",
	}); !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("reassign deleting placement = %v", got)
	}
	if got := apply(5, command{
		Op: opUpsertSpec, SandboxID: "sb-delete-fence", ExpectedIncarnationID: "inc-a", Spec: &models.CreateSandboxRequest{Image: "replacement"},
	}); !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("mutate deleting placement = %v", got)
	}
	expired := fsm.expiredDeletingPlacements(101)
	if len(expired) != 1 || expired[0].SandboxID != "sb-delete-fence" {
		t.Fatalf("expired deleting placements = %+v", expired)
	}
	if got := apply(6, command{
		Op: opDelete, SandboxID: "sb-delete-fence", ExpectedOwnerNodeID: "node-a", ExpectedOwnerNodeIDSet: true,
		ExpectedIncarnationID: "inc-a",
	}); got != nil {
		t.Fatalf("final delete: %v", got)
	}
	if _, ok := fsm.get("sb-delete-fence"); ok || len(fsm.expiredDeletingPlacements(101)) != 0 {
		t.Fatal("final delete left placement or deleting index")
	}
}

func TestFSMBeginDeletePromotesReservationIntoCleanupFence(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(index uint64, cmd command) interface{} {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return fsm.Apply(&raft.Log{Index: index, Data: payload})
	}
	if got := apply(1, command{
		Op: opReserve, SandboxID: "sb-reserved-delete", OwnerNodeID: "node-a",
		IncarnationID: "inc-a", ExpiresUnix: 50,
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 2, MemoryMB: 1024},
	}); got != nil {
		t.Fatal(got)
	}
	if len(fsm.pendingReservationsByNode(1)) != 1 {
		t.Fatal("reservation did not acquire pending capacity")
	}
	if got := apply(2, command{
		Op: opBeginDelete, SandboxID: "sb-reserved-delete", ExpectedOwnerNodeID: "node-a", ExpectedOwnerNodeIDSet: true,
		ExpectedIncarnationID: "inc-a", ExpiresUnix: 100,
	}); got != nil {
		t.Fatalf("begin reserved delete: %v", got)
	}
	p, ok := fsm.get("sb-reserved-delete")
	if !ok || !p.IsDeleting() || p.ExpiresUnix != 100 {
		t.Fatalf("reserved delete fence = %+v, ok=%v", p, ok)
	}
	if len(fsm.pendingReservationsByNode(1)) != 0 || len(fsm.reservedIndex) != 0 {
		t.Fatal("reserved delete fence retained pending capacity")
	}
}

func TestFSMOrphanDeleteIsOwnerFencedAcrossConcurrentClaim(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(index uint64, cmd command) interface{} {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return fsm.Apply(&raft.Log{Index: index, Data: payload})
	}
	if got := apply(1, command{Op: opPlace, SandboxID: "sb-claimed", OwnerNodeID: "node-new", IncarnationID: "inc-same"}); got != nil {
		t.Fatal(got)
	}
	if got := apply(2, command{
		Op: opDelete, SandboxID: "sb-claimed", ExpectedIncarnationID: "inc-same", ExpectedOwnerNodeIDSet: true,
	}); got != nil {
		t.Fatalf("stale orphan delete = %v, want acknowledged no-op", got)
	}
	if p, ok := fsm.get("sb-claimed"); !ok || p.OwnerNodeID != "node-new" {
		t.Fatalf("stale orphan delete removed claimed placement: %+v ok=%v", p, ok)
	}
}

func TestFSMDeleteRetainsAndPrunesAuditACL(t *testing.T) {
	fsm := newPlacementFSM()
	expires := time.Now().UTC().Add(time.Hour).Unix()
	place, _ := encodeCommand(command{
		Op:            opPlace,
		SandboxID:     "sb-audit",
		OwnerNodeID:   "node-a",
		OwnerRef:      "tenant-a",
		IncarnationID: "inc-a",
	})
	if got := fsm.Apply(&raft.Log{Index: 1, Data: place}); got != nil {
		t.Fatalf("place: %v", got)
	}
	reassign, _ := encodeCommand(command{Op: opReassign, SandboxID: "sb-audit", OwnerNodeID: "node-b", ExpectedIncarnationID: "inc-a"})
	if got := fsm.Apply(&raft.Log{Index: 2, Data: reassign}); got != nil {
		t.Fatalf("reassign: %v", got)
	}
	del, _ := encodeCommand(command{Op: opDelete, SandboxID: "sb-audit", ExpectedIncarnationID: "inc-a", ExpiresUnix: expires})
	if got := fsm.Apply(&raft.Log{Index: 3, Data: del}); got != nil {
		t.Fatalf("delete: %v", got)
	}
	if _, ok := fsm.get("sb-audit"); ok {
		t.Fatal("placement should be gone after delete")
	}
	acl, ok := fsm.auditACLForSandbox("sb-audit", "inc-a", expires-1)
	if !ok || acl.OwnerRef != "tenant-a" || acl.ExpiresUnix != expires {
		t.Fatalf("retained ACL = %+v, %v", acl, ok)
	}
	if got, want := acl.AuditNodeIDs, []string{"node-a", "node-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retained audit nodes = %v, want %v", got, want)
	}
	if _, ok := fsm.auditACLForSandbox("sb-audit", "inc-a", expires); ok {
		t.Fatal("expired ACL must not authorize access before its prune sweep")
	}

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if acl, ok := restored.auditACLForSandbox("sb-audit", "inc-a", expires-1); !ok || acl.OwnerRef != "tenant-a" {
		t.Fatalf("restored ACL = %+v, %v", acl, ok)
	}

	if acl, ok := restored.auditACLForSandbox("sb-audit", "inc-a", expires-1); !ok || !reflect.DeepEqual(acl.AuditNodeIDs, []string{"node-a", "node-b"}) {
		t.Fatalf("restored audit nodes = %+v, %v", acl, ok)
	}

	prune, _ := encodeCommand(command{Op: opPruneAuditACL, ExpiresUnix: expires})
	if got := restored.Apply(&raft.Log{Index: 4, Data: prune}); got != nil {
		t.Fatalf("prune: %v", got)
	}
	if _, ok := restored.auditACLForSandbox("sb-audit", "inc-a", expires-1); ok {
		t.Fatal("prune should remove the expired retained ACL")
	}
}

func TestFSMDeleteRetainsOwnerlessAuditNodeIndex(t *testing.T) {
	fsm := newPlacementFSM()
	place, err := encodeCommand(command{
		Op:            opPlace,
		SandboxID:     "sb-operator-audit",
		OwnerNodeID:   "node-a",
		IncarnationID: "inc-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := fsm.Apply(&raft.Log{Index: 1, Data: place}); got != nil {
		t.Fatalf("place: %v", got)
	}
	del, err := encodeCommand(command{Op: opDelete, SandboxID: "sb-operator-audit", ExpectedIncarnationID: "inc-a", ExpiresUnix: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if got := fsm.Apply(&raft.Log{Index: 2, Data: del}); got != nil {
		t.Fatalf("delete: %v", got)
	}
	acl, ok := fsm.auditACLForSandbox("sb-operator-audit", "inc-a", time.Now().Unix())
	if !ok || acl.OwnerRef != "" || acl.IncarnationID != "inc-a" || !reflect.DeepEqual(acl.AuditNodeIDs, []string{"node-a"}) {
		t.Fatalf("ownerless audit ACL = %+v ok=%v", acl, ok)
	}
}

func TestFSMDeleteRetainsEverySandboxIncarnation(t *testing.T) {
	fsm := newPlacementFSM()
	expires := time.Now().Add(time.Hour).Unix()
	apply := func(index uint64, cmd command) {
		t.Helper()
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if got := fsm.Apply(&raft.Log{Index: index, Data: payload}); got != nil {
			t.Fatalf("apply index %d: %v", index, got)
		}
	}
	apply(1, command{Op: opPlace, SandboxID: "sb-reused", OwnerNodeID: "node-a", OwnerRef: "tenant-old", IncarnationID: "inc-old"})
	apply(2, command{Op: opDelete, SandboxID: "sb-reused", ExpectedIncarnationID: "inc-old", ExpiresUnix: expires})
	apply(3, command{Op: opPlace, SandboxID: "sb-reused", OwnerNodeID: "node-b", OwnerRef: "tenant-new", IncarnationID: "inc-new"})
	apply(4, command{Op: opDelete, SandboxID: "sb-reused", ExpectedIncarnationID: "inc-new", ExpiresUnix: expires})

	oldACL, oldOK := fsm.auditACLForSandbox("sb-reused", "inc-old", expires-1)
	newACL, newOK := fsm.auditACLForSandbox("sb-reused", "inc-new", expires-1)
	latest, latestOK := fsm.auditACLForSandbox("sb-reused", "", expires-1)
	if !oldOK || oldACL.OwnerRef != "tenant-old" || !newOK || newACL.OwnerRef != "tenant-new" {
		t.Fatalf("retained lifecycle ACLs old=%+v/%v new=%+v/%v", oldACL, oldOK, newACL, newOK)
	}
	if !latestOK || latest.IncarnationID != "inc-new" || latest.RetainedVersion != 4 {
		t.Fatalf("latest retained lifecycle = %+v/%v", latest, latestOK)
	}
}

func TestPlacementAuditNodeHistoryBoundIsFailOpenForCoverage(t *testing.T) {
	p := Placement{}
	for i := 0; i <= maxPlacementAuditNodes; i++ {
		recordPlacementAuditNode(&p, fmt.Sprintf("node-%03d", i))
	}
	if len(p.AuditNodeIDs) != maxPlacementAuditNodes {
		t.Fatalf("history len = %d, want %d", len(p.AuditNodeIDs), maxPlacementAuditNodes)
	}
	if !p.AuditNodesTruncated {
		t.Fatal("overflow must mark history truncated so readers use full fan-out")
	}
}

// TestFSMPlaceCarriesSpec verifies the spec payload survives an opPlace round
// trip and a no-op idempotent retry that omits the spec doesn't erase it.
func TestFSMPlaceCarriesSpec(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256}
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", Spec: spec})
	fsm.Apply(&raft.Log{Data: c})
	got, _ := fsm.get("sb1")
	if got.Spec == nil || got.Spec.Image != "alpine" {
		t.Fatalf("expected spec to be stored; got %+v", got.Spec)
	}
	// Idempotent retry without a spec must not erase the stored spec.
	c2, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A"})
	fsm.Apply(&raft.Log{Data: c2})
	got2, _ := fsm.get("sb1")
	if got2.Spec == nil || got2.Spec.Image != "alpine" {
		t.Fatalf("idempotent re-place erased spec; got %+v", got2.Spec)
	}
}

// TestFSMUpsertSpec exercises opUpsertSpec: it overwrites Placement.Spec
// without touching the owner pointer.
func TestFSMUpsertSpec(t *testing.T) {
	fsm := newPlacementFSM()
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", IncarnationID: "inc-upsert",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1}})
	fsm.Apply(&raft.Log{Data: c})

	// Resize: bump CPU via opUpsertSpec.
	u, _ := encodeCommand(command{Op: opUpsertSpec, SandboxID: "sb1", ExpectedIncarnationID: "inc-upsert",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 2}})
	fsm.Apply(&raft.Log{Data: u})

	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "A" {
		t.Fatalf("opUpsertSpec must not touch owner; got %q", got.OwnerNodeID)
	}
	if got.Spec == nil || got.Spec.CPU != 2 {
		t.Fatalf("expected CPU=2 after upsert; got %+v", got.Spec)
	}

	// Upsert against unknown sandbox: silent no-op.
	u2, _ := encodeCommand(command{Op: opUpsertSpec, SandboxID: "ghost",
		ExpectedIncarnationID: "inc-ghost", Spec: &models.CreateSandboxRequest{Image: "x"}})
	if got := fsm.Apply(&raft.Log{Data: u2}); got != nil {
		t.Fatalf("upsert against unknown id returned %v, want nil", got)
	}
}

func TestFSMHotPlacementReadsOmitRecoveryPayload(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op:            opPlace,
		SandboxID:     "sb-hot",
		OwnerNodeID:   "node-a",
		OwnerAPIURL:   "http://node-a",
		Spec:          &models.CreateSandboxRequest{Image: "alpine", Name: "demo", Env: map[string]string{"K": "V"}},
		IncarnationID: "inc-hot", SecretRef: testSecretRef("sb-hot", "inc-hot"),
		SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 1,
	})
	if got := fsm.Apply(&raft.Log{Index: 1, Data: place}); got != nil {
		t.Fatalf("opPlace: %v", got)
	}
	add, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb-hot", ExpectedIncarnationID: "inc-hot", Port: 8080, Protocol: "http"})
	if got := fsm.Apply(&raft.Log{Index: 2, Data: add}); got != nil {
		t.Fatalf("opAddExposedPort: %v", got)
	}

	full, ok := fsm.get("sb-hot")
	if !ok || full.Spec == nil || full.Spec.Image != "alpine" || full.SecretRef == "" {
		t.Fatalf("point lookup lost recovery payload: %+v ok=%v", full, ok)
	}

	shardRows := fsm.placementsForShards(PlacementShardFilter{})
	if len(shardRows) != 1 {
		t.Fatalf("placementsForShards len=%d, want 1", len(shardRows))
	}
	if shardRows[0].Spec != nil || shardRows[0].SecretRef != "" || shardRows[0].SecretVersion != 0 {
		t.Fatalf("hot shard read included recovery payload: %+v", shardRows[0])
	}
	if shardRows[0].ExposedPorts[8080] != "http" {
		t.Fatalf("hot shard read lost route fields: %+v", shardRows[0].ExposedPorts)
	}

	page := fsm.placementPage(PlacementPageRequest{Limit: 10})
	if len(page.Placements) != 1 {
		t.Fatalf("placementPage len=%d, want 1", len(page.Placements))
	}
	if page.NextPageToken != "" {
		t.Fatalf("exact-full page NextPageToken=%q, want empty (no further IDs)", page.NextPageToken)
	}
	if page.Placements[0].Spec != nil || page.Placements[0].SecretRef != "" {
		t.Fatalf("hot page read included recovery payload: %+v", page.Placements[0])
	}
}

func TestPlacementPageExactLimitBoundaryClearsNextToken(t *testing.T) {
	fsm := newPlacementFSM()
	for i := 0; i < 3; i++ {
		place, _ := encodeCommand(command{
			Op:          opPlace,
			SandboxID:   fmt.Sprintf("sb-%d", i),
			OwnerNodeID: "node-a",
			Spec:        &models.CreateSandboxRequest{Image: "alpine"},
		})
		if got := fsm.Apply(&raft.Log{Index: uint64(i + 1), Data: place}); got != nil {
			t.Fatalf("place %d: %v", i, got)
		}
	}
	page := fsm.placementPage(PlacementPageRequest{Limit: 3})
	if len(page.Placements) != 3 {
		t.Fatalf("len=%d, want 3", len(page.Placements))
	}
	if page.NextPageToken != "" {
		t.Fatalf("NextPageToken=%q, want empty when total==limit", page.NextPageToken)
	}
	mid := fsm.placementPage(PlacementPageRequest{Limit: 2})
	if len(mid.Placements) != 2 || mid.NextPageToken == "" {
		t.Fatalf("mid page = %+v, want 2 rows and next token", mid)
	}
	last := fsm.placementPage(PlacementPageRequest{Limit: 2, PageToken: mid.NextPageToken})
	if len(last.Placements) != 1 || last.NextPageToken != "" {
		t.Fatalf("last page = %+v, want 1 row and empty next", last)
	}
}

func TestPlacementsByIDsPointLookup(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "n1",
		Spec: &models.CreateSandboxRequest{Image: "alpine"}, SecretRecipients: []string{"n1", "n2"},
	})
	fsm.Apply(&raft.Log{Index: 1, Data: place})
	got := fsm.placementsByIDs([]string{"sb-a", "missing", ""})
	if len(got) != 1 || got["sb-a"].OwnerNodeID != "n1" {
		t.Fatalf("placementsByIDs = %+v", got)
	}
	if len(got["sb-a"].SecretRecipients) != 2 {
		t.Fatalf("SecretRecipients = %v", got["sb-a"].SecretRecipients)
	}
}

func TestFSMUpdateSecretRecipientsPreservesIncarnation(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-exp", OwnerNodeID: "n1", OwnerAPIURL: "http://n1",
		Spec:                 &models.CreateSandboxRequest{Image: "alpine"},
		SecretRecipients:     []string{"n1", "dead-a", "dead-b"},
		IncarnationID:        "inc-keep",
		SecretRef:            secretspkg.FormatRef("sb-exp", "inc-keep", secretspkg.RefVersion),
		SecretVersion:        secretspkg.RefVersion,
		SecretSealGeneration: 3,
	})
	if res := fsm.Apply(&raft.Log{Index: 1, Data: place}); res != nil {
		t.Fatalf("opPlace: %v", res)
	}
	upd, _ := encodeCommand(command{
		Op:                     opUpdateSecretRecipients,
		SandboxID:              "sb-exp",
		SecretRecipients:       []string{"n1", "live-b", "live-c"},
		SecretRef:              secretspkg.FormatRef("sb-exp", "inc-keep", secretspkg.RefVersion),
		SecretVersion:          secretspkg.RefVersion,
		SecretSealGeneration:   4,
		ExpectedIncarnationID:  "inc-keep",
		ExpectedSealGeneration: 3,
	})
	if res := fsm.Apply(&raft.Log{Index: 2, Data: upd}); res != nil {
		t.Fatalf("opUpdateSecretRecipients: %v", res)
	}
	got, ok := fsm.get("sb-exp")
	if !ok {
		t.Fatal("placement missing")
	}
	if got.IncarnationID != "inc-keep" {
		t.Fatalf("IncarnationID=%q, want preserved", got.IncarnationID)
	}
	if got.OwnerNodeID != "n1" {
		t.Fatalf("OwnerNodeID=%q, want n1", got.OwnerNodeID)
	}
	if len(got.SecretRecipients) != 3 || got.SecretRecipients[1] != "live-b" {
		t.Fatalf("SecretRecipients=%v", got.SecretRecipients)
	}
}

func TestFSMPlacePreservesAndFencesIncarnation(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-inc-place", OwnerNodeID: "n1",
		IncarnationID: "inc-a", SecretRef: testSecretRef("sb-inc-place", "inc-a"), SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 1,
	})
	if res := fsm.Apply(&raft.Log{Index: 1, Data: place}); res != nil {
		t.Fatalf("initial opPlace: %v", res)
	}

	// A mutation of an existing placement must carry the authoritative fence.
	replay, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-inc-place", OwnerNodeID: "n1",
		IncarnationID: "inc-a", ExpectedIncarnationID: "inc-a",
	})
	if res := fsm.Apply(&raft.Log{Index: 2, Data: replay}); res != nil {
		t.Fatalf("replay opPlace: %v", res)
	}
	if got, _ := fsm.get("sb-inc-place"); got.IncarnationID != "inc-a" {
		t.Fatalf("replay changed incarnation to %q", got.IncarnationID)
	}
	unfenced, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-inc-place", OwnerNodeID: "n1",
		IncarnationID: "candidate-only",
	})
	if res := fsm.Apply(&raft.Log{Index: 3, Data: unfenced}); !errors.Is(res.(error), ErrIncarnationConflict) {
		t.Fatalf("unfenced opPlace = %v, want ErrIncarnationConflict", res)
	}

	stale, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-inc-place", OwnerNodeID: "n1",
		IncarnationID: "inc-b", ExpectedIncarnationID: "inc-b",
		SecretRef: testSecretRef("sb-inc-place", "inc-b"), SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 2,
	})
	res := fsm.Apply(&raft.Log{Index: 4, Data: stale})
	if err, ok := res.(error); !ok || !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("stale opPlace result = %v, want ErrIncarnationConflict", res)
	}
	got, _ := fsm.get("sb-inc-place")
	if got.IncarnationID != "inc-a" || got.SecretRef != testSecretRef("sb-inc-place", "inc-a") || got.SecretVersion != secretspkg.RefVersion {
		t.Fatalf("stale opPlace mutated placement: %+v", got)
	}
}

func TestFSMReassignIsIncarnationFencedAcrossIDReuse(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-reassign-reused", OwnerNodeID: "node-new", IncarnationID: "inc-new",
	})
	if got := fsm.Apply(&raft.Log{Index: 1, Data: place}); got != nil {
		t.Fatal(got)
	}
	stale, _ := encodeCommand(command{
		Op: opReassign, SandboxID: "sb-reassign-reused", OwnerNodeID: "stale-target", ExpectedIncarnationID: "inc-old",
	})
	if got := fsm.Apply(&raft.Log{Index: 2, Data: stale}); !errors.Is(got.(error), ErrIncarnationConflict) {
		t.Fatalf("stale reassign = %v, want ErrIncarnationConflict", got)
	}
	if p, ok := fsm.get("sb-reassign-reused"); !ok || p.OwnerNodeID != "node-new" || p.IncarnationID != "inc-new" {
		t.Fatalf("stale reassign mutated replacement: %+v ok=%v", p, ok)
	}
}

func TestFSMRoutingMutationsAreIncarnationFencedAcrossIDReuse(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(index uint64, cmd command) interface{} {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return fsm.Apply(&raft.Log{Index: index, Data: payload})
	}
	if got := apply(1, command{Op: opPlace, SandboxID: "sb-routing-reused", OwnerNodeID: "node-new", IncarnationID: "inc-new"}); got != nil {
		t.Fatal(got)
	}
	if got := apply(2, command{Op: opAddExposedPort, SandboxID: "sb-routing-reused", ExpectedIncarnationID: "inc-new", Port: 8080, Protocol: "http"}); got != nil {
		t.Fatal(got)
	}
	for index, cmd := range []command{
		{Op: opRemoveExposedPort, SandboxID: "sb-routing-reused", ExpectedIncarnationID: "inc-old", Port: 8080},
		{Op: opAddExposedPort, SandboxID: "sb-routing-reused", ExpectedIncarnationID: "inc-old", Port: 9090, Protocol: "http"},
		{Op: opAddCustomDomain, SandboxID: "sb-routing-reused", ExpectedIncarnationID: "inc-old", Hostname: "stale.example.com"},
	} {
		got := apply(uint64(index+3), cmd)
		if err, ok := got.(error); !ok || !errors.Is(err, ErrIncarnationConflict) {
			t.Fatalf("stale routing op %d = %v, want ErrIncarnationConflict", cmd.Op, got)
		}
	}
	p, ok := fsm.get("sb-routing-reused")
	if !ok || p.ExposedPorts[8080] != "http" {
		t.Fatalf("stale remove changed replacement ports: %+v ok=%v", p.ExposedPorts, ok)
	}
	if _, exists := p.ExposedPorts[9090]; exists || len(p.CustomHostnames) != 0 {
		t.Fatalf("stale add changed replacement routing: ports=%+v domains=%v", p.ExposedPorts, p.CustomHostnames)
	}
}

func TestFSMUpdateSecretRecipientsCASRejectsStaleGeneration(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-cas", OwnerNodeID: "n1", OwnerAPIURL: "http://n1",
		Spec:                 &models.CreateSandboxRequest{Image: "alpine"},
		SecretRecipients:     []string{"n1", "dead-a", "dead-b"},
		IncarnationID:        "inc-a",
		SecretRef:            secretspkg.FormatRef("sb-cas", "inc-a", secretspkg.RefVersion),
		SecretVersion:        secretspkg.RefVersion,
		SecretSealGeneration: 5,
	})
	if res := fsm.Apply(&raft.Log{Index: 1, Data: place}); res != nil {
		t.Fatalf("opPlace: %v", res)
	}
	unfenced, _ := encodeCommand(command{
		Op:                   opUpdateSecretRecipients,
		SandboxID:            "sb-cas",
		SecretRecipients:     []string{"n1", "live-b", "live-c"},
		SecretRef:            secretspkg.FormatRef("sb-cas", "inc-a", secretspkg.RefVersion),
		SecretVersion:        secretspkg.RefVersion,
		SecretSealGeneration: 6,
	})
	unfencedRes := fsm.Apply(&raft.Log{Index: 2, Data: unfenced})
	if err, ok := unfencedRes.(error); !ok || !errors.Is(err, ErrSecretRecipientsCASMismatch) {
		t.Fatalf("unfenced recipient update = %v, want ErrSecretRecipientsCASMismatch", unfencedRes)
	}
	stale, _ := encodeCommand(command{
		Op:                     opUpdateSecretRecipients,
		SandboxID:              "sb-cas",
		SecretRecipients:       []string{"n1", "live-b", "live-c"},
		ExpectedIncarnationID:  "inc-a",
		ExpectedSealGeneration: 4,
		SecretSealGeneration:   6,
		SecretRef:              secretspkg.FormatRef("sb-cas", "inc-a", secretspkg.RefVersion),
		SecretVersion:          secretspkg.RefVersion,
	})
	res := fsm.Apply(&raft.Log{Index: 3, Data: stale})
	err, ok := res.(error)
	if !ok || !errors.Is(err, ErrSecretRecipientsCASMismatch) {
		t.Fatalf("stale CAS = %v (%T), want ErrSecretRecipientsCASMismatch", res, res)
	}
	got, _ := fsm.get("sb-cas")
	if got.SecretSealGeneration != 5 || got.SecretRecipients[1] != "dead-a" {
		t.Fatalf("stale CAS mutated placement: gen=%d recipients=%v", got.SecretSealGeneration, got.SecretRecipients)
	}

	okCmd, _ := encodeCommand(command{
		Op:                     opUpdateSecretRecipients,
		SandboxID:              "sb-cas",
		SecretRecipients:       []string{"n1", "live-b", "live-c"},
		ExpectedIncarnationID:  "inc-a",
		ExpectedSealGeneration: 5,
		SecretSealGeneration:   6,
		SecretRef:              secretspkg.FormatRef("sb-cas", "inc-a", secretspkg.RefVersion),
		SecretVersion:          secretspkg.RefVersion,
	})
	if res := fsm.Apply(&raft.Log{Index: 4, Data: okCmd}); res != nil {
		t.Fatalf("matching CAS: %v", res)
	}
	got, _ = fsm.get("sb-cas")
	if got.SecretSealGeneration != 6 || got.SecretRecipients[1] != "live-b" {
		t.Fatalf("after CAS gen=%d recipients=%v", got.SecretSealGeneration, got.SecretRecipients)
	}
}

func TestFSMNameLookupTracksPlaceRenameAndDelete(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", IncarnationID: "inc-name",
		Spec: &models.CreateSandboxRequest{Image: "alpine", Name: "alpha"}})
	fsm.Apply(&raft.Log{Data: place})

	if got, ok := fsm.sandboxIDByName(" alpha "); !ok || got != "sb1" {
		t.Fatalf("lookup alpha = (%q, %v), want (sb1, true)", got, ok)
	}

	rename, _ := encodeCommand(command{Op: opUpsertSpec, SandboxID: "sb1", ExpectedIncarnationID: "inc-name",
		Spec: &models.CreateSandboxRequest{Image: "alpine", Name: "beta"}})
	fsm.Apply(&raft.Log{Data: rename})

	if got, ok := fsm.sandboxIDByName("alpha"); ok {
		t.Fatalf("old name alpha still resolves to %q after rename", got)
	}
	if got, ok := fsm.sandboxIDByName("beta"); !ok || got != "sb1" {
		t.Fatalf("lookup beta = (%q, %v), want (sb1, true)", got, ok)
	}

	deleteCmd, _ := encodeCommand(command{Op: opDelete, SandboxID: "sb1", ExpectedIncarnationID: "inc-name"})
	fsm.Apply(&raft.Log{Data: deleteCmd})
	if got, ok := fsm.sandboxIDByName("beta"); ok {
		t.Fatalf("deleted name beta still resolves to %q", got)
	}
}

// TestFSMReassignPreservesSpec asserts opReassign moves the owner but leaves
// the replicated spec intact — that's what makes auto-recreation possible.
func TestFSMReassignPreservesSpec(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", Spec: spec, IncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Data: c})
	r, _ := encodeCommand(command{Op: opReassign, SandboxID: "sb1", OwnerNodeID: "B", OwnerAPIURL: "http://b", ExpectedIncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Data: r})
	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "B" {
		t.Fatalf("expected owner B, got %q", got.OwnerNodeID)
	}
	if got.Spec == nil || got.Spec.Image != "alpine" {
		t.Fatalf("reassign erased spec; got %+v", got.Spec)
	}
}

// TestFSMAddRemoveExposedPort exercises the port-intent ops. opAdd is
// idempotent for the same protocol; opRemove is idempotent for absent ports;
// the empty map collapses to nil so JSON snapshots stay clean.
func TestFSMAddRemoveExposedPort(t *testing.T) {
	fsm := newPlacementFSM()
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", IncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Data: c})

	add1, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-1", Port: 80, Protocol: "http"})
	add2, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-1", Port: 5432, Protocol: "tcp"})
	fsm.Apply(&raft.Log{Data: add1})
	fsm.Apply(&raft.Log{Data: add2})

	got, _ := fsm.get("sb1")
	if got.ExposedPorts[80] != "http" || got.ExposedPorts[5432] != "tcp" {
		t.Fatalf("ports not recorded: %+v", got.ExposedPorts)
	}

	// Idempotent re-add: snapshot the version, re-apply, version must be unchanged.
	preVer := got.Version
	fsm.Apply(&raft.Log{Data: add1})
	got, _ = fsm.get("sb1")
	if got.Version != preVer {
		t.Fatalf("idempotent re-add bumped version: %d -> %d", preVer, got.Version)
	}

	// Remove one and verify the other survives.
	rem, _ := encodeCommand(command{Op: opRemoveExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-1", Port: 80})
	fsm.Apply(&raft.Log{Data: rem})
	got, _ = fsm.get("sb1")
	if _, present := got.ExposedPorts[80]; present {
		t.Fatalf("port 80 should be gone; got %+v", got.ExposedPorts)
	}
	if got.ExposedPorts[5432] != "tcp" {
		t.Fatalf("port 5432 should remain; got %+v", got.ExposedPorts)
	}

	// Remove the last entry — the map should collapse to nil so snapshots don't
	// carry an empty container indefinitely.
	rem2, _ := encodeCommand(command{Op: opRemoveExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-1", Port: 5432})
	fsm.Apply(&raft.Log{Data: rem2})
	got, _ = fsm.get("sb1")
	if got.ExposedPorts != nil {
		t.Fatalf("empty ExposedPorts should collapse to nil; got %+v", got.ExposedPorts)
	}

	// Removing an absent port is a no-op.
	preVer = got.Version
	fsm.Apply(&raft.Log{Data: rem2})
	got, _ = fsm.get("sb1")
	if got.Version != preVer {
		t.Fatalf("idempotent re-remove bumped version: %d -> %d", preVer, got.Version)
	}
}

// TestFSMPlaceCarriesPortsThroughRetry asserts an idempotent opPlace retry
// (e.g. AssertOwnership at boot writing spec=nil) does not erase the port
// intents that had been added by opAddExposedPort calls in between.
func TestFSMPlaceCarriesPortsThroughRetry(t *testing.T) {
	fsm := newPlacementFSM()
	p, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", IncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Data: p})
	add, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-1", Port: 8080, Protocol: "http"})
	fsm.Apply(&raft.Log{Data: add})
	// Retry place with same owner, no spec — must not erase ports.
	fsm.Apply(&raft.Log{Data: p})
	got, _ := fsm.get("sb1")
	if got.ExposedPorts[8080] != "http" {
		t.Fatalf("idempotent re-place erased ports; got %+v", got.ExposedPorts)
	}
}

// TestFSMReassignPreservesPorts pairs with TestFSMReassignPreservesSpec — port
// intents must survive a failover reassignment so the new owner can replay
// exposures during recreate.
func TestFSMReassignPreservesPorts(t *testing.T) {
	fsm := newPlacementFSM()
	p, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A",
		Spec: &models.CreateSandboxRequest{Image: "alpine"}, IncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Data: p})
	add, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-1", Port: 5432, Protocol: "tcp"})
	fsm.Apply(&raft.Log{Data: add})
	r, _ := encodeCommand(command{Op: opReassign, SandboxID: "sb1", OwnerNodeID: "B", ExpectedIncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Data: r})
	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "B" {
		t.Fatalf("expected owner B; got %q", got.OwnerNodeID)
	}
	if got.ExposedPorts[5432] != "tcp" {
		t.Fatalf("reassign erased ports; got %+v", got.ExposedPorts)
	}
}

func TestFSMRejectsDuplicateTCPHostPortWithSentinel(t *testing.T) {
	fsm := newPlacementFSM()
	for _, id := range []string{"sb1", "sb2"} {
		place, _ := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: "node-" + id, IncarnationID: "inc-" + id})
		fsm.Apply(&raft.Log{Data: place})
	}
	add1, _ := encodeCommand(command{
		Op: opAddExposedPort, SandboxID: "sb1", Port: 5432,
		Protocol: models.ExposedPortProtocolTCP, HostPort: 22432, ExpectedIncarnationID: "inc-sb1",
	})
	if got := fsm.Apply(&raft.Log{Data: add1}); got != nil {
		t.Fatalf("first add returned %v, want nil", got)
	}
	add2, _ := encodeCommand(command{
		Op: opAddExposedPort, SandboxID: "sb2", Port: 5432,
		Protocol: models.ExposedPortProtocolTCP, HostPort: 22432, ExpectedIncarnationID: "inc-sb2",
	})
	got := fsm.Apply(&raft.Log{Data: add2})
	err, ok := got.(error)
	if !ok || !errors.Is(err, ErrHostPortReserved) {
		t.Fatalf("duplicate host port error = %v, want ErrHostPortReserved", got)
	}
}

// fakeSnapshotSink lets us drive Snapshot/Restore without a real BoltStore.
type fakeSnapshotSink struct {
	*bytes.Buffer
	cancelled bool
}

func (f *fakeSnapshotSink) ID() string    { return "fake" }
func (f *fakeSnapshotSink) Cancel() error { f.cancelled = true; return nil }
func (f *fakeSnapshotSink) Close() error  { return nil }

func TestFSMSnapshotRestoreRoundTrip(t *testing.T) {
	src := newPlacementFSM()
	for _, id := range []string{"a", "b", "c"} {
		c, _ := encodeCommand(command{
			Op: opPlace, SandboxID: id, OwnerNodeID: "owner-" + id, OwnerAPIURL: "http://" + id,
			Spec: &models.CreateSandboxRequest{Image: "img-" + id, CPU: 0.5, MemoryMB: 128},
		})
		src.Apply(&raft.Log{Data: c})
	}
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if sink.cancelled {
		t.Fatal("sink should not have been cancelled on success")
	}

	dst := newPlacementFSMWithRecoveryStore(src.recoveryStore)
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		p, ok := dst.get(id)
		if !ok {
			t.Errorf("missing placement for %s after restore", id)
			continue
		}
		if p.OwnerNodeID != "owner-"+id {
			t.Errorf("wrong owner after restore for %s: %q", id, p.OwnerNodeID)
		}
		if p.Spec == nil || p.Spec.Image != "img-"+id {
			t.Errorf("spec lost in snapshot/restore for %s: got %+v", id, p.Spec)
		}
	}
	if got := dst.idsOwnedBy("owner-a"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("owner index was not rebuilt on restore: %+v", got)
	}
}

func TestFSMSnapshotOmitsRecoveryPayload(t *testing.T) {
	fsm := newPlacementFSM()
	payload, _ := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb-secret",
		OwnerNodeID: "node-a",
		Spec:        &models.CreateSandboxRequest{Image: "unique-image-only-in-recovery"},
	})
	if got := fsm.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("place: %v", got)
	}
	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	raw := sink.Buffer.Bytes()
	if bytes.Contains(raw, []byte("unique-image-only-in-recovery")) {
		t.Fatalf("snapshot persisted recovery payload")
	}
}

func TestFSMStoresSecretRefWithoutReplicatedPayload(t *testing.T) {
	fsm := newPlacementFSM()

	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a",
		Spec:          &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256},
		IncarnationID: "inc-secret", SecretRef: testSecretRef("sb1", "inc-secret"),
		SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 1,
	})
	if got := fsm.Apply(&raft.Log{Data: place}); got != nil {
		t.Fatalf("opPlace: %v", got)
	}
	p, _ := fsm.get("sb1")
	if p.SecretRef != testSecretRef("sb1", "inc-secret") || p.SecretVersion != secretspkg.RefVersion {
		t.Fatalf("secret handle = (%q,%d), want ref v1", p.SecretRef, p.SecretVersion)
	}

	upsert, _ := encodeCommand(command{
		Op: opUpsertSpec, SandboxID: "sb1", ExpectedIncarnationID: "inc-secret",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 2, MemoryMB: 512},
	})
	if got := fsm.Apply(&raft.Log{Data: upsert}); got != nil {
		t.Fatalf("opUpsertSpec: %v", got)
	}
	p, _ = fsm.get("sb1")
	if p.SecretRef != testSecretRef("sb1", "inc-secret") || p.SecretVersion != secretspkg.RefVersion {
		t.Fatalf("secret ref was not preserved through spec-only upsert: %+v", p)
	}

	rotated, _ := encodeCommand(command{
		Op: opUpsertSpec, SandboxID: "sb1", ExpectedIncarnationID: "inc-secret", IncarnationID: "inc-secret",
		SecretRef: testSecretRef("sb1", "inc-secret"), SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 2,
	})
	if got := fsm.Apply(&raft.Log{Data: rotated}); got != nil {
		t.Fatalf("opUpsertSpec ref-only: %v", got)
	}
	p, _ = fsm.get("sb1")
	if p.SecretRef != testSecretRef("sb1", "inc-secret") || p.SecretVersion != secretspkg.RefVersion || p.SecretSealGeneration != 2 {
		t.Fatalf("secret ref did not rotate: (%q,%d)", p.SecretRef, p.SecretVersion)
	}
}

func TestFSMReadSnapshotsAreDeepCopies(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op:            opPlace,
		SandboxID:     "sb1",
		OwnerNodeID:   "nodeA",
		IncarnationID: "inc-1",
		Spec: &models.CreateSandboxRequest{
			Image: "alpine",
			Env:   map[string]string{"A": "1"},
			Mounts: []models.MountSpec{{
				Target:      "/mnt/data",
				Options:     map[string]string{"ro": "true"},
				Credentials: map[string]string{"token": "secret"},
			}},
			Tags:             map[string]string{"team": "infra"},
			ContainerCommand: []string{"sleep", "60"},
			Registry:         &models.RegistryAuth{Server: "ghcr.io", Username: "u", Password: "p"},
			Lifecycle:        &models.Lifecycle{StopAtAge: time.Minute},
			GPUs:             &models.GPURequest{Vendor: models.GPUVendorNVIDIA, DeviceIDs: []string{"0"}},
		},
	})
	fsm.Apply(&raft.Log{Data: place})
	add, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-1", Port: 8080, Protocol: "http"})
	fsm.Apply(&raft.Log{Data: add})

	got, ok := fsm.get("sb1")
	if !ok {
		t.Fatal("missing placement")
	}
	got.Spec.Env["A"] = "mutated"
	got.Spec.Mounts[0].Options["ro"] = "false"
	got.Spec.Mounts[0].Credentials["token"] = "mutated"
	got.Spec.Tags["team"] = "mutated"
	got.Spec.ContainerCommand[0] = "rm"
	got.Spec.Registry.Password = "mutated"
	got.Spec.Lifecycle.StopAtAge = 2 * time.Minute
	got.Spec.GPUs.DeviceIDs[0] = "1"
	got.ExposedPorts[8080] = "tcp"

	again, _ := fsm.get("sb1")
	if again.Spec.Env["A"] != "1" ||
		again.Spec.Mounts[0].Options["ro"] != "true" ||
		again.Spec.Mounts[0].Credentials["token"] != "secret" ||
		again.Spec.Tags["team"] != "infra" ||
		again.Spec.ContainerCommand[0] != "sleep" ||
		again.Spec.Registry.Password != "p" ||
		again.Spec.Lifecycle.StopAtAge != time.Minute ||
		again.Spec.GPUs.DeviceIDs[0] != "0" ||
		again.ExposedPorts[8080] != "http" {
		t.Fatalf("mutating get() result changed FSM state: %+v", again)
	}

	snap := fsm.snapshot()
	snap["sb1"].Spec.Env["A"] = "snap-mutated"
	snap["sb1"].ExposedPorts[8080] = "tls"
	afterSnap, _ := fsm.get("sb1")
	if afterSnap.Spec.Env["A"] != "1" || afterSnap.ExposedPorts[8080] != "http" {
		t.Fatalf("mutating snapshot() result changed FSM state: %+v", afterSnap)
	}
}

// TestFSMRejectsDuplicateName confirms cluster-wide name uniqueness: two
// opPlace commands carrying the same Name on different sandbox IDs make the
// second one fail with ErrNameConflict. Without this check, two concurrent
// creates landing on different owners would both succeed and any name-based
// facade lookup would resolve ambiguously.
func TestFSMRejectsDuplicateName(t *testing.T) {
	fsm := newPlacementFSM()
	specA := &models.CreateSandboxRequest{Name: "shared"}
	specB := &models.CreateSandboxRequest{Name: "shared"}

	payloadA, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "node-1", Spec: specA})
	if got := fsm.Apply(&raft.Log{Data: payloadA}); got != nil {
		t.Fatalf("first place failed: %v", got)
	}
	payloadB, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-b", OwnerNodeID: "node-2", Spec: specB})
	got := fsm.Apply(&raft.Log{Data: payloadB})
	err, _ := got.(error)
	if err == nil || !errors.Is(err, ErrNameConflict) {
		t.Fatalf("second place returned %v, want ErrNameConflict", got)
	}
	// The first placement must remain untouched — a rejected apply mustn't
	// leak partial state into the FSM.
	if p, ok := fsm.get("sb-a"); !ok || p.OwnerNodeID != "node-1" {
		t.Fatalf("first placement disturbed by rejected apply: %+v ok=%v", p, ok)
	}
	if _, ok := fsm.get("sb-b"); ok {
		t.Fatal("rejected place left a placement behind for sb-b")
	}
}

// TestFSMNameReleasedOnDelete confirms the nameIndex frees the slot when a
// placement is deleted, so a follow-up create with the same name succeeds.
func TestFSMNameReleasedOnDelete(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Name: "freed"}
	payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "node-1", IncarnationID: "inc-a", Spec: spec})
	if got := fsm.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("place: %v", got)
	}
	delPayload, _ := encodeCommand(command{Op: opDelete, SandboxID: "sb-a", ExpectedIncarnationID: "inc-a"})
	if got := fsm.Apply(&raft.Log{Data: delPayload}); got != nil {
		t.Fatalf("delete: %v", got)
	}
	// New sandbox with same name should now succeed.
	rePayload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-b", OwnerNodeID: "node-2", Spec: &models.CreateSandboxRequest{Name: "freed"}})
	if got := fsm.Apply(&raft.Log{Data: rePayload}); got != nil {
		t.Fatalf("re-place after delete failed: %v", got)
	}
}

// TestFSMSamePlacementSameNameIdempotent confirms repeating opPlace for the
// same sandbox_id with the same name is not flagged as a name conflict.
// Without this, the create-then-retry idempotency contract on RecordPlacement
// would break the moment we add cluster-wide name validation.
func TestFSMSamePlacementSameNameIdempotent(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Name: "stable"}
	payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "node-1", Spec: spec, IncarnationID: "inc-a"})
	retry, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "node-1", Spec: spec, IncarnationID: "inc-a", ExpectedIncarnationID: "inc-a"})
	if got := fsm.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("first place: %v", got)
	}
	if got := fsm.Apply(&raft.Log{Data: retry}); got != nil {
		t.Fatalf("idempotent re-place rejected: %v", got)
	}
}

// TestFSMRestoreRebuildsNameIndex confirms a snapshot restore reconstructs
// the name→id map. Older snapshots predate the index, so a name conflict
// after Restore would be missed without the rebuild.
func TestFSMRestoreRebuildsNameIndex(t *testing.T) {
	src := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Name: "preserved"}
	payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "node-1", Spec: spec})
	if got := src.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("place: %v", got)
	}

	// Snapshot + restore into a fresh FSM.
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	dst := newPlacementFSMWithRecoveryStore(src.recoveryStore)
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// A second sandbox with the same name should now collide on the
	// restored index.
	collidePayload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-b", OwnerNodeID: "node-2", Spec: &models.CreateSandboxRequest{Name: "preserved"}})
	got := dst.Apply(&raft.Log{Data: collidePayload})
	err2, _ := got.(error)
	if err2 == nil || !errors.Is(err2, ErrNameConflict) {
		t.Fatalf("restored FSM did not enforce name uniqueness: got %v", got)
	}
}

// TestFSMSubscribeFiresOnApply confirms that subscribers receive a wake
// signal after every Apply. The ingress reconciler relies on this to
// converge in <1s after a placement change instead of waiting out the
// reconcile timer.
func TestFSMSubscribeFiresOnApply(t *testing.T) {
	fsm := newPlacementFSM()
	wake := make(chan struct{}, 1)
	cancel := fsm.subscribe(wake)
	defer cancel()

	cmd := command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA"}
	payload, _ := encodeCommand(cmd)
	if got := fsm.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("apply: %v", got)
	}
	select {
	case <-wake:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("subscriber did not receive wake after FSM apply")
	}
}

// TestFSMSubscribeCoalesces confirms multiple applies between reads collapse
// to one wake. notifySubscribers does non-blocking sends, so a slow
// reconciler doesn't accumulate a backlog.
func TestFSMSubscribeCoalesces(t *testing.T) {
	fsm := newPlacementFSM()
	wake := make(chan struct{}, 1)
	cancel := fsm.subscribe(wake)
	defer cancel()

	for i := 0; i < 5; i++ {
		cmd := command{Op: opDelete, SandboxID: "sb-x"}
		payload, _ := encodeCommand(cmd)
		fsm.Apply(&raft.Log{Data: payload})
	}
	// Drain the one available wake.
	select {
	case <-wake:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected at least one wake")
	}
	// No second wake should be readable; cap=1 dropped the rest.
	select {
	case <-wake:
		t.Fatal("subscriber received more than one wake from coalesced applies")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestFSMSubscribeCancel deregisters a subscriber. After cancel, an apply
// must not wake the channel.
func TestFSMSubscribeCancel(t *testing.T) {
	fsm := newPlacementFSM()
	wake := make(chan struct{}, 1)
	cancel := fsm.subscribe(wake)
	cancel()

	cmd := command{Op: opDelete, SandboxID: "sb-y"}
	payload, _ := encodeCommand(cmd)
	fsm.Apply(&raft.Log{Data: payload})

	select {
	case <-wake:
		t.Fatal("subscriber received wake after cancel")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestFSMVersionTracksLogIndex pins the B9 fix: f.version must follow the
// raft log index, not a per-process counter. Without this, watchers see the
// revision regress to 0 after every restart, and the same revision value can
// refer to different states on different nodes.
func TestFSMVersionTracksLogIndex(t *testing.T) {
	fsm := newPlacementFSM()
	for _, idx := range []uint64{10, 11, 17, 42} {
		expected := ""
		if idx != 10 {
			expected = "inc-1"
		}
		cmd, _ := encodeCommand(command{
			Op: opPlace, SandboxID: "sb1", OwnerNodeID: "n1", OwnerAPIURL: "http://n1",
			Spec: &models.CreateSandboxRequest{Image: "img", CPU: 1, MemoryMB: 64}, IncarnationID: "inc-1", ExpectedIncarnationID: expected,
		})
		fsm.Apply(&raft.Log{Index: idx, Data: cmd})
		if got := fsm.currentVersion(); got != idx {
			t.Fatalf("after Apply(Index=%d) version = %d, want %d", idx, got, idx)
		}
		p, _ := fsm.get("sb1")
		if p.Version != idx {
			t.Fatalf("Placement.Version = %d, want log index %d", p.Version, idx)
		}
	}
}

// TestFSMSnapshotPreservesVersion pins that the version survives a
// snapshot/restore round trip — the durable-revision half of B9. A fresh FSM
// instance restored from the snapshot must report the original version so
// watchers can pick up exactly where they left off.
func TestFSMSnapshotPreservesVersion(t *testing.T) {
	src := newPlacementFSM()
	cmd, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb1", OwnerNodeID: "n1", OwnerAPIURL: "http://n1",
		Spec: &models.CreateSandboxRequest{Image: "img", CPU: 1, MemoryMB: 64},
	})
	src.Apply(&raft.Log{Index: 99, Data: cmd})

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}

	dst := newPlacementFSMWithRecoveryStore(src.recoveryStore)
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := dst.currentVersion(); got != 99 {
		t.Fatalf("restored version = %d, want 99", got)
	}
}

// TestFSMRestoreLegacySnapshotRecoversVersion exercises the bare-map fallback
// in Restore: a snapshot written before the envelope existed must still load,
// and its version must be derived from the highest Placement.Version so
// watchers don't see a regression to 0.
func TestFSMRestoreLegacySnapshotRecoversVersion(t *testing.T) {
	legacy := map[string]Placement{
		"sb1": {SandboxID: "sb1", OwnerNodeID: "n1", Version: 7},
		"sb2": {SandboxID: "sb2", OwnerNodeID: "n2", Version: 42},
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(legacy); err != nil {
		t.Fatalf("encode legacy: %v", err)
	}

	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatalf("restore legacy: %v", err)
	}
	if got := dst.currentVersion(); got != 42 {
		t.Fatalf("legacy restore version = %d, want max placement.Version 42", got)
	}
	if _, ok := dst.get("sb1"); !ok {
		t.Fatal("sb1 missing after legacy restore")
	}
}

// TestFSMSnapshotIsolatedFromLaterApplies is the load-bearing B8 claim: an
// fsmSnapshot returned by Snapshot() must encode the state at snapshot time
// even when later Applies mutate the FSM before Persist runs. Raft can defer
// Persist arbitrarily long, so without per-value deep-copy here a snapshot
// would silently capture post-snapshot state for any reference-typed field
// (Spec, ExposedPorts) — that would break log truncation
// safety: replaying the truncated tail against the persisted snapshot would
// double-apply mutations the snapshot already absorbed.
func TestFSMSnapshotIsolatedFromLaterApplies(t *testing.T) {
	src := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb1",
		OwnerNodeID: "nodeA",
		Spec: &models.CreateSandboxRequest{
			Image: "alpine:before",
			Env:   map[string]string{"K": "before"},
		},
		IncarnationID: "inc-snapshot", SecretRef: testSecretRef("sb1", "inc-snapshot"), SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 1,
	})
	src.Apply(&raft.Log{Data: place})

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// Mutate the FSM AFTER the snapshot is taken but BEFORE Persist runs.
	// Both opUpsertSpec (replaces the Spec pointer and secret handle) and a
	// fresh opPlace (new owner / version) must not leak into the persisted
	// bytes.
	upsert, _ := encodeCommand(command{
		Op:                    opUpsertSpec,
		SandboxID:             "sb1",
		ExpectedIncarnationID: "inc-snapshot",
		Spec: &models.CreateSandboxRequest{
			Image: "alpine:after",
			Env:   map[string]string{"K": "after"},
		},
		IncarnationID: "inc-snapshot", SecretRef: testSecretRef("sb1", "inc-snapshot"), SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 2,
	})
	src.Apply(&raft.Log{Data: upsert})

	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}

	dst := newPlacementFSMWithRecoveryStore(src.recoveryStore)
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, ok := dst.get("sb1")
	if !ok {
		t.Fatal("sb1 missing after restore")
	}
	if got.Spec == nil || got.Spec.Image != "alpine:before" {
		t.Fatalf("snapshot leaked post-snapshot Spec mutation: spec=%+v", got.Spec)
	}
	if got.Spec.Env["K"] != "before" {
		t.Fatalf("snapshot leaked post-snapshot Env mutation: K=%q", got.Spec.Env["K"])
	}
	if got.SecretRef != testSecretRef("sb1", "inc-snapshot") {
		t.Fatalf("snapshot leaked post-snapshot secret-handle mutation: %q", got.SecretRef)
	}
}

// TestFSMSnapshotIsolatedFromExposedPortMutations pins the tricky half of B8:
// opAddExposedPort and opRemoveExposedPort mutate Placement.ExposedPorts /
// ExposedPortRoutes IN PLACE (the maps are reference types, and apply rewrites
// keys on the same map then re-stores the Placement value). A naive snapshot
// that copied the map header without cloning entries would let later port
// mutations bleed into the persisted bytes. This test exercises that exact
// path: snapshot, then add/remove ports, then persist, then assert the
// snapshot's port set matches the pre-mutation state.
func TestFSMSnapshotIsolatedFromExposedPortMutations(t *testing.T) {
	src := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA",
		Spec: &models.CreateSandboxRequest{Image: "alpine"}, IncarnationID: "inc-snapshot",
	})
	src.Apply(&raft.Log{Data: place})
	add80, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-snapshot", Port: 80, Protocol: "http"})
	src.Apply(&raft.Log{Data: add80})

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// After the snapshot: add a NEW port and remove the original. If the
	// snapshot aliased the live ExposedPorts map, both mutations would
	// leak — the persisted state would show port 443 (added later) and
	// miss port 80 (removed later).
	add443, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-snapshot", Port: 443, Protocol: "tls"})
	src.Apply(&raft.Log{Data: add443})
	rm80, _ := encodeCommand(command{Op: opRemoveExposedPort, SandboxID: "sb1", ExpectedIncarnationID: "inc-snapshot", Port: 80})
	src.Apply(&raft.Log{Data: rm80})

	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}

	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, ok := dst.get("sb1")
	if !ok {
		t.Fatal("sb1 missing after restore")
	}
	if got.ExposedPorts[80] != "http" {
		t.Fatalf("snapshot lost port 80: ExposedPorts=%v", got.ExposedPorts)
	}
	if _, present := got.ExposedPorts[443]; present {
		t.Fatalf("snapshot leaked port 443 added after Snapshot(): ExposedPorts=%v", got.ExposedPorts)
	}
	if got.ExposedPortRoutes[80].Protocol != "http" {
		t.Fatalf("snapshot lost ExposedPortRoutes[80]: %+v", got.ExposedPortRoutes)
	}
	if _, present := got.ExposedPortRoutes[443]; present {
		t.Fatalf("snapshot leaked ExposedPortRoutes[443]: %+v", got.ExposedPortRoutes)
	}
}

// TestFSMReassignFailoverReportsOnlyRealTransitions is the regression test for
// counting failover reassigns off the raft ack instead of the FSM transition.
// The ack is wrong in both directions:
//
//   - Overcount: opReassign against a deleted placement hits the no-op branch
//     and returns success, so an ack-counting caller records a reassign that
//     never happened.
//   - Undercount: a forwarded opReassign can commit on the leader while its
//     HTTP acknowledgment is lost, so an ack-counting caller misses a reassign
//     that did happen.
//
// Applying straight to the FSM here proves that the leader wrapper receives
// an authoritative changed bit. It also models follower replay: direct FSM
// application must not increment the process-local counter.
func TestFSMReassignFailoverReportsOnlyRealTransitions(t *testing.T) {
	fsm := newPlacementFSM()

	// Raced delete: reassign a placement that isn't there. The FSM no-ops
	// ("delete wins") and must not count it.
	missing, _ := encodeCommand(command{
		Op: opReassign, SandboxID: "sb-gone", OwnerNodeID: "nodeB",
		ExpectedIncarnationID: "inc-gone", ReassignCause: reassignCauseFailover,
	})
	before := clusterFailoverReassignTotal.Value()
	got, ok := fsm.Apply(&raft.Log{Index: 1, Data: missing}).(reassignApplyResult)
	if !ok || got.Changed {
		t.Fatalf("missing reassign result = %+v ok=%v, want Changed=false", got, ok)
	}
	if got := clusterFailoverReassignTotal.Value() - before; got != 0 {
		t.Fatalf("direct FSM apply changed metric by %d, want 0", got)
	}

	// Real transition: place, then reassign. The FSM reports changed, while
	// the leader wrapper remains responsible for the one process-local count.
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", IncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Index: 2, Data: place})

	real, _ := encodeCommand(command{
		Op: opReassign, SandboxID: "sb1", OwnerNodeID: "nodeB",
		ExpectedIncarnationID: "inc-1", ReassignCause: reassignCauseFailover,
	})
	before = clusterFailoverReassignTotal.Value()
	got, ok = fsm.Apply(&raft.Log{Index: 3, Data: real}).(reassignApplyResult)
	if !ok || !got.Changed {
		t.Fatalf("real reassign result = %+v ok=%v, want Changed=true", got, ok)
	}
	if got := clusterFailoverReassignTotal.Value() - before; got != 0 {
		t.Fatalf("direct FSM apply changed metric by %d, want 0", got)
	}
	if p, ok := fsm.get("sb1"); !ok || p.OwnerNodeID != "nodeB" {
		t.Fatalf("ownership did not move: %+v ok=%v", p, ok)
	}

	// A retry that targets the owner already installed by the first command is
	// an idempotent state refresh, not another failover reassignment.
	redundant, _ := encodeCommand(command{
		Op: opReassign, SandboxID: "sb1", OwnerNodeID: "nodeB",
		ExpectedIncarnationID: "inc-1", ReassignCause: reassignCauseFailover,
	})
	got, ok = fsm.Apply(&raft.Log{Index: 4, Data: redundant}).(reassignApplyResult)
	if !ok || got.Changed {
		t.Fatalf("redundant reassign result = %+v ok=%v, want Changed=false", got, ok)
	}
}

// TestFSMReassignMetricIgnoresOperatorReassign pins the scope of the counter.
// opReassign has four producers: two failover paths and two operator /
// live-migration paths (Cluster.ReassignPlacement, Agent.ReassignPlacement).
// Only the failover ones tag a cause, so a WASM live migration must not inflate
// aerolvm_cluster_failover_reassign_total.
func TestFSMReassignMetricIgnoresOperatorReassign(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", IncarnationID: "inc-1"})
	fsm.Apply(&raft.Log{Index: 1, Data: place})

	// No ReassignCause — what ReassignPlacement emits.
	operator, _ := encodeCommand(command{Op: opReassign, SandboxID: "sb1", OwnerNodeID: "nodeB", ExpectedIncarnationID: "inc-1"})
	before := clusterFailoverReassignTotal.Value()
	fsm.Apply(&raft.Log{Index: 2, Data: operator})

	if got := clusterFailoverReassignTotal.Value() - before; got != 0 {
		t.Fatalf("failover reassign delta = %d for an operator reassign, want 0", got)
	}
	if p, ok := fsm.get("sb1"); !ok || p.OwnerNodeID != "nodeB" {
		t.Fatalf("operator reassign must still move ownership: %+v ok=%v", p, ok)
	}
}

// TestFSMReassignCauseDoesNotAffectState pins that ReassignCause is
// observability-only. Tagged and untagged current-format commands produce the
// same placement state; only the metric differs.
func TestFSMReassignCauseDoesNotAffectState(t *testing.T) {
	apply := func(cause string) Placement {
		t.Helper()
		fsm := newPlacementFSM()
		place, _ := encodeCommand(command{
			Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a:8080",
			IncarnationID: "inc-1",
		})
		fsm.Apply(&raft.Log{Index: 1, Data: place})
		reassign, _ := encodeCommand(command{
			Op: opReassign, SandboxID: "sb1", OwnerNodeID: "nodeB",
			OwnerAPIURL: "http://b:8080", ExpectedIncarnationID: "inc-1", ReassignCause: cause,
		})
		fsm.Apply(&raft.Log{Index: 2, Data: reassign})
		p, ok := fsm.get("sb1")
		if !ok {
			t.Fatal("placement missing after reassign")
		}
		return p
	}

	untagged := apply("")
	tagged := apply(reassignCauseFailover)

	if untagged.OwnerNodeID != tagged.OwnerNodeID ||
		untagged.OwnerAPIURL != tagged.OwnerAPIURL ||
		untagged.OwnerState != tagged.OwnerState ||
		untagged.Version != tagged.Version {
		t.Fatalf("ReassignCause changed the applied state:\n untagged=%+v\n tagged=%+v", untagged, tagged)
	}
}
