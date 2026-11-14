package cluster

import (
	"bytes"
	"context"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// applyOrFail applies cmd to fsm and fails on an error answer.
func applyOrFail(t *testing.T, fsm *placementFSM, cmd command) {
	t.Helper()
	raw, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got := fsm.Apply(&raft.Log{Data: raw}); got != nil {
		if err, ok := got.(error); ok {
			t.Fatalf("apply %v: %v", cmd.Op, err)
		}
	}
}

func orphanedRecoveryIDs(fsm *placementFSM) []string {
	ids, _ := fsm.orphanedRecoveryPage("", 1000)
	return ids
}

// The backlog index holds exactly the orphaned placements that want a
// failover recreate (R14), through every way a row is orphaned, given an
// owner again or deleted, and a snapshot restore rebuilds it.
func TestOrphanedRecoveryIndex(t *testing.T) {
	fsm := newPlacementFSM()
	recreate := &models.CreateSandboxRequest{Image: "alpine", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	plain := &models.CreateSandboxRequest{Image: "alpine"}
	for _, p := range []struct {
		id   string
		spec *models.CreateSandboxRequest
	}{{"sb-a", recreate}, {"sb-b", recreate}, {"sb-c", recreate}, {"sb-plain", plain}} {
		applyOrFail(t, fsm, command{Op: opPlace, SandboxID: p.id, OwnerNodeID: "dead", IncarnationID: "inc-" + p.id, Spec: p.spec})
	}
	if got := orphanedRecoveryIDs(fsm); len(got) != 0 {
		t.Fatalf("placed rows in the backlog: %v", got)
	}
	// The owner dies with no room anywhere: every row is orphaned, and the
	// recreate-policy ones join the backlog.
	applyOrFail(t, fsm, command{Op: opOrphanOwner, NodeID: "dead"})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-a", "sb-b", "sb-c"}) {
		t.Fatalf("after the owner died: %v", got)
	}
	// Paging walks it in order from a cursor.
	if page, end := fsm.orphanedRecoveryPage("", 2); !slices.Equal(page, []string{"sb-a", "sb-b"}) || end {
		t.Fatalf("first page %v end %v", page, end)
	}
	if page, end := fsm.orphanedRecoveryPage("sb-b", 2); !slices.Equal(page, []string{"sb-c"}) || !end {
		t.Fatalf("second page %v end %v", page, end)
	}
	// One finds a node; one is deleted.
	applyOrFail(t, fsm, command{Op: opReassign, SandboxID: "sb-a", OwnerNodeID: "fresh", ExpectedIncarnationID: "inc-sb-a",
		ExpectedOwnerNodeIDSet: true, ReassignCause: reassignCauseFailover})
	applyOrFail(t, fsm, command{Op: opDelete, SandboxID: "sb-b", ExpectedIncarnationID: "inc-sb-b"})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-c"}) {
		t.Fatalf("after a recovery and a delete: %v", got)
	}
	// A target refusing it for capacity hands it back as an orphan.
	applyOrFail(t, fsm, command{Op: opReassign, SandboxID: "sb-a", ExpectedIncarnationID: "inc-sb-a",
		ExpectedOwnerNodeID: "fresh", ExpectedOwnerNodeIDSet: true})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-a", "sb-c"}) {
		t.Fatalf("after a hand-back: %v", got)
	}

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	if got := orphanedRecoveryIDs(restored); !slices.Equal(got, []string{"sb-a", "sb-c"}) || restored.orphanedRecoveryLen() != 2 {
		t.Fatalf("after a restore: %v", got)
	}
}

// The reviewer's case (R14): a worker dies while no node has room, so its
// recreate-policy sandbox is orphaned. The autoscaler then adds a worker
// with room, and the leader's next pass moves the sandbox to it.
func TestFailoverMustRetryAfterCapacityReturns(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-backlog", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	p := placeFailoverPlacement(t, c, "sb-no-capacity", "permanently-dead-worker")
	c.evictDeadOwner(context.Background(), p.OwnerNodeID)
	if after, _ := c.fsm.get(p.SandboxID); !after.IsOrphaned() {
		t.Fatalf("expected an orphan for want of room, got owner %q", after.OwnerNodeID)
	}
	// Still no room: the pass leaves it, and the backlog shows it.
	c.reconcileDeadOwners(context.Background())
	if after, _ := c.fsm.get(p.SandboxID); !after.IsOrphaned() || failoverRecoveryBacklog.Value() != 1 {
		t.Fatalf("moved with no room: owner %q backlog %d", after.OwnerNodeID, failoverRecoveryBacklog.Value())
	}

	seedGossipView(t, c, []Member{recreateCandidate("new-capacity", config.NodeRoleWorker, 100)})
	before := failoverRecoveryRecovered.Value()
	c.reconcileDeadOwners(context.Background())
	after, _ := c.fsm.get(p.SandboxID)
	if after.IsOrphaned() || after.OwnerNodeID != "new-capacity" || after.IncarnationID != p.IncarnationID {
		t.Fatalf("still orphaned after capacity returned: owner=%q orphanedFrom=%q", after.OwnerNodeID, after.OrphanedOwnerNodeID)
	}
	if failoverRecoveryRecovered.Value() != before+1 || failoverRecoveryBacklog.Value() != 0 {
		t.Fatalf("recovered %d (want +1), backlog %d", failoverRecoveryRecovered.Value()-before, failoverRecoveryBacklog.Value())
	}
}

// An orphan whose previous owner is alive (it refused the sandbox for
// capacity, or it came back and may reclaim it) waits first, then moves to
// another node, never back to that one.
func TestOrphanRetryWaitsForALiveOwnerThenGoesElsewhere(t *testing.T) {
	old := orphanRetryAliveWait
	t.Cleanup(func() { orphanRetryAliveWait = old })
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-alive", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	// The refuser has the most room on paper, as a node whose heartbeat is
	// behind its admission does.
	seedGossipView(t, c, []Member{
		recreateCandidate("refuser", config.NodeRoleWorker, 120),
		recreateCandidate("other", config.NodeRoleWorker, 20),
	})
	p := placeFailoverPlacement(t, c, "sb-refused", "refuser")
	// handBackRefusedPlacement's write: the refuser gives it back.
	if err := c.applyCommand(context.Background(), command{Op: opReassign, SandboxID: p.SandboxID,
		ExpectedIncarnationID: p.IncarnationID, ExpectedOwnerNodeID: "refuser", ExpectedOwnerNodeIDSet: true}); err != nil {
		t.Fatal(err)
	}

	orphanRetryAliveWait = time.Hour
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 0 {
		t.Fatalf("moved %d before the live owner's wait", moved)
	}
	orphanRetryAliveWait = 0
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 1 {
		t.Fatalf("moved %d after the wait, want 1", moved)
	}
	if after, _ := c.fsm.get(p.SandboxID); after.OwnerNodeID != "other" {
		t.Fatalf("owner %q, want other: never back to the node that refused it", after.OwnerNodeID)
	}
}

// The leader walks a backlog bigger than one page across passes.
func TestOrphanRetryWalksTheBacklogAcrossPasses(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-pages", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	n := orphanRetryPage + 3
	for i := range n {
		placeFailoverPlacement(t, c, "sb-"+string(rune('a'+i/26))+string(rune('a'+i%26)), "gone-worker")
	}
	if err := c.applyCommand(context.Background(), command{Op: opOrphanOwner, NodeID: "gone-worker"}); err != nil {
		t.Fatal(err)
	}
	// Room for all of them: the FSM counts each move against its target
	// until that target's next heartbeat.
	seedGossipView(t, c, []Member{
		recreateCandidate("room-1", config.NodeRoleWorker, 128),
		recreateCandidate("room-2", config.NodeRoleWorker, 128),
		recreateCandidate("room-3", config.NodeRoleWorker, 128),
	})
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != orphanRetryPage {
		t.Fatalf("first pass moved %d, want a page of %d", moved, orphanRetryPage)
	}
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 3 {
		t.Fatalf("second pass moved %d, want the last 3", moved)
	}
	if c.fsm.orphanedRecoveryLen() != 0 {
		t.Fatalf("backlog left: %d", c.fsm.orphanedRecoveryLen())
	}
}
