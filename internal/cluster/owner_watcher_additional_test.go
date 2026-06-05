package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestRecreateFailureTracker(t *testing.T) {
	tr := &recreateFailureTracker{counts: make(map[string]int)}
	if c := tr.record("a"); c != 1 {
		t.Errorf("expected 1, got %d", c)
	}
	if c := tr.record("a"); c != 2 {
		t.Errorf("expected 2, got %d", c)
	}
	tr.clear("a")
	if tr.counts["a"] != 0 {
		t.Errorf("expected clear to remove")
	}
}

type failingRecreator struct {
	*recordingRecreator
}

func (r *failingRecreator) RecreateSandbox(ctx context.Context, id string, spec models.CreateSandboxRequest, secrets PlacementSecrets, ports map[int]ExposedPortRoute) error {
	r.recordingRecreator.RecreateSandbox(ctx, id, spec, secrets, ports)
	return errors.New("simulated failure")
}

func TestOwnerWatcherRecreateFailureAndReassign(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	// Add an alternate target
	index := newGossipMemberIndex()
	index.replace([]Member{
		recreateCandidate("leader", "worker", 10),
		recreateCandidate("alt-worker", "worker", 100),
	})
	c.gossip = &gossipNode{memberIndex: index}

	rec := &failingRecreator{recordingRecreator: newRecordingRecreator()}
	c.AttachRecreator(rec)
	c.recreateFailures = &recreateFailureTracker{counts: make(map[string]int)}

	spec := failoverRecreateSpec()
	cmd := command{Op: opPlace, SandboxID: "sb-fail", OwnerNodeID: "leader", Spec: spec}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	// Trigger watcher multiple times to hit maxRecreateFailuresBeforeReassign
	ctx := context.Background()
	for i := 0; i < maxRecreateFailuresBeforeReassign-1; i++ {
		c.recreateOwnedSandboxes(ctx)
		owner, _ := c.OwnerOf("sb-fail")
		if owner.NodeID != "leader" {
			t.Fatalf("owner should not be reassigned yet, got %v", owner.NodeID)
		}
	}

	// The next call should trigger reassign
	c.recreateOwnedSandboxes(ctx)

	// Wait a moment for raft to apply the reassign command
	time.Sleep(100 * time.Millisecond)

	owner, _ := c.OwnerOf("sb-fail")
	if owner.NodeID != "alt-worker" {
		t.Fatalf("owner should have been reassigned to alt-worker, got %v", owner.NodeID)
	}
}

func TestTryReassignStuckPlacementSkipNonRecreate(t *testing.T) {
	c := &Cluster{recreateFailures: &recreateFailureTracker{counts: make(map[string]int)}}
	c.tryReassignStuckPlacement(context.Background(), "sb", Placement{
		Spec: &models.CreateSandboxRequest{},
	})
	// no panic or error means it returned early successfully
}
