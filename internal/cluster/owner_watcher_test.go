package cluster

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// recordingRecreator captures every RecreateSandbox call so a test can assert
// the cluster owner watcher fired with the expected (id, spec) tuple.
type recordingRecreator struct {
	mu    sync.Mutex
	calls map[string]models.CreateSandboxRequest
	err   error
}

func newRecordingRecreator() *recordingRecreator {
	return &recordingRecreator{calls: make(map[string]models.CreateSandboxRequest)}
}

func (r *recordingRecreator) RecreateSandbox(_ context.Context, id string, spec models.CreateSandboxRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[id] = spec
	return r.err
}

func (r *recordingRecreator) get(id string) (models.CreateSandboxRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.calls[id]
	return s, ok
}

// TestOwnerWatcherSkipsWithoutSpec verifies a placement with no Spec doesn't
// trigger a recreate call — the recreator can't reconstruct without the spec.
func TestOwnerWatcherSkipsWithoutSpec(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	// Placement owned by self, but no Spec.
	cmd := command{Op: opPlace, SandboxID: "sb-no-spec", OwnerNodeID: "leader"}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	c.recreateOwnedSandboxes(context.Background())
	if _, ok := rec.get("sb-no-spec"); ok {
		t.Fatal("recreator should not have been invoked for placement without spec")
	}
}

// TestOwnerWatcherRecreatesOwnedSandbox is the headline failover test: a
// placement carrying a spec and pointing to self drives the watcher to call
// the recreator with the original ID and replicated spec.
func TestOwnerWatcherRecreatesOwnedSandbox(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512}
	cmd := command{Op: opPlace, SandboxID: "sb-failover", OwnerNodeID: "leader", Spec: spec}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	c.recreateOwnedSandboxes(context.Background())
	got, ok := rec.get("sb-failover")
	if !ok {
		t.Fatal("recreator was not invoked for sb-failover")
	}
	if got.Image != "alpine" || got.CPU != 1 || got.MemoryMB != 512 {
		t.Fatalf("recreator received wrong spec: %+v", got)
	}
}

// TestEvictThenWatcherEndToEnd is the end-to-end pipeline: a placement on a
// dead node carries a spec; eviction reassigns it to the live leader; the
// next watcher tick recreates it via the mock recreator. This is the
// failover-recreation scenario expressed against a single-node test cluster
// (the leader picks itself as the recreation target via SelectPlacement's
// fallback-to-self).
func TestEvictThenWatcherEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 0.5, MemoryMB: 256}
	cmd := command{
		Op: opPlace, SandboxID: "sb-e2e", OwnerNodeID: "dead-node", OwnerAPIURL: "http://gone",
		Spec: spec,
	}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.evictDeadOwner(ctx, "dead-node")

	owner, err := c.OwnerOf("sb-e2e")
	if err != nil || owner.NodeID != "leader" {
		t.Fatalf("post-evict OwnerOf = %+v err=%v, want NodeID=leader", owner, err)
	}

	c.recreateOwnedSandboxes(ctx)
	got, ok := rec.get("sb-e2e")
	if !ok {
		t.Fatal("recreator was not invoked after evict + watcher tick")
	}
	if got.Image != "alpine" {
		t.Fatalf("recreator received wrong spec: %+v", got)
	}
}
