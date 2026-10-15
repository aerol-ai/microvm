package cluster

import (
	"context"
	"testing"
	"time"
)

// TestClusterSnapshotNodeClientRoundTrip exercises the real raft apply + local
// FSM read path for the snapshot-home index on a voter Cluster.
func TestClusterSnapshotNodeClientRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft sockets")
	}
	c, cleanup := newTestCluster(t, "ldr-snap-client", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if _, found, err := c.SnapshotHomeNode(ctx, "snap-a"); err != nil || found {
		t.Fatalf("home before register = found=%v err=%v, want not-found", found, err)
	}
	if err := c.RegisterSnapshotNode(ctx, "snap-a", "node-x"); err != nil {
		t.Fatalf("RegisterSnapshotNode: %v", err)
	}
	node, found, err := c.SnapshotHomeNode(ctx, "snap-a")
	if err != nil || !found || node != "node-x" {
		t.Fatalf("home after register = %q,%v,%v, want node-x/true/nil", node, found, err)
	}
	// Re-register moves the home.
	if err := c.RegisterSnapshotNode(ctx, "snap-a", "node-y"); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if node, _, _ := c.SnapshotHomeNode(ctx, "snap-a"); node != "node-y" {
		t.Fatalf("home after re-register = %q, want node-y", node)
	}
	// Forget.
	if err := c.ForgetSnapshotNode(ctx, "snap-a"); err != nil {
		t.Fatalf("ForgetSnapshotNode: %v", err)
	}
	if _, found, _ := c.SnapshotHomeNode(ctx, "snap-a"); found {
		t.Fatal("snapshot still has a home after forget")
	}

	// Validation + no-op forget.
	if err := c.RegisterSnapshotNode(ctx, "", "node-x"); err == nil {
		t.Fatal("register with empty name should error")
	}
	if err := c.RegisterSnapshotNode(ctx, "snap-a", ""); err == nil {
		t.Fatal("register with empty node should error")
	}
	if err := c.ForgetSnapshotNode(ctx, ""); err != nil {
		t.Fatalf("forget with empty name should be a no-op, got %v", err)
	}
}
