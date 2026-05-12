package cluster

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// TestClusterSingleNodeBootstrap is the smallest possible end-to-end test of
// the real raft + memberlist stack: bootstrap a one-node cluster on real
// ports, become leader, commit a placement, read it back. If this fails the
// other cluster tests aren't worth running.
func TestClusterSingleNodeBootstrap(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires opening real raft/memberlist sockets")
	}
	c, cleanup := newTestCluster(t, "n1", true, nil)
	defer cleanup()

	waitForLeader(t, c, 10*time.Second)
	if got := c.Leader(); got != "n1" {
		t.Fatalf("leader = %q, want n1", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.RecordPlacement(ctx, "sb-1"); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	owner, err := c.OwnerOf("sb-1")
	if err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}
	if !owner.IsSelf || owner.NodeID != "n1" {
		t.Fatalf("owner = %+v, want IsSelf=true NodeID=n1", owner)
	}
	if err := c.DeletePlacement(ctx, "sb-1"); err != nil {
		t.Fatalf("DeletePlacement: %v", err)
	}
	if _, err := c.OwnerOf("sb-1"); err == nil {
		t.Fatal("expected ErrUnknownSandbox after delete")
	}

	members := c.Members()
	if len(members) != 1 || members[0].NodeID != "n1" {
		t.Fatalf("members = %+v, want exactly self", members)
	}
}

// TestClusterTwoNodeReplication validates the Phase 2 auto-voter promotion:
// a follower joins via memberlist alone, the leader auto-promotes it to a
// raft voter, and an FSM commit on the leader replicates to the follower.
// No manual AddVoter required.
func TestClusterTwoNodeReplication(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires opening real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestCluster(t, "leader", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	// Follower joins the gossip ring via the leader's gossip address.
	follower, cleanupFollower := newTestCluster(t, "follower", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()

	// Wait for the leader to auto-promote the follower as a raft voter. This
	// happens either via the NotifyJoin event (fast path) or the periodic
	// reconcile loop (slow path) once the follower's gossiped RaftAddr arrives.
	waitForVoter(t, leader, "follower", 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := leader.RecordPlacement(ctx, "sb-replicate"); err != nil {
		t.Fatalf("leader RecordPlacement: %v", err)
	}

	// Poll the follower's FSM until it sees the placement (or times out).
	deadline := time.Now().Add(10 * time.Second)
	var got OwnerInfo
	for time.Now().Before(deadline) {
		o, err := follower.OwnerOf("sb-replicate")
		if err == nil {
			got = o
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got.NodeID != "leader" {
		t.Fatalf("follower OwnerOf returned %+v after timeout, want NodeID=leader", got)
	}
	if got.IsSelf {
		t.Fatal("follower should not see itself as owner of leader-placed sandbox")
	}
}

// --- helpers below ---

// newTestCluster builds a real *Cluster on dynamic ports under t.TempDir().
// bootstrap=true bootstraps a single-voter raft; peers (if non-nil) are gossip
// addresses to join. Returns a cleanup that closes the cluster — defer it.
func newTestCluster(t *testing.T, nodeID string, bootstrap bool, gossipPeers []string) (*Cluster, func()) {
	t.Helper()
	raftPort := pickFreeTCPPort(t)
	gossipPort := pickFreeTCPPort(t)
	dir := t.TempDir()
	apiURL := fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t))

	cfg := config.Config{
		EnableCluster:                 true,
		NodeID:                        nodeID,
		RaftBindAddr:                  fmt.Sprintf("127.0.0.1:%d", raftPort),
		RaftAdvertiseAddr:             fmt.Sprintf("127.0.0.1:%d", raftPort),
		RaftDataDir:                   filepath.Join(dir, "raft"),
		GossipBindAddr:                fmt.Sprintf("127.0.0.1:%d", gossipPort),
		GossipAdvertiseAddr:           fmt.Sprintf("127.0.0.1:%d", gossipPort),
		BootstrapPeers:                gossipPeers,
		ClusterBootstrap:              bootstrap,
		SelfAPIAdvertiseURL:           apiURL,
		ClusterRaftCommitTimeout:      2 * time.Second,
		ClusterCapacityGossipInterval: time.Second,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := New(cfg, logger, nil)
	if err != nil {
		t.Fatalf("cluster.New(%s): %v", nodeID, err)
	}
	return c, func() {
		if err := c.Close(); err != nil {
			t.Logf("cluster.Close(%s): %v", nodeID, err)
		}
	}
}

// pickFreeTCPPort grabs an unused port. There's an inherent race between
// returning the port and the caller binding it, but for an in-process test
// with high random ports the collision risk is negligible.
func pickFreeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickFreeTCPPort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// waitForLeader blocks until the cluster reports a leader, or fails the test.
func waitForLeader(t *testing.T, c *Cluster, max time.Duration) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if c.Leader() != "" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("cluster %q never elected a leader within %s", c.SelfNodeID(), max)
}

// waitForVoter blocks until nodeID appears in the leader's raft configuration
// as a voter (i.e. the auto-voter promotion has fired), or fails the test.
func waitForVoter(t *testing.T, leader *Cluster, nodeID string, max time.Duration) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		cfg := leader.raft.raft.GetConfiguration()
		if cfg.Error() == nil {
			for _, srv := range cfg.Configuration().Servers {
				if string(srv.ID) == nodeID {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("voter %q never appeared in leader config within %s", nodeID, max)
}
