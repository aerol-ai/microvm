package cluster

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// newTestClusterWithRoleAndGrace mirrors newTestClusterWithRole but lets the
// caller shorten ClusterDeadOwnerGrace so tests don't have to wait the full
// 30s production default. Kept narrow on purpose; broader cfg mutators
// belong on newTestClusterWithCfg.
func newTestClusterWithRoleAndGrace(t *testing.T, nodeID, role string, bootstrap bool, gossipPeers []string, grace time.Duration) (*Cluster, func()) {
	t.Helper()
	raftPort := pickFreeTCPPort(t)
	gossipPort := pickFreeTCPPort(t)
	dir := t.TempDir()
	apiURL := fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t))

	cfg := config.Config{
		EnableCluster:                 true,
		NodeID:                        nodeID,
		NodeRole:                      role,
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
		ClusterDeadOwnerGrace:         grace,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := New(cfg, logger, nil)
	if err != nil {
		t.Fatalf("cluster.New(%s, role=%s): %v", nodeID, role, err)
	}
	// Idempotent close: the convergence test deliberately Close()s the
	// worker mid-test, so the deferred cleanup must not double-shut
	// memberlist (which panics).
	var once sync.Once
	return c, func() {
		once.Do(func() {
			if err := c.Close(); err != nil {
				t.Logf("cluster.Close(%s): %v", nodeID, err)
			}
		})
	}
}

// TestRoleSplitConvergenceOnWorkerDeath drives the headline release-gate
// scenario from plans/data-plane-load-balancer.md Phase 5 in a single
// in-process cluster: server bootstraps, worker joins, worker holds a
// placement, worker dies. The leader (server) must orphan the placement
// after SB_DEAD_OWNER_GRACE — at which point ingress nodes would see
// OwnerNodeID="" and stop routing to a dead host.
//
// The test runs entirely in-process — it does not exercise the actual ingress
// reconciler (that lives in internal/service). It does verify the FSM-level
// pipeline that ingress consumes: dead-owner detection → grace expiry →
// orphan in the replicated placement map.
func TestRoleSplitConvergenceOnWorkerDeath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	server, cleanupServer := newTestClusterWithRoleAndGrace(t, "srv-cv", config.NodeRoleServer, true, nil, 200*time.Millisecond)
	defer cleanupServer()
	waitForLeader(t, server, 10*time.Second)
	server.cfg.ClusterMaxAutoVoters = 10

	worker, cleanupWorkerRaw := newTestAgentWithRole(t, "wkr-cv", config.NodeRoleWorker,
		[]string{server.gossip.ml.LocalNode().Address()})
	var workerCloseOnce sync.Once
	cleanupWorker := func() { workerCloseOnce.Do(cleanupWorkerRaw) }
	// cleanupWorker is sync.Once-guarded so a deferred call after the
	// explicit shutdown below is a no-op.
	defer cleanupWorker()

	// Wait until the worker shows up in gossip. Workers are no longer raft
	// non-voters; dead-owner handling now relies on memberlist membership for
	// non-server owners.
	waitForGossipMember(t, server, "wkr-cv", 10*time.Second)

	// Place a sandbox owned by the worker. We write directly to the FSM via
	// raft so the test doesn't depend on the service-layer create path.
	cmd := command{Op: opPlace, SandboxID: "sb-conv", OwnerNodeID: "wkr-cv", OwnerAPIURL: worker.apiURL}
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatalf("encodeCommand: %v", err)
	}
	if err := server.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	// Pre-kill sanity: placement is on the worker.
	if owner, err := server.OwnerOf("sb-conv"); err != nil || owner.NodeID != "wkr-cv" {
		t.Fatalf("pre-kill owner = %+v err=%v, want NodeID=wkr-cv", owner, err)
	}

	// "Kill" the worker. cleanupWorker is sync.Once-guarded so the
	// deferred cleanup runs as a no-op. This shuts down gossip + raft;
	// memberlist will mark the worker dead once the suspect timer fires.
	cleanupWorker()
	_ = worker // worker stays referenced only for clarity at the placement step above

	// Wait for the leader's dead-owner reconciler to fire — it polls every
	// few seconds and grace is 200ms, so the placement should orphan well
	// within ten seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if !waitForOrphan(ctx, server, "sb-conv") {
		t.Fatalf("placement never orphaned after worker death")
	}
}

// waitForOrphan polls OwnerOf until it returns ErrOrphaned (the post-eviction
// state) or the context expires. Returns true on success.
func waitForOrphan(ctx context.Context, c *Cluster, sandboxID string) bool {
	for {
		_, err := c.OwnerOf(sandboxID)
		if err == ErrOrphaned {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
		}
	}
}
