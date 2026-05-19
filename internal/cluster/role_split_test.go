package cluster

import (
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// newTestClusterWithRole is newTestCluster but lets the caller set fields on
// the config *before* cluster.New runs. This matters for NodeRole because the
// role is published in the gossip delegate at startup; mutating cfg.NodeRole
// after New wouldn't change what peers see.
func newTestClusterWithRole(t *testing.T, nodeID, role string, bootstrap bool, gossipPeers []string) (*Cluster, func()) {
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
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := New(cfg, logger, nil)
	if err != nil {
		t.Fatalf("cluster.New(%s, role=%s): %v", nodeID, role, err)
	}
	return c, func() {
		if err := c.Close(); err != nil {
			t.Logf("cluster.Close(%s): %v", nodeID, err)
		}
	}
}

func newTestAgentWithRole(t *testing.T, nodeID, role string, gossipPeers []string) (*Agent, func()) {
	t.Helper()
	gossipPort := pickFreeTCPPort(t)
	apiURL := fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t))
	cfg := config.Config{
		EnableCluster:                 true,
		NodeID:                        nodeID,
		NodeRole:                      role,
		GossipBindAddr:                fmt.Sprintf("127.0.0.1:%d", gossipPort),
		GossipAdvertiseAddr:           fmt.Sprintf("127.0.0.1:%d", gossipPort),
		BootstrapPeers:                gossipPeers,
		SelfAPIAdvertiseURL:           apiURL,
		ClusterRaftCommitTimeout:      2 * time.Second,
		ClusterCapacityGossipInterval: time.Second,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := NewAgent(cfg, logger, nil)
	if err != nil {
		t.Fatalf("cluster.NewAgent(%s, role=%s): %v", nodeID, role, err)
	}
	return a, func() {
		if err := a.Close(); err != nil {
			t.Logf("agent.Close(%s): %v", nodeID, err)
		}
	}
}

// TestRoleSplitWorkerDoesNotJoinRaft is the headline gate: a worker must not
// start raft at all and therefore must not appear in the raft configuration as
// either voter or non-voter. It still joins gossip so servers can see capacity
// and route ownership to it.
func TestRoleSplitWorkerDoesNotJoinRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-server", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	// Cap is high — worker role itself must keep it out of voter status.
	leader.cfg.ClusterMaxAutoVoters = 10

	worker, cleanupWorker := newTestAgentWithRole(t, "wkr", config.NodeRoleWorker,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupWorker()

	waitForGossipMember(t, leader, "wkr", 10*time.Second)
	if worker.gossip == nil {
		t.Fatal("worker agent did not start gossip")
	}
	assertNotInRaftConfig(t, leader, "wkr")
}

// TestRoleSplitIngressDoesNotJoinRaft mirrors the worker case for ingress:
// ingress nodes participate in gossip and poll control-plane state but must
// not store the placement FSM as raft non-voters.
func TestRoleSplitIngressDoesNotJoinRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-srv2", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	leader.cfg.ClusterMaxAutoVoters = 10

	_, cleanupIngress := newTestAgentWithRole(t, "ing", config.NodeRoleIngress,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupIngress()

	waitForGossipMember(t, leader, "ing", 10*time.Second)
	assertNotInRaftConfig(t, leader, "ing")
}

// TestRoleSplitServerJoinsAsVoter verifies the inverse: a peer that gossiped
// SB_NODE_ROLE=server is still eligible for voter promotion (subject to the
// usual voter cap).
func TestRoleSplitServerJoinsAsVoter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-srv3", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	_, cleanupServer := newTestClusterWithRole(t, "srv2", config.NodeRoleServer, false,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupServer()

	waitForVoter(t, leader, "srv2", 10*time.Second)
}

// TestPeerForcedNonVoterPolicy unit-tests the role classification helper
// without spinning up real raft/memberlist sockets. The Member fed in
// stand-ins for what gossip would have produced.
func TestPeerForcedNonVoterPolicy(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{config.NodeRoleWorker, true},
		{config.NodeRoleIngress, true},
		{config.NodeRoleServer, false},
		{config.NodeRoleMixed, false},
		// Empty role represents older builds (or single-node defaults). They
		// must remain voter-eligible so rolling upgrades don't strand
		// pre-existing voters.
		{"", false},
		// Unknown future role values: stay voter-eligible — better to
		// over-include than to silently demote a legitimate server.
		{"controller", false},
		// Hybrid combinations gossiped by the new builds. The rule is:
		// "server" or "mixed" anywhere in the role set means voter-eligible;
		// anything else with at least one known worker/ingress token is a
		// forced non-voter.
		{"worker,ingress", true},
		// Canonical form is sorted but isForcedNonVoterRole should not depend
		// on order — the leader may receive either form during a rolling
		// upgrade window or from a test harness that bypasses canonicalisation.
		{"ingress,worker", true},
		{"server,worker", false},
		{"server,ingress", false},
		// Explicit equivalent of "mixed" — server presence wins.
		{"server,worker,ingress", false},
		// Server alongside a future role we don't recognise yet should still
		// stay voter-eligible (the server token short-circuits the loop).
		{"server,controller", false},
		// Whitespace/case must be tolerated since gossip is just a string
		// pass-through; canonicalisation happens at config.Load() time on the
		// sender but the receiver must not break if it ever sees a sloppy
		// form (e.g. from a future schema migration).
		{" Worker , Ingress ", true},
	}
	for _, tc := range cases {
		got := isForcedNonVoterRole(tc.role)
		if got != tc.want {
			t.Fatalf("role=%q forced-non-voter=%v want %v", tc.role, got, tc.want)
		}
	}
}

// TestRoleSplitHybridWorkerIngressDoesNotJoinRaft is the hybrid analogue of
// TestRoleSplitWorkerDoesNotJoinRaft: an edge node that owns sandboxes and
// fans out ingress still does not store the control-plane FSM.
func TestRoleSplitHybridWorkerIngressDoesNotJoinRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-hyb-wi", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	leader.cfg.ClusterMaxAutoVoters = 10

	// Canonical form is sorted, matching what config.Load() produces. Either
	// order would work at the gate (the helper is order-independent) but we
	// publish the form an operator would actually deploy with.
	_, cleanupEdge := newTestAgentWithRole(t, "edge", "ingress,worker",
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupEdge()

	waitForGossipMember(t, leader, "edge", 10*time.Second)
	assertNotInRaftConfig(t, leader, "edge")
}

// TestRoleSplitHybridServerWorkerJoinsAsVoter mirrors
// TestRoleSplitServerJoinsAsVoter for the "server,worker" hybrid — a node
// that owns sandboxes locally *and* participates in raft. Voter eligibility
// must follow the server presence rather than the worker presence.
func TestRoleSplitHybridServerWorkerJoinsAsVoter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-hyb-sw", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	_, cleanupSrvWk := newTestClusterWithRole(t, "srv-wk", "server,worker", false,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupSrvWk()

	waitForVoter(t, leader, "srv-wk", 10*time.Second)
}

func waitForGossipMember(t *testing.T, observer *Cluster, nodeID string, max time.Duration) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		for _, m := range observer.Members() {
			if m.NodeID == nodeID && m.Alive {
				if m.RaftAddr != "" {
					t.Fatalf("agent %q gossiped raft address %q; worker/ingress agents must not expose raft", nodeID, m.RaftAddr)
				}
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("member %q never appeared in gossip within %s", nodeID, max)
}

func assertNotInRaftConfig(t *testing.T, leader *Cluster, nodeID string) {
	t.Helper()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := leader.configuredServer(nodeID); ok {
			t.Fatalf("agent %q appeared in raft configuration; non-server nodes must not be voters or non-voters", nodeID)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
