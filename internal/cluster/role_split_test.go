package cluster

import (
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/raft"
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

// TestRoleSplitWorkerJoinsAsNonVoter is the headline gate: a follower that
// gossiped SB_NODE_ROLE=worker must land in the raft configuration as a
// non-voter even when the voter cap is high enough to accept it as a voter.
// This is what cuts 200 → 3 voters at scale.
func TestRoleSplitWorkerJoinsAsNonVoter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-server", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	// Cap is high — worker role itself must keep it out of voter status.
	leader.cfg.ClusterMaxAutoVoters = 10

	_, cleanupWorker := newTestClusterWithRole(t, "wkr", config.NodeRoleWorker, false,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupWorker()

	waitForServerSuffrage(t, leader, "wkr", raft.Nonvoter, 10*time.Second)
}

// TestRoleSplitIngressJoinsAsNonVoter mirrors the worker case for the ingress
// role: ingress nodes participate in gossip and receive placement updates but
// must not vote in raft.
func TestRoleSplitIngressJoinsAsNonVoter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-srv2", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	leader.cfg.ClusterMaxAutoVoters = 10

	_, cleanupIngress := newTestClusterWithRole(t, "ing", config.NodeRoleIngress, false,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupIngress()

	waitForServerSuffrage(t, leader, "ing", raft.Nonvoter, 10*time.Second)
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
	}
	for _, tc := range cases {
		got := isForcedNonVoterRole(tc.role)
		if got != tc.want {
			t.Fatalf("role=%q forced-non-voter=%v want %v", tc.role, got, tc.want)
		}
	}
}
