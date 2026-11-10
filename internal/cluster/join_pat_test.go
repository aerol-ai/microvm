package cluster

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// TestJoinAnswerPATByRole is the PAT rule of a join answer: a server gets
// the PAT; a worker or ingress node gets the PAT's hashes and the operator
// volume scope instead, unless some live member still needs the PAT on peer
// calls; a server that holds no PAT hands out only the hashes.
func TestJoinAnswerPATByRole(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "pat-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t), mutate: func(c *config.Config) {
		c.PATToken = "cluster-pat"
		c.PATTokenPrevious = "old-pat"
		c.OperatorVolumeScope = "op-pinned"
		// No member-index refresh during the case: it would drop the
		// older member the case adds by hand.
		c.ClusterCapacityGossipInterval = time.Hour
	}})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	join := func(role, nodeID string) JoinResponse {
		t.Helper()
		created, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: role, TTL: "1h"})
		if err != nil {
			t.Fatal(err)
		}
		ports := dialBackListeners(t, 3)
		_, csr := newCSR(t, nodeID)
		resp, err := leader.Join(ctx, JoinRequest{
			Token: created.Token, NodeID: nodeID, CSR: csr, Version: version.Version,
			Ports: &JoinPorts{Gossip: ports[0], Internal: ports[1], Raft: ports[2]},
		}, netip.MustParseAddr("127.0.0.1"))
		if err != nil {
			t.Fatalf("join %s as %s: %v", nodeID, role, err)
		}
		return resp
	}
	hashes := []string{config.PATSHA256("cluster-pat"), config.PATSHA256("old-pat")}

	if !leader.PATFreeJoin() {
		t.Fatal("a fresh one-server cluster on this build keeps the PAT in joins")
	}
	for _, role := range []string{JoinRoleWorker, JoinRoleIngress} {
		resp := join(role, "pf-"+role)
		if resp.PATToken != "" || !slices.Equal(resp.PATSHA256, hashes) || resp.OperatorVolumeScope != "op-pinned" || resp.CAKey != "" {
			t.Fatalf("%s answer = pat %q hashes %v scope %q ca key %t", role, resp.PATToken, resp.PATSHA256, resp.OperatorVolumeScope, resp.CAKey != "")
		}
	}
	if resp := join(JoinRoleServer, "pf-server"); resp.PATToken != "cluster-pat" || resp.PATSHA256 != nil || resp.CAKey == "" {
		t.Fatalf("server answer = pat %q hashes %v ca key %t", resp.PATToken, resp.PATSHA256, resp.CAKey != "")
	}

	// A live member on an older build would refuse a cert-only call: the
	// worker gets the PAT, as every node did before.
	leader.gossip.memberIndex.upsert(Member{NodeID: "old-build", Alive: true, Role: config.NodeRoleWorker, FSMOpsVersion: peerCertAuthFSMOpsVersion - 1})
	if leader.PATFreeJoin() {
		t.Fatal("an older live member left the gate open")
	}
	if resp := join(JoinRoleWorker, "pf-worker-old"); resp.PATToken != "cluster-pat" || resp.PATSHA256 != nil {
		t.Fatalf("worker answer with an older member = pat %q hashes %v", resp.PATToken, resp.PATSHA256)
	}
	leader.gossip.memberIndex.upsert(Member{NodeID: "old-build", Alive: false, Role: config.NodeRoleWorker, FSMOpsVersion: peerCertAuthFSMOpsVersion - 1})
}

// A server that holds no PAT itself (it was joined without one) can hand
// out only the hashes, and the scope it derives, to any role.
func TestJoinAnswerFromAServerWithoutThePAT(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	hash := config.PATSHA256("cluster-pat")
	scope, _ := volumes.OperatorScope("", "cluster-pat")
	leader, cleanup := newJoinTestCluster(t, "nopat-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t), mutate: func(c *config.Config) {
		c.PATToken, c.PATTokenSHA256, c.OperatorVolumeScope = "own-token", []string{hash}, scope
	}})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	created, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleServer, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	ports := dialBackListeners(t, 3)
	_, csr := newCSR(t, "nopat-server")
	resp, err := leader.Join(ctx, JoinRequest{
		Token: created.Token, NodeID: "nopat-server", CSR: csr, Version: version.Version,
		Ports: &JoinPorts{Gossip: ports[0], Internal: ports[1], Raft: ports[2]},
	}, netip.MustParseAddr("127.0.0.1"))
	if err != nil || resp.PATToken != "" || !slices.Equal(resp.PATSHA256, []string{hash}) || resp.OperatorVolumeScope != scope {
		t.Fatalf("answer from a server without the PAT = pat %q hashes %v scope %q, %v", resp.PATToken, resp.PATSHA256, resp.OperatorVolumeScope, err)
	}
}

// PATFreeJoin is closed on a node with no Raft, and follows the active
// version once it is written.
func TestPATFreeJoinGate(t *testing.T) {
	var nilCluster *Cluster
	if nilCluster.PATFreeJoin() || (&Cluster{}).PATFreeJoin() {
		t.Fatal("a cluster with no Raft opened the gate")
	}
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "gate-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t)})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	// The active version as the FSM publishes it (its own apply is tested
	// in fsm_rollout_test.go).
	before := leader.fsm.activeFV.Load()
	defer leader.fsm.activeFV.Store(before)
	leader.fsm.activeFV.Store(peerCertAuthFSMOpsVersion - 1)
	if leader.PATFreeJoin() {
		t.Fatal("an active version below the gate (a rollout not yet finalized) left it open")
	}
	leader.fsm.activeFV.Store(peerCertAuthFSMOpsVersion)
	if !leader.PATFreeJoin() {
		t.Fatal("the active version at the gate kept it closed")
	}
}
