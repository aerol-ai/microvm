package cluster

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/memberlist"
)

func TestGossipDelegateNoopMethods(t *testing.T) {
	d := newGossipDelegate("id", "name", "api", "dp", "raft", "internal", "role", "public", nil)
	// These methods are no-ops but need coverage
	d.NotifyMsg([]byte("msg"))
	d.MergeRemoteState([]byte("state"), false)

	if meta := d.NodeMeta(-1); meta != nil {
		t.Errorf("NodeMeta with negative limit should return nil, got %v", meta)
	}
}

func TestIndexedEventDelegateNotifyUpdate(t *testing.T) {
	idx := newGossipMemberIndex()
	d := &indexedEventDelegate{index: idx}

	// Create a dummy memberlist.Node
	n := &memberlist.Node{
		Name:  "node-1",
		State: memberlist.StateAlive,
	}

	d.NotifyUpdate(n)
	members := idx.snapshot()
	if len(members) != 1 || members[0].NodeID != "node-1" {
		t.Errorf("expected node-1 in index, got %v", members)
	}
}

func TestGossipNodePeerDataPlaneHost(t *testing.T) {
	idx := newGossipMemberIndex()
	idx.upsert(Member{NodeID: "n1", DataPlaneHost: "dp1", Alive: true})
	idx.upsert(Member{NodeID: "n2", DataPlaneHost: "dp2", Alive: true})

	gn := &gossipNode{memberIndex: idx}

	if h := gn.peerDataPlaneHost("n1"); h != "dp1" {
		t.Errorf("expected dp1, got %v", h)
	}
	if h := gn.peerDataPlaneHost("unknown"); h != "" {
		t.Errorf("expected empty for unknown, got %v", h)
	}
}

func TestSetupGossipInvalidSecretKey(t *testing.T) {
	cfg := gossipSetupConfig{
		NodeID:    "test",
		BindAddr:  "127.0.0.1:0",
		SecretKey: []byte("too-short"),
	}

	_, err := setupGossip(cfg, nil, slog.Default())
	if err == nil || err.Error() != "gossip setup: SecretKey must be 16, 24, or 32 bytes (got 9)" {
		t.Errorf("expected specific error, got %v", err)
	}
}

func TestSetupGossipContinuesWhenInitialBootstrapJoinFails(t *testing.T) {
	cfg := gossipSetupConfig{
		NodeID:         "join-retry-node",
		BindAddr:       "127.0.0.1:0",
		BootstrapPeers: []string{"127.0.0.1:1"},
		GossipInterval: time.Hour,
		APIURL:         "http://127.0.0.1:21212",
		Role:           config.NodeRoleWorker,
		AdvertiseAddr:  "",
		DataPlaneHost:  "127.0.0.1",
		RaftAddr:       "",
		InternalURL:    "",
		PublicHost:     "",
		Events:         nil,
	}

	gn, err := setupGossip(cfg, nil, slog.Default())
	if err != nil {
		t.Fatalf("setupGossip returned fatal error for transient bootstrap join failure: %v", err)
	}
	defer gn.Close()

	members := gn.members()
	if len(members) != 1 || members[0].NodeID != "join-retry-node" || !members[0].Alive {
		t.Fatalf("members after failed initial join = %+v, want live self member", members)
	}
	if len(gn.bootstrapPeers) != 1 || gn.bootstrapPeers[0] != "127.0.0.1:1" {
		t.Fatalf("bootstrap peers = %v, want retained peer for background retry", gn.bootstrapPeers)
	}
}

func TestGossipRefreshLoopExitsOnCancel(t *testing.T) {
	// We just want to ensure runRefreshLoop doesn't block forever and handles context correctly
	gn := &gossipNode{
		memberIndex: newGossipMemberIndex(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	done := make(chan struct{})
	go func() {
		gn.runRefreshLoop(ctx, 1*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		t.Fatal("runRefreshLoop did not exit")
	}
}

func TestHasLiveControlPlaneMemberRequiresUsableServer(t *testing.T) {
	nodes := []*memberlist.Node{
		gossipTestNode(t, "worker", config.NodeRoleWorker, "http://worker:21212", "", memberlist.StateAlive),
		gossipTestNode(t, "dead-server", config.NodeRoleServer, "http://dead-server:21212", "", memberlist.StateDead),
		gossipTestNode(t, "missing-endpoint", config.NodeRoleServer, "", "", memberlist.StateAlive),
	}

	if hasLiveControlPlaneMember(nodes, "self") {
		t.Fatal("hasLiveControlPlaneMember = true, want false without a live server endpoint")
	}

	nodes = append(nodes, gossipTestNode(t, "seed", config.NodeRoleServer, "http://seed:21212", "https://seed:21213", memberlist.StateAlive))
	if !hasLiveControlPlaneMember(nodes, "self") {
		t.Fatal("hasLiveControlPlaneMember = false, want true for live server endpoint")
	}

	nodes = []*memberlist.Node{
		gossipTestNode(t, "self", config.NodeRoleServer, "http://self:21212", "", memberlist.StateAlive),
	}
	if hasLiveControlPlaneMember(nodes, "self") {
		t.Fatal("hasLiveControlPlaneMember = true, want false when the only server is self")
	}
}

func TestMaybeRejoinBootstrapPeersOnlyWithoutControlPlane(t *testing.T) {
	var calls int
	gn := &gossipNode{
		delegate:       &gossipDelegate{nodeID: "self"},
		bootstrapPeers: []string{"10.42.1.215:7001"},
		joinBootstrapPeers: func(peers []string) (int, error) {
			calls++
			if len(peers) != 1 || peers[0] != "10.42.1.215:7001" {
				t.Fatalf("join peers = %v, want configured seed", peers)
			}
			return 1, nil
		},
	}

	gn.maybeRejoinBootstrapPeers([]*memberlist.Node{
		gossipTestNode(t, "worker", config.NodeRoleWorker, "http://worker:21212", "", memberlist.StateAlive),
	})
	if calls != 1 {
		t.Fatalf("join calls = %d, want 1 when no live control-plane member is visible", calls)
	}

	gn.maybeRejoinBootstrapPeers([]*memberlist.Node{
		gossipTestNode(t, "self", config.NodeRoleServer, "http://self:21212", "", memberlist.StateAlive),
	})
	if calls != 2 {
		t.Fatalf("join calls = %d, want 2 when only self is visible as control plane", calls)
	}

	gn.maybeRejoinBootstrapPeers([]*memberlist.Node{
		gossipTestNode(t, "server", config.NodeRoleServer, "http://server:21212", "https://server:21213", memberlist.StateAlive),
		gossipTestNode(t, "worker", config.NodeRoleWorker, "http://worker:21212", "", memberlist.StateAlive),
	})
	if calls != 2 {
		t.Fatalf("join calls = %d, want unchanged when a live control-plane member is visible", calls)
	}
}

func gossipTestNode(t *testing.T, nodeID, role, apiURL, internalURL string, state memberlist.NodeStateType) *memberlist.Node {
	t.Helper()
	encoded, err := json.Marshal(nodeMeta{
		NodeID:      nodeID,
		APIURL:      apiURL,
		InternalURL: internalURL,
		Role:        role,
	})
	if err != nil {
		t.Fatalf("marshal node meta: %v", err)
	}
	return &memberlist.Node{Name: nodeID, State: state, Meta: encoded}
}
