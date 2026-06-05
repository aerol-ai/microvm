package cluster

import (
	"context"
	"log/slog"
	"testing"
	"time"

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
