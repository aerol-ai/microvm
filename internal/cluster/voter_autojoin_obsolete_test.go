package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/hashicorp/raft"
)

// An obsolete server (it missed a finalize while it was down) is kept out
// of Raft and removed if present, and joins again once upgraded (§6.5,
// Codex outside review finding 7).
func TestVoterAutoJoinKeepsObsoleteServersOutOfRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "ldr", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	c.rolloutStop()
	ctx := context.Background()
	if err := c.raft.raft.AddNonvoter("old", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	old := Member{NodeID: "old", Alive: true, Role: config.NodeRoleWorker, RaftAddr: "127.0.0.1:1", FSMOpsVersion: 12}
	c.gossip.memberIndex.upsert(old)
	// No active version yet: nothing is obsolete.
	c.reconcileVoters()
	if _, ok := c.configuredServer("old"); !ok {
		t.Fatal("removed before any active version")
	}
	if _, err := c.writeActiveVersion(ctx, ActiveVersionCommand{FV: 13, ExpectFV: 0, Release: version.Version}); err != nil {
		t.Fatal(err)
	}
	before := obsoleteServersRemoved.Value()
	c.reconcileVoters()
	if _, ok := c.configuredServer("old"); ok {
		t.Fatal("a server below the active version stayed in Raft")
	}
	if obsoleteServersRemoved.Value() != before+1 || c.membersBelowActive() != 1 {
		t.Fatal("removal not counted")
	}
	c.handleMemberJoin("old")
	if _, ok := c.configuredServer("old"); ok {
		t.Fatal("auto-join added an obsolete server")
	}
	// Upgraded: it joins again.
	old.FSMOpsVersion = 13
	c.gossip.memberIndex.upsert(old)
	c.handleMemberJoin("old")
	srv, ok := c.configuredServer("old")
	if !ok || srv.Suffrage != raft.Nonvoter {
		t.Fatalf("upgraded server not back: %+v %v", srv, ok)
	}
	// An unknown fv (meta not seen yet) is never taken for obsolete.
	old.FSMOpsVersion = 0
	c.gossip.memberIndex.upsert(old)
	c.reconcileVoters()
	if _, ok := c.configuredServer("old"); !ok || c.peerObsolete("old") {
		t.Fatal("a server with unknown fv was removed")
	}
	var nilGossip Cluster
	if nilGossip.peerObsolete("x") {
		t.Fatal("peerObsolete without gossip")
	}
}
