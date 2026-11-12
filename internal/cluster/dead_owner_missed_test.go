package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// A server that was down when a worker died saw no leave event, and the
// worker is gone from gossip too: the placements it still owns are the
// only sign of it. The leader marks it from them and fails it over after
// the grace; an owner gossip shows alive is not marked (plan risk "a
// restarted server may miss a dead worker").
func TestReconcileDeadOwnersMarksOwnersGossipNeverSaw(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	const grace = 200 * time.Millisecond
	c, cleanup := newTestClusterWithCfg(t, "ldr-missed", true, nil, func(cfg *config.Config) {
		cfg.ClusterDeadOwnerGrace = grace
	})
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	for _, p := range []struct{ sb, owner string }{{"sb-missed", "never-seen"}, {"sb-live", "wkr-live"}} {
		payload, _ := encodeCommand(command{Op: opPlace, SandboxID: p.sb, OwnerNodeID: p.owner})
		if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
			t.Fatal(err)
		}
	}
	self, _ := c.gossip.lookupMember(c.nodeID)
	seedGossipView(t, c, []Member{self, {NodeID: "wkr-live", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-live"}})

	c.reconcileDeadOwners(ctx)
	marked := c.deadOwners.snapshot()
	if _, ok := marked["never-seen"]; !ok {
		t.Fatalf("an owner gossip never saw was not marked: %v", marked)
	}
	if _, ok := marked["wkr-live"]; ok {
		t.Fatal("an owner gossip shows alive was marked")
	}
	if _, ok := marked[c.nodeID]; ok {
		t.Fatal("the leader marked itself")
	}
	if owner, err := c.OwnerOf("sb-missed"); err != nil || owner.NodeID != "never-seen" {
		t.Fatalf("moved inside the grace: %+v %v", owner, err)
	}
	time.Sleep(grace + 100*time.Millisecond)
	c.reconcileDeadOwners(ctx)
	if _, err := c.OwnerOf("sb-missed"); err != ErrOrphaned {
		t.Fatalf("after the grace OwnerOf err = %v, want ErrOrphaned", err)
	}
	if owner, err := c.OwnerOf("sb-live"); err != nil || owner.NodeID != "wkr-live" {
		t.Fatalf("a live owner's sandbox moved: %+v %v", owner, err)
	}
	if ids := c.fsm.ownerNodeIDs(); len(ids) != 1 || ids[0] != "wkr-live" {
		t.Fatalf("ownerNodeIDs = %v, want [wkr-live]", ids)
	}
}
