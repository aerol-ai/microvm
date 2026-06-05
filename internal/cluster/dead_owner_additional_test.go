package cluster

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestHandleMemberLeave(t *testing.T) {
	c := &Cluster{
		nodeID:     "self",
		deadOwners: newDeadOwnerTracker(),
	}
	// empty node id
	c.handleMemberLeave("")
	if len(c.deadOwners.snapshot()) != 0 {
		t.Errorf("expected no mark")
	}

	// self node id
	c.handleMemberLeave("self")
	if len(c.deadOwners.snapshot()) != 0 {
		t.Errorf("expected no mark")
	}

	// valid node id
	c.handleMemberLeave("peer")
	if _, ok := c.deadOwners.snapshot()["peer"]; !ok {
		t.Errorf("expected peer to be marked")
	}
}

func TestCancelDeadOwnerWatch(t *testing.T) {
	c := &Cluster{
		deadOwners: newDeadOwnerTracker(),
	}
	c.deadOwners.markDead("peer", time.Now())
	c.cancelDeadOwnerWatch("peer")
	if _, ok := c.deadOwners.snapshot()["peer"]; ok {
		t.Errorf("expected peer to be cleared")
	}

	// nil tracker should not panic
	c.deadOwners = nil
	c.cancelDeadOwnerWatch("peer")
}

func TestPickRecreationTarget(t *testing.T) {
	c := &Cluster{
		nodeID: "self",
		apiURL: "http://self",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: newGossipMemberIndex()},
	}

	// nil spec
	id, url, dp := c.pickRecreationTarget(nil)
	if id != "" || url != "" || dp != "" {
		t.Errorf("expected empty returns")
	}

	// local only mode
	id, url, dp = c.pickRecreationTarget(&models.CreateSandboxRequest{
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	})
	if id != "" || url != "" || dp != "" {
		t.Errorf("expected empty returns for local only")
	}
}

func TestStartDeadOwnerLoopExits(t *testing.T) {
	c := &Cluster{}
	c.startDeadOwnerLoop()
	if c.deadOwnerLoopStop == nil {
		t.Fatal("expected stop func")
	}
	c.deadOwnerLoopStop()
}

func TestStartReservationGCLoopExits(t *testing.T) {
	c := &Cluster{}
	c.startReservationGCLoop()
	if c.reservationGCStop == nil {
		t.Fatal("expected stop func")
	}
	c.reservationGCStop()
}
