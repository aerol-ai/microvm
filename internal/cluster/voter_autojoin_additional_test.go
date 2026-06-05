package cluster

import (
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/memberlist"
	"testing"
)

func TestVoterAutoJoinDelegate(t *testing.T) {
	d := &voterAutoJoinDelegate{}

	// Should not panic on nil c or nil n
	d.NotifyJoin(nil)
	d.NotifyLeave(nil)
	d.NotifyUpdate(nil)

	d.c = &Cluster{}
	d.NotifyJoin(&memberlist.Node{Name: "test"})
	d.NotifyLeave(&memberlist.Node{Name: "test"})
}

func TestIsForcedNonVoterRole(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{"", false},
		{config.NodeRoleServer, false},
		{config.NodeRoleMixed, false},
		{config.NodeRoleWorker, true},
		{config.NodeRoleIngress, true},
		{"worker,ingress", true},
		{"server,worker", false},
		{"unknown", false},
	}
	for _, tc := range cases {
		if got := isForcedNonVoterRole(tc.role); got != tc.want {
			t.Errorf("isForcedNonVoterRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
}

func TestStartVoterReconcileLoopExits(t *testing.T) {
	c := &Cluster{}
	c.startVoterReconcileLoop()
	if c.voterReconcileStop == nil {
		t.Fatal("expected stop func")
	}
	c.voterReconcileStop()
}

func TestVoterCapReachedMaxZero(t *testing.T) {
	c := &Cluster{}
	c.cfg.ClusterMaxAutoVoters = 0
	if c.voterCapReached() {
		t.Errorf("expected false for max <= 0")
	}
}
