package cluster

import (
	"testing"
	"time"
)

// A one-server cluster: self is a voter and the leader; any other member
// (a worker) is neither.
func TestAnnotateRaftRolesFromConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	c, cleanup := newTestCluster(t, "roles-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	roles, ok := c.RaftRoles()
	if !ok || !roles.Servers["roles-a"] || roles.Leader != "roles-a" {
		t.Fatalf("RaftRoles = %+v %v", roles, ok)
	}
	got := AnnotateRaftRoles(c, []Member{{NodeID: "roles-a"}, {NodeID: "wkr-1", Voter: true, Leader: true}})
	if !got[0].Voter || !got[0].Leader {
		t.Fatalf("server = %+v, want voter and leader", got[0])
	}
	if got[1].Voter || got[1].Leader {
		t.Fatalf("worker = %+v, want neither (a stale value is overwritten)", got[1])
	}
}

// No Raft view leaves members exactly as they came: an agent's members are
// already a server's annotated answer, and single-node has nothing to add.
func TestAnnotateRaftRolesWithoutRaftView(t *testing.T) {
	in := []Member{{NodeID: "a", Voter: true, Leader: true}}
	if got := AnnotateRaftRoles(NewNoop("a", "http://a", ""), in); !got[0].Voter || !got[0].Leader {
		t.Fatalf("Noop changed members: %+v", got)
	}
	if got := AnnotateRaftRoles(&Cluster{}, in); !got[0].Voter || !got[0].Leader {
		t.Fatalf("raftless cluster changed members: %+v", got)
	}
	var nilCluster *Cluster
	if _, ok := nilCluster.RaftRoles(); ok {
		t.Fatal("nil cluster reported a Raft view")
	}
}

// Voters is the configuration's voters, sorted, non-voters left out; an
// empty configuration lists none (an empty list, never nil).
func TestRaftRolesVoters(t *testing.T) {
	r := RaftRoles{Servers: map[string]bool{"c": true, "a": true, "learner": false, "b": true}}
	if got := r.Voters(); len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("Voters = %v", got)
	}
	if got := (RaftRoles{}).Voters(); got == nil || len(got) != 0 {
		t.Fatalf("empty Voters = %#v", got)
	}
}
