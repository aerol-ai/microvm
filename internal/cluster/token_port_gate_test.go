package cluster

import "testing"

// TestTokenPortGate: a port may become token-gated only once every live
// member, any role, advertises a build that keeps the visibility through
// failover. A member on the build before it keeps the gate closed (a
// failover through it would recreate the port as public); a dead old member
// does not hold it; one that comes back on the old build closes it again; a
// restarted node that has not rejoined stays closed.
func TestTokenPortGate(t *testing.T) {
	if tokenPortFSMOpsVersion > fsmOpsVersion {
		t.Fatal("this build cannot gate on a version it does not advertise")
	}
	if tokenPortFSMOpsVersion <= sshSessionOwnerRecordFSMOpsVersion {
		t.Fatal("the token-port gate must name a version no build without it advertises")
	}
	old := tokenPortFSMOpsVersion - 1
	self := Member{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}
	steps := []struct {
		name   string
		member Member
		want   bool
	}{
		{"an upgraded worker", Member{NodeID: "wrk-b", Alive: true, Role: "worker", FSMOpsVersion: fsmOpsVersion}, true},
		{"a server on the build before", Member{NodeID: "srv-c", Alive: true, Role: "server", FSMOpsVersion: old}, false},
		{"the server upgrades", Member{NodeID: "srv-c", Alive: true, Role: "server", FSMOpsVersion: fsmOpsVersion}, true},
		{"a dead old member", Member{NodeID: "old-d", Alive: false, FSMOpsVersion: old}, true},
		{"it returns on the old build", Member{NodeID: "old-d", Alive: true, FSMOpsVersion: old}, false},
		{"it upgrades", Member{NodeID: "old-d", Alive: true, FSMOpsVersion: fsmOpsVersion}, true},
	}
	index := newGossipMemberIndex()
	index.replace([]Member{self})
	g := &gossipNode{memberIndex: index, bootstrapPeers: []string{"10.0.0.2:7946"}}
	c := &Cluster{gossip: g}
	a := &Agent{gossip: g}
	for _, step := range steps {
		index.upsert(step.member)
		if got := c.TokenPortsAllowed(); got != step.want {
			t.Fatalf("%s: Cluster gate = %v, want %v", step.name, got, step.want)
		}
		if got := a.TokenPortsAllowed(); got != step.want {
			t.Fatalf("%s: Agent gate = %v, want %v", step.name, got, step.want)
		}
	}

	solo := newGossipMemberIndex()
	solo.replace([]Member{self})
	if (&Agent{gossip: &gossipNode{memberIndex: solo, bootstrapPeers: []string{"10.0.0.2:7946"}}}).TokenPortsAllowed() {
		t.Fatal("a restarted node that has not rejoined opened the gate")
	}
	var nc *Cluster
	var na *Agent
	if nc.TokenPortsAllowed() || na.TokenPortsAllowed() {
		t.Fatal("a nil client opened the gate")
	}
	var client Client = NewNoop("n", "", "")
	if _, ok := client.(TokenPortGate); ok {
		t.Fatal("Noop must not implement TokenPortGate: a single node has no older peer")
	}
}
