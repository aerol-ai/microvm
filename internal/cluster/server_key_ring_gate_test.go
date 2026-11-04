package cluster

import "testing"

// TestServerKeyRingGate: `sandboxd key rotate --stage` waits for every live
// member, any role, to advertise the ring build; a dead old member does not
// hold it, one that comes back on the old build closes it again, and a
// restarted node that has not rejoined yet stays closed (eng D26).
func TestServerKeyRingGate(t *testing.T) {
	if ServerKeyRingFSMOpsVersion > fsmOpsVersion {
		t.Fatal("this build cannot gate on a version it does not advertise")
	}
	self := Member{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}
	steps := []struct {
		name   string
		member Member
		want   bool
	}{
		{"an upgraded server", Member{NodeID: "srv-b", Alive: true, Role: "server", FSMOpsVersion: fsmOpsVersion}, true},
		{"a worker on the API-token release", Member{NodeID: "wrk-c", Alive: true, Role: "worker", FSMOpsVersion: apiTokenFSMOpsVersion}, false},
		{"the worker upgrades", Member{NodeID: "wrk-c", Alive: true, Role: "worker", FSMOpsVersion: fsmOpsVersion}, true},
		{"a dead old member", Member{NodeID: "old-d", Alive: false, FSMOpsVersion: apiTokenFSMOpsVersion}, true},
		{"it returns on the old build", Member{NodeID: "old-d", Alive: true, FSMOpsVersion: apiTokenFSMOpsVersion}, false},
		{"it upgrades", Member{NodeID: "old-d", Alive: true, FSMOpsVersion: fsmOpsVersion}, true},
	}
	index := newGossipMemberIndex()
	index.replace([]Member{self})
	g := &gossipNode{memberIndex: index, bootstrapPeers: []string{"10.0.0.2:7946"}}
	c := &Cluster{gossip: g}
	a := &Agent{gossip: g}
	for _, step := range steps {
		index.upsert(step.member)
		if got := c.ServerKeyRingAllowed(); got != step.want {
			t.Fatalf("%s: Cluster gate = %v, want %v", step.name, got, step.want)
		}
		if got := a.ServerKeyRingAllowed(); got != step.want {
			t.Fatalf("%s: Agent gate = %v, want %v", step.name, got, step.want)
		}
	}

	// Boot window: alone with a peer to rejoin stays closed; alone with
	// nowhere to join is a cluster of one.
	solo := newGossipMemberIndex()
	solo.replace([]Member{self})
	if (&Cluster{gossip: &gossipNode{memberIndex: solo, bootstrapPeers: []string{"10.0.0.2:7946"}}}).ServerKeyRingAllowed() {
		t.Fatal("a restarted node that has not rejoined opened the gate")
	}
	if !(&Cluster{gossip: &gossipNode{memberIndex: solo}}).ServerKeyRingAllowed() {
		t.Fatal("a cluster of one stayed closed")
	}
	var nc *Cluster
	var na *Agent
	if nc.ServerKeyRingAllowed() || na.ServerKeyRingAllowed() {
		t.Fatal("a nil client opened the gate")
	}
}
