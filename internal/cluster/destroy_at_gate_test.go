package cluster

import "testing"

// TestDestroyAtGate: a lifecycle update may carry destroy_at only once every
// live member, any role, runs a build that understands it. An older member
// keeps the gate closed (the update forwarded to it would clear the
// sandbox's timers); a dead one does not; a restarted node that has not
// rejoined stays closed; the single-node Noop has no gate.
func TestDestroyAtGate(t *testing.T) {
	if destroyAtFSMOpsVersion > fsmOpsVersion {
		t.Fatal("this build cannot gate on a version it does not advertise")
	}
	old := destroyAtFSMOpsVersion - 1
	self := Member{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}
	steps := []struct {
		name   string
		member Member
		want   bool
	}{
		{"an upgraded worker", Member{NodeID: "wrk-b", Alive: true, Role: "worker", FSMOpsVersion: fsmOpsVersion}, true},
		{"a worker on the build before", Member{NodeID: "wrk-c", Alive: true, Role: "worker", FSMOpsVersion: old}, false},
		{"it upgrades", Member{NodeID: "wrk-c", Alive: true, Role: "worker", FSMOpsVersion: fsmOpsVersion}, true},
		{"a dead old member", Member{NodeID: "old-d", Alive: false, FSMOpsVersion: old}, true},
		{"it returns on the old build", Member{NodeID: "old-d", Alive: true, FSMOpsVersion: old}, false},
	}
	index := newGossipMemberIndex()
	index.replace([]Member{self})
	g := &gossipNode{memberIndex: index, bootstrapPeers: []string{"10.0.0.2:7946"}}
	c := &Cluster{gossip: g}
	a := &Agent{gossip: g}
	for _, step := range steps {
		index.upsert(step.member)
		if got := c.DestroyAtAllowed(); got != step.want {
			t.Fatalf("%s: Cluster gate = %v, want %v", step.name, got, step.want)
		}
		if got := a.DestroyAtAllowed(); got != step.want {
			t.Fatalf("%s: Agent gate = %v, want %v", step.name, got, step.want)
		}
	}

	solo := newGossipMemberIndex()
	solo.replace([]Member{self})
	if (&Agent{gossip: &gossipNode{memberIndex: solo, bootstrapPeers: []string{"10.0.0.2:7946"}}}).DestroyAtAllowed() {
		t.Fatal("a restarted node that has not rejoined opened the gate")
	}
	var nc *Cluster
	var na *Agent
	if nc.DestroyAtAllowed() || na.DestroyAtAllowed() {
		t.Fatal("a nil client opened the gate")
	}
	var client Client = NewNoop("n", "", "")
	if _, ok := client.(DestroyAtGate); ok {
		t.Fatal("Noop must not implement DestroyAtGate: a single node forwards to no older owner")
	}
}
