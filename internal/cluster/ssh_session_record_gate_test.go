package cluster

import "testing"

// TestSSHSessionOwnerRecordGate: the SSH gateway hands a bridged session's
// record to the owner only once every live member, any role, advertises a
// build that writes it. A member still on the key-ring build (fv 4, which
// would drop the marker) keeps it closed; a dead old member does not hold
// it; one that comes back on the old build closes it again; a restarted
// node that has not rejoined stays closed, so the gateway records locally.
func TestSSHSessionOwnerRecordGate(t *testing.T) {
	if sshSessionOwnerRecordFSMOpsVersion > fsmOpsVersion {
		t.Fatal("this build cannot gate on a version it does not advertise")
	}
	if sshSessionOwnerRecordFSMOpsVersion <= ServerKeyRingFSMOpsVersion {
		t.Fatal("the owner-record gate must name a version no build without it advertises")
	}
	self := Member{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}
	steps := []struct {
		name   string
		member Member
		want   bool
	}{
		{"an upgraded worker", Member{NodeID: "wrk-b", Alive: true, Role: "worker", FSMOpsVersion: fsmOpsVersion}, true},
		{"an ingress node on the key-ring build", Member{NodeID: "ing-c", Alive: true, Role: "ingress", FSMOpsVersion: ServerKeyRingFSMOpsVersion}, false},
		{"the ingress node upgrades", Member{NodeID: "ing-c", Alive: true, Role: "ingress", FSMOpsVersion: fsmOpsVersion}, true},
		{"a dead old member", Member{NodeID: "old-d", Alive: false, FSMOpsVersion: ServerKeyRingFSMOpsVersion}, true},
		{"it returns on the old build", Member{NodeID: "old-d", Alive: true, FSMOpsVersion: ServerKeyRingFSMOpsVersion}, false},
		{"it upgrades", Member{NodeID: "old-d", Alive: true, FSMOpsVersion: fsmOpsVersion}, true},
	}
	index := newGossipMemberIndex()
	index.replace([]Member{self})
	g := &gossipNode{memberIndex: index, bootstrapPeers: []string{"10.0.0.2:7946"}}
	c := &Cluster{gossip: g}
	a := &Agent{gossip: g}
	for _, step := range steps {
		index.upsert(step.member)
		if got := c.SSHSessionOwnerRecordAllowed(); got != step.want {
			t.Fatalf("%s: Cluster gate = %v, want %v", step.name, got, step.want)
		}
		if got := a.SSHSessionOwnerRecordAllowed(); got != step.want {
			t.Fatalf("%s: Agent gate = %v, want %v", step.name, got, step.want)
		}
	}

	solo := newGossipMemberIndex()
	solo.replace([]Member{self})
	if (&Agent{gossip: &gossipNode{memberIndex: solo, bootstrapPeers: []string{"10.0.0.2:7946"}}}).SSHSessionOwnerRecordAllowed() {
		t.Fatal("a restarted node that has not rejoined opened the gate")
	}
	var nc *Cluster
	var na *Agent
	if nc.SSHSessionOwnerRecordAllowed() || na.SSHSessionOwnerRecordAllowed() {
		t.Fatal("a nil client opened the gate")
	}
	var client Client = NewNoop("n", "", "")
	if _, ok := client.(SSHSessionRecordGate); ok {
		t.Fatal("Noop must not implement SSHSessionRecordGate: a single node bridges nothing")
	}
}
