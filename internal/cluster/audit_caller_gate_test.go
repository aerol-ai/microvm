package cluster

import (
	"testing"
	"time"
)

// TestAuditCallerGateMixedVersions is the mixed-version gate (T4, §5.8): no
// node writes the audit caller field while any live member, worker or
// ingress included, advertises an older fv, and writes start once the last
// one upgrades. Dead members do not hold the gate; one that comes back on
// an old build closes it again.
func TestAuditCallerGateMixedVersions(t *testing.T) {
	self := Member{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}
	steps := []struct {
		name   string
		member Member // upserted before the check
		want   bool
	}{
		{"an upgraded server joins", Member{NodeID: "srv-b", Alive: true, Role: "server", FSMOpsVersion: fsmOpsVersion}, true},
		{"a worker still on the previous release", Member{NodeID: "wrk-c", Alive: true, Role: "worker", FSMOpsVersion: 1}, false},
		{"an ingress node from before fv existed", Member{NodeID: "ing-d", Alive: true, Role: "ingress", FSMOpsVersion: 0}, false},
		{"the worker upgrades", Member{NodeID: "wrk-c", Alive: true, Role: "worker", FSMOpsVersion: fsmOpsVersion}, false},
		{"the ingress node upgrades: every member now reads callers", Member{NodeID: "ing-d", Alive: true, Role: "ingress", FSMOpsVersion: fsmOpsVersion}, true},
		{"a dead member on an old build does not hold the gate", Member{NodeID: "old-e", Alive: false, FSMOpsVersion: 1}, true},
		{"it comes back on the old build: closed again", Member{NodeID: "old-e", Alive: true, FSMOpsVersion: 1}, false},
		{"it leaves", Member{NodeID: "old-e", Alive: false, FSMOpsVersion: 1}, true},
	}
	index := newGossipMemberIndex()
	index.replace([]Member{self})
	g := &gossipNode{memberIndex: index, bootstrapPeers: []string{"10.0.0.2:7946"}}
	c := &Cluster{gossip: g}
	a := &Agent{gossip: g}
	for _, step := range steps {
		index.upsert(step.member)
		if got := c.AuditCallerWritesAllowed(); got != step.want {
			t.Fatalf("%s: Cluster gate = %v, want %v", step.name, got, step.want)
		}
		if got := a.AuditCallerWritesAllowed(); got != step.want {
			t.Fatalf("%s: Agent gate = %v, want %v", step.name, got, step.want)
		}
	}

	// A full membership refresh (the periodic replace) reaches the same
	// answer as the incremental events.
	index.replace([]Member{self, {NodeID: "srv-b", Alive: true, FSMOpsVersion: 1}})
	if c.AuditCallerWritesAllowed() {
		t.Fatal("replace with an old member left the gate open")
	}
	index.replace([]Member{self, {NodeID: "srv-b", Alive: true, FSMOpsVersion: fsmOpsVersion}})
	if !c.AuditCallerWritesAllowed() {
		t.Fatal("replace with every member upgraded left the gate closed")
	}
}

// TestAuditCallerGateBootWindow: a node that knows only itself must not
// open the gate while it still has peers to join (a restarted node before
// its first join); only a node with nowhere to join is a cluster of one.
func TestAuditCallerGateBootWindow(t *testing.T) {
	selfOnly := func() *gossipMemberIndex {
		index := newGossipMemberIndex()
		index.replace([]Member{{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}})
		return index
	}
	remembered := &gossipPeerCache{last: []string{"10.0.0.9:7946"}}
	cases := []struct {
		name string
		g    *gossipNode
		want bool
	}{
		{"nil gossip", nil, false},
		{"no member index yet", &gossipNode{}, false},
		{"empty index", &gossipNode{memberIndex: newGossipMemberIndex()}, false},
		{"alone with configured peers to join", &gossipNode{memberIndex: selfOnly(), bootstrapPeers: []string{"10.0.0.2:7946"}}, false},
		{"alone with remembered peers to rejoin", &gossipNode{memberIndex: selfOnly(), peerCache: remembered}, false},
		{"alone, configured peer is only itself", &gossipNode{memberIndex: selfOnly(), bootstrapPeers: []string{"10.0.0.1:7946"}, selfGossipAddr: "10.0.0.1:7946"}, true},
		{"alone with nowhere to join: a cluster of one", &gossipNode{memberIndex: selfOnly()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (&Cluster{gossip: tc.g}).AuditCallerWritesAllowed(); got != tc.want {
				t.Fatalf("gate = %v, want %v", got, tc.want)
			}
		})
	}
	var nilCluster *Cluster
	var nilAgent *Agent
	if nilCluster.AuditCallerWritesAllowed() || nilAgent.AuditCallerWritesAllowed() {
		t.Fatal("a nil client must keep the gate closed")
	}
	if floor, alive := (*gossipMemberIndex)(nil).featureFloor(); floor != -1 || alive != 0 {
		t.Fatalf("nil index floor = %d, %d", floor, alive)
	}
}

// TestAuditCallerGateRealSingleServer: a real one-server cluster bootstrapped
// with no peers advertises this build's fv and opens the gate; the Noop
// client does not implement the gate at all (single-node mode decides in
// the service, from config).
func TestAuditCallerGateRealSingleServer(t *testing.T) {
	c, cleanup := newTestCluster(t, "gate-solo", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	if !c.AuditCallerWritesAllowed() {
		t.Fatal("a cluster of one on this build must write callers")
	}
	var client Client = NewNoop("n", "", "")
	if _, ok := client.(AuditCallerGate); ok {
		t.Fatal("Noop must not implement AuditCallerGate")
	}
	if auditCallerFSMOpsVersion > fsmOpsVersion {
		t.Fatal("this build cannot gate on a version it does not advertise")
	}
}

// TestAuditCallerGateConcurrentChurn: the gate is read on every audit record
// while gossip events rewrite the index; the floor and count are atomics, so
// readers never race the writers (run under -race) and never take the index
// lock.
func TestAuditCallerGateConcurrentChurn(t *testing.T) {
	index := newGossipMemberIndex()
	index.replace([]Member{{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}})
	c := &Cluster{gossip: &gossipNode{memberIndex: index}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			index.upsert(Member{NodeID: "peer", Alive: i%2 == 0, FSMOpsVersion: 1})
		}
		index.upsert(Member{NodeID: "peer", Alive: true, FSMOpsVersion: fsmOpsVersion})
	}()
	for {
		select {
		case <-done:
			if !c.AuditCallerWritesAllowed() {
				t.Fatal("gate closed after the last member upgraded")
			}
			return
		default:
			_ = c.AuditCallerWritesAllowed()
		}
	}
}
