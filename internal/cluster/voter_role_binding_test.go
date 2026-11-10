package cluster

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// Role binding (Codex eng finding 1): the admitted role decides voter
// eligibility when a node has one; the gossiped role only when it has none.
func TestPeerForcedNonVoterUsesTheAdmittedRole(t *testing.T) {
	f := newPlacementFSM()
	applyDenyLogAt(t, f, 1, command{Op: opAdoptNodes, StampUnixNano: 1, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{
		{NodeID: "liar", Role: JoinRoleWorker, KeyHash: testKey("liar")},
		{NodeID: "srv", Role: JoinRoleServer, KeyHash: testKey("srv")},
	}}})
	c := &Cluster{fsm: f}
	c.gossip = &gossipNode{memberIndex: newGossipMemberIndex()}
	for _, m := range []Member{
		{NodeID: "liar", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "srv", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "legacy-worker", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "legacy-server", Alive: true, Role: config.NodeRoleServer},
	} {
		c.gossip.memberIndex.upsert(m)
	}
	cases := map[string]bool{
		"liar":          true,  // admitted worker gossiping server: never a voter
		"srv":           false, // admitted server: voter-eligible whatever it gossips
		"legacy-worker": true,  // no record: gossiped role, as before
		"legacy-server": false,
		"unknown":       false,
	}
	for id, want := range cases {
		if got := c.peerForcedNonVoter(id); got != want {
			t.Fatalf("peerForcedNonVoter(%s) = %v, want %v", id, got, want)
		}
	}
	if !c.admittedNonServer("liar") || c.admittedNonServer("srv") || c.admittedNonServer("legacy-worker") {
		t.Fatal("admittedNonServer disagrees with the records")
	}
}
