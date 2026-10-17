package cluster

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/memberlist"
)

// TestPATScopeGossip pins the scope's gossip contract
// (plans/identity-and-access.md §5.11): the default scope adds nothing to a
// node's meta, so a default cluster gossips byte for byte what it did, and
// "host" round-trips through a peer's decode.
func TestPATScopeGossip(t *testing.T) {
	d := newGossipDelegate("n1", "", "http://n1:21212", "", "n1:7000", "https://n1:7002", "mixed", "", nil)
	before := append([]byte(nil), d.encoded...)
	for _, scope := range []string{"", "any", "ANY", "loopback"} {
		d.setPATScope(scope)
		if string(d.encoded) != string(before) {
			t.Fatalf("scope %q changed the default meta:\n %s\nwant\n %s", scope, d.encoded, before)
		}
	}
	if strings.Contains(string(before), `"ps"`) {
		t.Fatalf("default meta carries the scope key: %s", before)
	}

	d.setPATScope("host")
	var meta nodeMeta
	if err := json.Unmarshal(d.NodeMeta(memberlist.MetaMaxSize), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.PATScope != "host" {
		t.Fatalf("gossiped scope = %q, want host", meta.PATScope)
	}
	m := memberFromMemberlistNode(&memberlist.Node{Name: "n1", State: memberlist.StateAlive, Meta: d.NodeMeta(memberlist.MetaMaxSize)})
	if m.PATScope != "host" {
		t.Fatalf("decoded member scope = %q, want host", m.PATScope)
	}

	// A meta too large for memberlist falls back to a smaller tier; the
	// scope survives it, so a long node name raises no false drift alert.
	long := newGossipDelegate("n2", strings.Repeat("aerolvm-node2-", 50), "http://n2:21212", "", "n2:7000", "https://n2:7002", "mixed", "ingress.example.com", nil)
	long.setPATScope("host")
	if len(long.encoded) <= memberlist.MetaMaxSize {
		t.Fatalf("test setup: meta is %d bytes, want over %d", len(long.encoded), memberlist.MetaMaxSize)
	}
	var fallback nodeMeta
	if err := json.Unmarshal(long.NodeMeta(memberlist.MetaMaxSize), &fallback); err != nil {
		t.Fatal(err)
	}
	if fallback.PATScope != "host" || fallback.RaftAddr == "" {
		t.Fatalf("fallback meta lost the scope or the raft address: %+v", fallback)
	}
}

// TestPATScopeDriftGauge is the drift metric: it counts alive members whose
// gossiped scope differs from this node's, ignores dead ones, and treats an
// older build (no field) as the default "any".
func TestPATScopeDriftGauge(t *testing.T) {
	cases := []struct {
		name    string
		self    string
		members []Member
		want    int64
	}{
		{name: "single node", self: "", members: []Member{{NodeID: "self", Alive: true}}, want: 0},
		{name: "every node on any (older builds included)", self: "",
			members: []Member{{NodeID: "self", Alive: true}, {NodeID: "old", Alive: true}}, want: 0},
		{name: "every node on host", self: "host",
			members: []Member{{NodeID: "self", Alive: true, PATScope: "host"}, {NodeID: "b", Alive: true, PATScope: "host"}}, want: 0},
		{name: "one node left on any", self: "host",
			members: []Member{{NodeID: "self", Alive: true, PATScope: "host"}, {NodeID: "b", Alive: true, PATScope: "host"}, {NodeID: "c", Alive: true}}, want: 1},
		{name: "seen from the drifting node", self: "",
			members: []Member{{NodeID: "self", Alive: true}, {NodeID: "b", Alive: true, PATScope: "host"}, {NodeID: "c", Alive: true, PATScope: "host"}}, want: 2},
		{name: "a dead member does not count", self: "host",
			members: []Member{{NodeID: "self", Alive: true, PATScope: "host"}, {NodeID: "gone", Alive: false}}, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx := newGossipMemberIndex()
			idx.selfPATScope = tc.self
			idx.replace(tc.members)
			if got := patScopeDrift.Value(); got != tc.want {
				t.Fatalf("aerolvm_pat_scope_drift = %d, want %d", got, tc.want)
			}
		})
	}

	t.Run("a member changing scope updates the gauge", func(t *testing.T) {
		idx := newGossipMemberIndex()
		idx.selfPATScope = "host"
		idx.replace([]Member{{NodeID: "self", Alive: true, PATScope: "host"}, {NodeID: "b", Alive: true}})
		if got := patScopeDrift.Value(); got != 1 {
			t.Fatalf("drift = %d, want 1", got)
		}
		idx.upsert(Member{NodeID: "b", Alive: true, PATScope: "host"})
		if got := patScopeDrift.Value(); got != 0 {
			t.Fatalf("drift after b moved to host = %d, want 0", got)
		}
	})

	if GossipPATScope("host") != "host" || GossipPATScope("any") != "" || GossipPATScope("") != "" {
		t.Fatal("GossipPATScope must gossip host and nothing else")
	}
}
