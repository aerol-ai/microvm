package cluster

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/memberlist"
)

func TestGossipMemberIndexStoresDecodedMemberMetadata(t *testing.T) {
	encoded, err := json.Marshal(nodeMeta{
		NodeID:        "worker-a",
		APIURL:        "http://worker-a:21212",
		DataPlaneHost: "worker-a.internal",
		RaftAddr:      "worker-a:7000",
		Role:          config.NodeRoleWorker,
	})
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	idx := newGossipMemberIndex()
	idx.upsert(memberFromMemberlistNode(&memberlist.Node{
		Name:  "memberlist-name",
		State: memberlist.StateAlive,
		Meta:  encoded,
	}))

	got := idx.snapshot()
	if len(got) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(got))
	}
	m := got[0]
	if m.NodeID != "worker-a" || m.APIURL != "http://worker-a:21212" || m.Role != config.NodeRoleWorker {
		t.Fatalf("decoded member = %+v, want worker-a metadata", m)
	}
	if m.RaftAddr != "worker-a:7000" {
		t.Fatalf("decoded RaftAddr = %q, want worker-a:7000 (must round-trip — voter auto-join depends on it)", m.RaftAddr)
	}
	if !m.Alive {
		t.Fatalf("decoded member Alive=false, want true")
	}
	// Capacity no longer travels through gossip — peers stay zero-valued and
	// placement.go gracefully treats that as "unknown, forward and let the
	// remote admitter decide." Asserting it here pins that contract.
	if m.Capacity.CPUBudget != 0 || m.Capacity.MemoryBudgetMB != 0 {
		t.Fatalf("decoded capacity = %+v, want zero (capacity is no longer gossiped)", m.Capacity)
	}
}

func TestNodeMetaFallbackPreservesRaftJoinFields(t *testing.T) {
	d := newGossipDelegate(
		"ip-10-42-1-76",
		strings.Repeat("aerolvm-node2-", 50),
		"http://10.42.1.76:21212",
		"10.42.1.76",
		"10.42.1.76:7000",
		"https://10.42.1.76:7002",
		config.NodeRoleMixed,
		"ingress.example.com",
		nil,
	)
	if len(d.encoded) <= memberlist.MetaMaxSize {
		t.Fatalf("test setup encoded meta len=%d, want > %d", len(d.encoded), memberlist.MetaMaxSize)
	}

	encoded := d.NodeMeta(memberlist.MetaMaxSize)
	if len(encoded) > memberlist.MetaMaxSize {
		t.Fatalf("NodeMeta len=%d, want <= %d", len(encoded), memberlist.MetaMaxSize)
	}
	var meta nodeMeta
	if err := json.Unmarshal(encoded, &meta); err != nil {
		t.Fatalf("fallback NodeMeta is not valid JSON: %v; %q", err, string(encoded))
	}
	if meta.NodeID != "ip-10-42-1-76" {
		t.Fatalf("fallback NodeID=%q, want ip-10-42-1-76", meta.NodeID)
	}
	if meta.RaftAddr != "10.42.1.76:7000" {
		t.Fatalf("fallback RaftAddr=%q, want 10.42.1.76:7000", meta.RaftAddr)
	}
	if meta.Role != config.NodeRoleMixed {
		t.Fatalf("fallback Role=%q, want %s", meta.Role, config.NodeRoleMixed)
	}
	if meta.APIURL != "http://10.42.1.76:21212" {
		t.Fatalf("fallback APIURL=%q, want http://10.42.1.76:21212", meta.APIURL)
	}
}

func TestIndexedEventDelegateMarksLeaveUnusableForPlacement(t *testing.T) {
	idx := newGossipMemberIndex()
	d := &indexedEventDelegate{index: idx}
	d.NotifyJoin(&memberlist.Node{Name: "node-a", State: memberlist.StateAlive})
	d.NotifyLeave(&memberlist.Node{Name: "node-a", State: memberlist.StateAlive})

	got := idx.snapshot()
	if len(got) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(got))
	}
	if got[0].NodeID != "node-a" || got[0].Alive {
		t.Fatalf("member after leave = %+v, want node-a alive=false", got[0])
	}
}
