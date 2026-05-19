package cluster

import (
	"encoding/json"
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
