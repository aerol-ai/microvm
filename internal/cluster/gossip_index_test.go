package cluster

import (
	"encoding/json"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/hashicorp/memberlist"
)

func TestGossipMemberIndexStoresDecodedMemberMetadata(t *testing.T) {
	encoded, err := json.Marshal(nodeMeta{
		NodeID:        "worker-a",
		APIURL:        "http://worker-a:21212",
		DataPlaneHost: "worker-a.internal",
		Role:          config.NodeRoleWorker,
		Capacity: capacity.Snapshot{
			HostCPUCores:      8,
			HostMemoryTotalMB: 16_384,
			CPUBudget:         8,
			MemoryBudgetMB:    16_384,
		},
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
	if !m.Alive {
		t.Fatalf("decoded member Alive=false, want true")
	}
	if m.Capacity.CPUBudget != 8 || m.Capacity.MemoryBudgetMB != 16_384 {
		t.Fatalf("decoded capacity = %+v, want advertised budget", m.Capacity)
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
