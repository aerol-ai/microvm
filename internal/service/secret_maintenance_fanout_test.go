package service

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// Secret maintenance runs on every node on a ticker. Anything it does
// per-holder or per-member is multiplied by the fleet, and on an agent node
// every cluster.Client read below is a control-plane round trip:
//
//   - PlacementOf per holder, twice per tick, BEFORE secretHolderRefreshBatch
//     capped anything (~200k reads/30s at 100k holdings)
//   - Members() for liveness, ~850 B per peer (~1.7 MB at 2k nodes)
//
// These pin the bounded shapes: one batch placement read per tick, and gossip
// for liveness.

type maintenanceCluster struct {
	*cluster.Noop
	mu              sync.Mutex
	placements      map[string]cluster.Placement
	pointReads      int
	batchReads      int
	membersRPC      int
	localMembersHit int
	members         []cluster.Member
	batchUnavail    bool
}

func newMaintenanceCluster(self string) *maintenanceCluster {
	return &maintenanceCluster{
		Noop:       cluster.NewNoop(self, "http://"+self, ""),
		placements: map[string]cluster.Placement{},
	}
}

func (c *maintenanceCluster) PlacementOf(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pointReads++
	p, ok := c.placements[id]
	return p, ok
}

func (c *maintenanceCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batchReads++
	if c.batchUnavail {
		// Contract: nil means "not authoritative", never "none exist".
		return nil
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out
}

func (c *maintenanceCluster) Members() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.membersRPC++
	return append([]cluster.Member(nil), c.members...)
}

func (c *maintenanceCluster) LocalMembers() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localMembersHit++
	return append([]cluster.Member(nil), c.members...)
}

func (c *maintenanceCluster) counts() (point, batch, membersRPC, localMembers int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pointReads, c.batchReads, c.membersRPC, c.localMembersHit
}

// One batch per tick, no point reads — regardless of how many holders are
// tracked. The old shape issued two PlacementOf calls per holder before the
// batch cap applied, so the cap never bounded the inspection cost.
func TestSecretHolderRefreshBatchesPlacementReads(t *testing.T) {
	const holders = 150
	cl := newMaintenanceCluster("node-a")
	ids := make([]string, 0, holders)
	for i := 0; i < holders; i++ {
		id := fmt.Sprintf("sb-%04d", i)
		ids = append(ids, id)
		cl.placements[id] = cluster.Placement{
			SandboxID: id, OwnerNodeID: "node-a",
			IncarnationID: "inc-" + id, SecretSealGeneration: 1,
			State: cluster.PlacementStatePlaced,
		}
		t.Cleanup(func() { clearSecretFanoutHolders(id) })
		resetSecretHoldersForGeneration(id, "inc-"+id, 1, "node-a")
	}
	cl.members = []cluster.Member{{NodeID: "node-a", Alive: true}}

	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		testSecretPeerPusher: &fakePeerPusher{},
	}
	svc.refreshSecretHolderPossession(context.Background())

	point, batch, _, _ := cl.counts()
	if point != 0 {
		t.Fatalf("PlacementOf called %d times for %d holders; at 100k holdings that is ~200k control-plane reads every tick", point, holders)
	}
	if batch != 1 {
		t.Fatalf("PlacementsByIDs called %d times, want exactly 1 batch per tick", batch)
	}
}

// An unavailable batch must not read as "every placement is gone" — that would
// retire every holder set on the node during a control-plane blip.
func TestSecretHolderRefreshSkipsWhenPlacementBatchUnavailable(t *testing.T) {
	const sandboxID = "sb-unavail"
	cl := newMaintenanceCluster("node-a")
	cl.batchUnavail = true
	cl.placements[sandboxID] = cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a",
		IncarnationID: "inc-1", SecretSealGeneration: 1,
	}
	cl.members = []cluster.Member{{NodeID: "node-a", Alive: true}}
	clearSecretFanoutHolders(sandboxID)
	t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })
	resetSecretHoldersForGeneration(sandboxID, "inc-1", 1, "node-a")

	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		testSecretPeerPusher: &fakePeerPusher{},
	}
	svc.refreshSecretHolderPossession(context.Background())

	if _, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: sandboxID, incarnationID: "inc-1"}); !ok {
		t.Fatal("holder set retired on an unavailable placement view; an unreachable control plane must never read as absence")
	}
}

// Liveness is gossip's own answer. Members() on an agent is a control-plane
// round trip carrying every peer.
func TestAliveMemberSetPrefersLocalGossip(t *testing.T) {
	cl := newMaintenanceCluster("node-a")
	cl.members = []cluster.Member{
		{NodeID: "node-a", Alive: true},
		{NodeID: "node-b", Alive: true},
		{NodeID: "node-dead", Alive: false},
	}
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	alive := svc.aliveMemberSet()

	_, _, membersRPC, localHits := cl.counts()
	if membersRPC != 0 {
		t.Fatalf("aliveMemberSet made %d Members() RPCs; at 2k nodes that is ~1.7 MB per call on a 30s tick", membersRPC)
	}
	if localHits != 1 {
		t.Fatalf("LocalMembers() called %d times, want 1", localHits)
	}
	if _, ok := alive["node-b"]; !ok {
		t.Fatal("live peer missing from the gossip-derived set")
	}
	if _, ok := alive["node-dead"]; ok {
		t.Fatal("dead peer present in the alive set")
	}
}

// Gossip can legitimately be empty (very early boot). Falling back to the RPC
// is correct there — the point is that it is the exception, not the default.
func TestAliveMemberSetFallsBackWhenGossipEmpty(t *testing.T) {
	cl := newMaintenanceCluster("node-a")
	cl.members = nil
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	svc.aliveMemberSet()

	if _, _, membersRPC, _ := cl.counts(); membersRPC != 1 {
		t.Fatalf("Members() fallback calls = %d, want 1 when the gossip view is empty", membersRPC)
	}
}
