package cluster

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Our own lease is what SelectPlacement reads for this node, so it must carry
// the same slot pools peers read from /v1/capacity, and follow them per tick.
func TestRefreshLocalOverlaysSlotPools(t *testing.T) {
	admitter := capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil)
	cache := newCapacityLeaseCache("self", admitter, time.Second, nil)
	self := func() capacity.Snapshot {
		cache.refreshLocal(time.Now())
		cache.mu.RLock()
		defer cache.mu.RUnlock()
		return cache.leases["self"].snapshot
	}
	if len(self().SlotPools) != 0 {
		t.Fatal("a node without a slot provider must advertise no pools")
	}
	free := 3
	c := &Cluster{capacityLeases: cache}
	c.SetLocalSlotPoolsProvider(func() []capacity.SlotPool {
		return []capacity.SlotPool{{Name: capacity.SlotPoolFirecrackerTap, Runtimes: []string{models.RuntimeFirecracker}, Total: 256, Free: free}}
	})
	if pools := self().SlotPools; len(pools) != 1 || pools[0].Free != 3 {
		t.Fatalf("lease pools = %+v, want the provider's", pools)
	}
	free = 0
	if pool, _ := self().SlotPoolFor(models.RuntimeFirecracker); pool.Free != 0 {
		t.Fatalf("a pool that filled up must be advertised on the next tick: %+v", pool)
	}
	(*Cluster)(nil).SetLocalSlotPoolsProvider(nil)
	(&Cluster{}).SetLocalSlotPoolsProvider(nil)
	(*capacityLeaseCache)(nil).SetLocalSlotPoolsProvider(nil)
}

// An agent (ingress or worker) asks a server to place; "every worker is full"
// must survive that hop as ErrClusterAtCapacity, while an agent on the
// previous build still reads the exact ErrNoPlacementTarget text it matches.
func TestSelectPlacementErrorResponseCarriesAtCapacity(t *testing.T) {
	resp := SelectPlacementErrorResponse(ErrClusterAtCapacity)
	if !resp.AtCapacity || resp.Error != ErrNoPlacementTarget.Error() {
		t.Fatalf("at-capacity response = %+v, want AtCapacity with ErrNoPlacementTarget's exact text", resp)
	}
	raw, _ := json.Marshal(resp)
	var wire map[string]any
	_ = json.Unmarshal(raw, &wire)
	if wire["at_capacity"] != true {
		t.Fatalf("wire = %s, want at_capacity:true", raw)
	}
	if resp := SelectPlacementErrorResponse(ErrNoEgressGatewayTarget); resp.AtCapacity || resp.Error != ErrNoEgressGatewayTarget.Error() {
		t.Fatalf("other errors keep their own text: %+v", resp)
	}

	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != PublicInternalSelectPlacementPath {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SelectPlacementErrorResponse(ErrClusterAtCapacity))
		return true
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	_, err := agent.SelectPlacement(capacity.Request{CPU: 1, Runtime: models.RuntimeDocker})
	if !errors.Is(err, ErrClusterAtCapacity) || !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("agent err = %v, want ErrClusterAtCapacity (still an ErrNoPlacementTarget)", err)
	}
}
