package cluster

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

// TestRefreshLocalOverlaysEgressGatewayReady: our own lease is what local
// SelectPlacement reads, so it must carry the gateway readiness and follow it
// when the gateway goes down and comes back (CEO D20). No provider means the
// node runs no gateway and never advertises one.
func TestRefreshLocalOverlaysEgressGatewayReady(t *testing.T) {
	admitter := capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil)
	cache := newCapacityLeaseCache("self", admitter, time.Second, nil)
	self := func() capacity.Snapshot {
		cache.refreshLocal(time.Now())
		cache.mu.RLock()
		defer cache.mu.RUnlock()
		return cache.leases["self"].snapshot
	}
	if self().EgressGatewayReady {
		t.Fatal("a node without a gateway provider must not advertise one")
	}
	var ready atomic.Bool
	ready.Store(true)
	c := &Cluster{capacityLeases: cache}
	c.SetEgressGatewayReadyProvider(ready.Load)
	if !self().EgressGatewayReady {
		t.Fatal("a ready gateway must be advertised")
	}
	ready.Store(false)
	if self().EgressGatewayReady {
		t.Fatal("a gateway that went down must stop being advertised on the next tick")
	}
	(*Cluster)(nil).SetEgressGatewayReadyProvider(nil)
	(&Cluster{}).SetEgressGatewayReadyProvider(nil)
	(*capacityLeaseCache)(nil).SetEgressGatewayReadyProvider(nil)
}

// TestSnapshotEgressGatewayReadyWire pins the heartbeat field name and that a
// not-ready node omits it, which is what a legacy peer looks like too.
func TestSnapshotEgressGatewayReadyWire(t *testing.T) {
	b, _ := json.Marshal(capacity.Snapshot{EgressGatewayReady: true})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["egress_gateway_ready"] != true {
		t.Fatalf("wire = %s, want egress_gateway_ready:true", b)
	}
	b, _ = json.Marshal(capacity.Snapshot{})
	m = nil
	_ = json.Unmarshal(b, &m)
	if _, ok := m["egress_gateway_ready"]; ok {
		t.Fatalf("not-ready snapshot must omit the field: %s", b)
	}
}

// TestAgentSelectPlacementKeepsNoEgressGatewaySentinel: a worker that asks the
// control plane to place a gateway-mode create must get the specific sentinel
// back, not a generic error the create handler would turn into a 500.
func TestAgentSelectPlacementKeepsNoEgressGatewaySentinel(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != PublicInternalSelectPlacementPath {
			return false
		}
		var req SelectPlacementRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		capture.appendSelectRequest(req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SelectPlacementResponse{Error: ErrNoEgressGatewayTarget.Error()})
		return true
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	_, err := agent.SelectPlacement(capacity.Request{CPU: 1, NeedsEgressGateway: true})
	if !errors.Is(err, ErrNoEgressGatewayTarget) {
		t.Fatalf("err = %v, want ErrNoEgressGatewayTarget", err)
	}
	if reqs := capture.selectRequestsSnapshot(); len(reqs) != 1 || !reqs[0].Request.NeedsEgressGateway {
		t.Fatalf("the gateway requirement must reach the control plane: %+v", reqs)
	}
}
