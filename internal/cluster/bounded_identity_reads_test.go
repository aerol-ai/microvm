package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Build, template, JS-bundle and local-image routing all want one node. The
// only request shape available to them also returned every eligible worker,
// so a one-field answer cost O(fleet) bytes.
func TestAgentSelectPlacementAsksForTargetOnly(t *testing.T) {
	var got SelectPlacementRequest
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalSelectPlacementPath {
			http.NotFound(w, r)
			return
		}
		// Decode into a zero value: TargetOnly is omitempty, so decoding
		// into the previous request would leave a stale true behind.
		got = SelectPlacementRequest{}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		resp := SelectPlacementResponse{Target: PlacementTarget{NodeID: "wrk-7", APIURL: "http://wrk-7"}}
		if !got.TargetOnly {
			// What the server would still send to a caller that did not ask
			// for a bounded answer.
			for i := range 2000 {
				resp.Candidates = append(resp.Candidates, Member{NodeID: fmt.Sprintf("wrk-%04d", i), Alive: true})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	target, err := agent.SelectPlacement(capacity.Request{CPU: 1})
	if err != nil {
		t.Fatalf("SelectPlacement: %v", err)
	}
	if target.NodeID != "wrk-7" {
		t.Fatalf("target = %+v, want wrk-7", target)
	}
	if !got.TargetOnly {
		t.Fatal("target-only placement still asked for the full candidate array")
	}

	// The candidate shape must remain available for callers that need it.
	_, candidates, err := agent.SelectPlacementWithCandidates(capacity.Request{CPU: 1})
	if err != nil {
		t.Fatalf("SelectPlacementWithCandidates: %v", err)
	}
	if got.TargetOnly {
		t.Fatal("the candidate-taking caller asked for target-only")
	}
	if len(candidates) != 2000 {
		t.Fatalf("candidates = %d, want the full array for the caller that asked for it", len(candidates))
	}
}

// identityCountingCluster separates the local gossip view from the
// control-plane membership RPC so a test can prove which one a caller used.
type identityCountingCluster struct {
	*Noop
	mu        sync.Mutex
	members   []Member
	rpcCalls  int
	localHits int
}

func (c *identityCountingCluster) Members() []Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rpcCalls++
	return append([]Member(nil), c.members...)
}

func (c *identityCountingCluster) LocalMembers() []Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localHits++
	return append([]Member(nil), c.members...)
}

func (c *identityCountingCluster) counts() (rpc, local int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rpcCalls, c.localHits
}

// Identity, role and liveness are gossip facts the node already holds. The
// membership RPC redistributes capacity snapshots and template/module
// inventories with them (~850 B per peer, ~1.7 MB at 2k nodes), which a
// liveness-only caller throws away.
func TestIdentityMembersPrefersLocalGossip(t *testing.T) {
	cl := &identityCountingCluster{
		Noop:    NewNoop("node-a", "http://node-a", ""),
		members: []Member{{NodeID: "node-a", Alive: true}, {NodeID: "node-b", Alive: true}},
	}
	if got := IdentityMembers(cl); len(got) != 2 {
		t.Fatalf("IdentityMembers = %d members, want 2", len(got))
	}
	rpc, local := cl.counts()
	if rpc != 0 {
		t.Fatalf("made %d membership RPCs for an identity-only read", rpc)
	}
	if local != 1 {
		t.Fatalf("LocalMembers called %d times, want 1", local)
	}

	// Very early boot: gossip is empty and the control plane is the fallback.
	cl.mu.Lock()
	cl.members = nil
	cl.mu.Unlock()
	IdentityMembers(cl)
	if rpc, _ = cl.counts(); rpc != 1 {
		t.Fatalf("fallback RPCs = %d, want 1 when the gossip view is empty", rpc)
	}
	if got := IdentityMembers(nil); got != nil {
		t.Fatalf("IdentityMembers(nil) = %+v", got)
	}
}

// The ingress ring and every other identity-only caller must hash the same
// view, so IngressRingMembers stays an alias rather than a second policy.
func TestIngressRingMembersUsesIdentityView(t *testing.T) {
	cl := &identityCountingCluster{
		Noop:    NewNoop("ing-a", "http://ing-a", ""),
		members: []Member{{NodeID: "ing-a", Alive: true, Role: config.NodeRoleIngress}},
	}
	ring := IngressRingMembers(cl)
	identity := IdentityMembers(cl)
	if len(ring) != len(identity) {
		t.Fatalf("ring view (%d) and identity view (%d) disagree", len(ring), len(identity))
	}
	if rpc, _ := cl.counts(); rpc != 0 {
		t.Fatalf("ring membership made %d control-plane RPCs", rpc)
	}
}

// IngressTargets is a handful of hostnames; it must not pull the fleet.
func TestAgentIngressTargetsUsesLocalGossip(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "ing-0", Alive: true, Role: config.NodeRoleIngress, PublicHost: "203.0.113.10"})
	index.upsert(Member{NodeID: "ing-1", Alive: true, Role: config.NodeRoleIngress, PublicHost: "203.0.113.11"})
	rpcCalls := 0
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rpcCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"members": []Member{}})
	}))
	agent.gossip = &gossipNode{memberIndex: index}

	var target models.IngressTarget = agent.IngressTargets()
	if len(target.IPs) != 2 {
		t.Fatalf("ingress target = %+v, want two ingress IPs", target)
	}
	if rpcCalls != 0 {
		t.Fatalf("IngressTargets made %d control-plane RPCs", rpcCalls)
	}
}
