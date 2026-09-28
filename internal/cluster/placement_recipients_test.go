package cluster

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

// TestSelectPlacementForCreateReturnsBoundedRecipients pins the scale contract
// of the create path: the answer is a target plus a handful of recipient ids,
// never the candidate fleet. At 2,000 nodes the old shape made every create's
// control-plane response O(fleet) in bytes and allocations.
func TestSelectPlacementForCreateReturnsBoundedRecipients(t *testing.T) {
	n := NewNoop("node-self", "http://self", "")
	req := capacity.Request{CPU: 1, MemoryMB: 256, DiskGB: 1}

	target, recipients, err := n.SelectPlacementForCreate(req, "sb-1", 2)
	if err != nil {
		t.Fatalf("SelectPlacementForCreate: %v", err)
	}
	if !target.IsSelf {
		t.Fatalf("target = %+v, want self in standalone mode", target)
	}
	// Standalone has one member, so the owner is the only recipient.
	if len(recipients) != 1 || recipients[0] != "node-self" {
		t.Fatalf("recipients = %v, want [node-self]", recipients)
	}

	// A create that wants no fan-out skips selection entirely.
	if _, recipients, err := n.SelectPlacementForCreate(req, "sb-1", 0); err != nil || recipients != nil {
		t.Fatalf("no-fanout create = %v, %v; want no recipients", recipients, err)
	}
}

// TestSelectSecretRecipientsIsBoundedAndStable pins the selection itself: the
// result is owner + at most maxBackups, and it does not depend on the order
// the candidate list happened to arrive in.
func TestSelectSecretRecipientsIsBoundedAndStable(t *testing.T) {
	candidates := make([]Member, 0, 64)
	for _, id := range []string{"n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8"} {
		candidates = append(candidates, Member{NodeID: id, Alive: true})
	}
	got := SelectSecretRecipients("sb-stable", candidates, "n3", 2)
	if len(got) != 3 || got[0] != "n3" {
		t.Fatalf("recipients = %v, want owner first and 3 total", got)
	}

	reversed := make([]Member, len(candidates))
	for i, m := range candidates {
		reversed[len(candidates)-1-i] = m
	}
	if other := SelectSecretRecipients("sb-stable", reversed, "n3", 2); len(other) != len(got) {
		t.Fatalf("selection is order-sensitive: %v vs %v", got, other)
	} else {
		for i := range got {
			if got[i] != other[i] {
				t.Fatalf("selection is order-sensitive: %v vs %v", got, other)
			}
		}
	}
}

// TestAgentSelectPlacementForCreateAsksControlPlaneForRecipients pins the
// agent half of the create-path contract: the request names the sandbox, the
// answer is a bounded recipient list, and no candidate fleet crosses the wire.
func TestAgentSelectPlacementForCreateAsksControlPlaneForRecipients(t *testing.T) {
	var got SelectPlacementRequest
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != PublicInternalSelectPlacementPath {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode select placement request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SelectPlacementResponse{
			Target:     PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b"},
			Recipients: []string{"worker-b", "worker-c"},
		})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	target, recipients, err := agent.SelectPlacementForCreate(capacity.Request{CPU: 1, MemoryMB: 256, DiskGB: 1}, "sb-agent", 1)
	if err != nil {
		t.Fatalf("SelectPlacementForCreate: %v", err)
	}
	if got.SandboxID != "sb-agent" || got.RecipientBackups != 1 {
		t.Fatalf("request = %+v, want the sandbox id and backup count", got)
	}
	if target.NodeID != "worker-b" {
		t.Fatalf("target = %+v, want worker-b", target)
	}
	if len(recipients) != 2 || recipients[0] != "worker-b" {
		t.Fatalf("recipients = %v, want the control plane's bounded set", recipients)
	}
}

// TestAgentSelectPlacementForCreateFallsBackToCandidates pins rolling-upgrade
// safety in the other direction: a control plane still on the previous build
// answers with the candidate fleet and no recipients, and the agent selects
// locally rather than creating a sandbox with no seal recipients at all.
func TestAgentSelectPlacementForCreateFallsBackToCandidates(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SelectPlacementResponse{
			Target: PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b"},
			Candidates: []Member{
				{NodeID: "worker-b", Alive: true},
				{NodeID: "worker-c", Alive: true},
				{NodeID: "worker-d", Alive: true},
			},
		})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	_, recipients, err := agent.SelectPlacementForCreate(capacity.Request{CPU: 1, MemoryMB: 256, DiskGB: 1}, "sb-legacy", 1)
	if err != nil {
		t.Fatalf("SelectPlacementForCreate: %v", err)
	}
	if len(recipients) != 2 || recipients[0] != "worker-b" {
		t.Fatalf("legacy fallback recipients = %v, want owner plus one backup", recipients)
	}
}

// TestAgentSelectPlacementForCreateSurfacesErrors keeps the error shapes the
// router branches on intact through the new entry point.
func TestAgentSelectPlacementForCreateSurfacesErrors(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SelectPlacementResponse{Error: ErrNoPlacementTarget.Error()})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if _, _, err := agent.SelectPlacementForCreate(capacity.Request{CPU: 1}, "sb-err", 1); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("error = %v, want ErrNoPlacementTarget", err)
	}
}

// TestClusterSelectPlacementForCreateSelectsLocally pins the server-side half:
// a control-plane member picks the recipients where the membership already
// lives, so nothing is serialized to answer a create.
func TestClusterSelectPlacementForCreateSelectsLocally(t *testing.T) {
	c, cleanup := newTestCluster(t, "recipients-leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	// Placement needs a fresh capacity heartbeat from the node, the same way
	// the other placement tests seed one.
	c.gossip.delegate.mu.Lock()
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 8192, DiskTotalGB: 100, DiskFreeGB: 100},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, DiskReservationRatio: 1},
		nil,
	)
	c.gossip.delegate.admitter = admitter
	c.gossip.delegate.mu.Unlock()
	c.gossip.refreshMemberIndex()
	c.capacityLeases.setAdmitter(admitter)
	c.capacityLeases.set(c.nodeID, admitter.Snapshot(), time.Now())

	req := capacity.Request{CPU: 1, MemoryMB: 256, DiskGB: 1}
	target, recipients, err := c.SelectPlacementForCreate(req, "sb-local", 2)
	if err != nil {
		t.Fatalf("SelectPlacementForCreate: %v", err)
	}
	if target.NodeID != "recipients-leader" {
		t.Fatalf("target = %+v, want the only member", target)
	}
	// One member: the owner is the only possible recipient.
	if len(recipients) != 1 || recipients[0] != "recipients-leader" {
		t.Fatalf("recipients = %v, want [recipients-leader]", recipients)
	}
	// A create that wants no fan-out skips selection entirely.
	if _, recipients, err := c.SelectPlacementForCreate(req, "sb-local", 0); err != nil || recipients != nil {
		t.Fatalf("no-fanout create = %v, %v; want no recipients", recipients, err)
	}
}
