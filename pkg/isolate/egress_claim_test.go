package isolate

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// A create's egress slot claim refuses on a full group pool instead of
// starting a sandbox whose egress is silently denied; the refusal is a
// capacity error and leaves no trace of the sandbox in the host's tables.
func TestClaimEgressPolicyRefusesOnExhaustedPool(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t), EgressPoolSize: 1})
	defer h.stopServers()

	if err := h.ClaimEgressPolicy("sb-1", EgressPolicy{}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if _, ok := h.slotByID["sb-1"]; !ok {
		t.Fatal("sb-1 got no slot")
	}
	// Re-claiming a slot the sandbox already holds is not a refusal (a
	// create retried under the same id).
	if err := h.ClaimEgressPolicy("sb-1", EgressPolicy{Allow: []string{"example.com"}}); err != nil {
		t.Fatalf("re-claim of a held slot: %v", err)
	}

	err := h.ClaimEgressPolicy("sb-2", EgressPolicy{})
	if !errors.Is(err, ErrEgressPoolExhausted) || !errors.Is(err, capacity.ErrCapacityExceeded) {
		t.Fatalf("claim on a full pool = %v, want ErrEgressPoolExhausted (a capacity refusal)", err)
	}
	if pool, ok := capacity.SlotPoolExhausted(err); !ok || pool != "isolate egress pool" {
		t.Fatalf("SlotPoolExhausted = (%q, %t)", pool, ok)
	}
	h.mu.RLock()
	_, hasPolicy := h.egressPolicy["sb-2"]
	_, hasSlot := h.slotByID["sb-2"]
	h.mu.RUnlock()
	if hasPolicy || hasSlot {
		t.Fatalf("a refused claim recorded state: policy=%t slot=%t", hasPolicy, hasSlot)
	}

	// Block-all needs no slot, so it never refuses even on a full pool.
	if err := h.ClaimEgressPolicy("sb-block", EgressPolicy{BlockAll: true}); err != nil {
		t.Fatalf("block-all claim on a full pool: %v", err)
	}

	// The non-create form keeps its fail-closed fallback: no error path, no slot.
	h.SetEgressPolicy("sb-3", EgressPolicy{})
	if _, ok := h.slotByID["sb-3"]; ok {
		t.Fatal("SetEgressPolicy must not take a slot from a full pool")
	}

	// A freed slot is claimable again.
	h.Unload("sb-1")
	if err := h.ClaimEgressPolicy("sb-2", EgressPolicy{}); err != nil {
		t.Fatalf("claim after Unload freed a slot: %v", err)
	}
	if err := h.ClaimEgressPolicy("", EgressPolicy{}); err != nil {
		t.Fatalf("empty id is a no-op, got %v", err)
	}
}
