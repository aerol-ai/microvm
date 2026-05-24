package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestAssertOwnershipBackfillsCustomHostnames is the failover-recreate guard:
// on boot, the new owner's local store already has the custom hostnames (they
// were carried over via recovery_replication), but the FSM placement map
// doesn't. AssertOwnership must replay them through the FSM so cluster-wide
// hostname → sandbox lookups (TLSAsk, ingress_delta SNI matchers) resolve.
// Without this, a failed-over sandbox would be unreachable on its custom
// domains until the next mutating call rebuilt the FSM index.
func TestAssertOwnershipBackfillsCustomHostnames(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	local := []LocalSandboxState{{
		ID:              "sb-domains",
		Spec:            &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512},
		CustomHostnames: []string{"api.acme.com", "shop.beta.io"},
	}}
	if err := c.AssertOwnership(ctx, local); err != nil {
		t.Fatalf("AssertOwnership: %v", err)
	}

	got, ok := c.fsm.get("sb-domains")
	if !ok {
		t.Fatal("placement not created")
	}
	if len(got.CustomHostnames) != 2 {
		t.Fatalf("CustomHostnames = %v, want both replayed", got.CustomHostnames)
	}
	// Index must resolve cluster-wide — the TLSAsk hot path keys off this map.
	for _, h := range []string{"api.acme.com", "shop.beta.io"} {
		sid, ok := c.fsm.sandboxIDByCustomHostname(h)
		if !ok || sid != "sb-domains" {
			t.Fatalf("hostname index for %q = (%q, %v), want (sb-domains, true)", h, sid, ok)
		}
	}
}

// TestAssertOwnershipReReplaysMissingCustomHostnames covers the catch-up
// case where a placement we own already exists but the FSM is missing some
// hostnames (e.g. AssertOwnership ran before PR #3, or a prior replay
// failed mid-flight). Re-running must add the missing ones without
// disturbing the existing placement or its other state.
func TestAssertOwnershipReReplaysMissingCustomHostnames(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First pass: bind one hostname.
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-catchup",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{"first.acme.com"},
	}}); err != nil {
		t.Fatalf("first AssertOwnership: %v", err)
	}

	// Second pass: same sandbox, now with two hostnames. The owner+normal
	// branch must replay both (idempotent on the first, additive on the
	// second).
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-catchup",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{"first.acme.com", "second.acme.com"},
	}}); err != nil {
		t.Fatalf("second AssertOwnership: %v", err)
	}

	got, ok := c.fsm.get("sb-catchup")
	if !ok {
		t.Fatal("placement disappeared")
	}
	if len(got.CustomHostnames) != 2 {
		t.Fatalf("CustomHostnames = %v, want 2 after catch-up replay", got.CustomHostnames)
	}
	if sid, ok := c.fsm.sandboxIDByCustomHostname("second.acme.com"); !ok || sid != "sb-catchup" {
		t.Fatalf("second hostname not claimed: (%q, %v)", sid, ok)
	}
}
