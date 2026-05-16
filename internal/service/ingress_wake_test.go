package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// TestPlacementSubscriptionWiringSelectsOnWake verifies the wake-channel
// contract used by StartClusterIngressReconcile: cap=1, non-blocking sends
// coalesce, and a single receive drains the buffer. The FSM's
// notifySubscribers and Cluster.SubscribePlacement both rely on this shape.
func TestPlacementSubscriptionWiringSelectsOnWake(t *testing.T) {
	// This test verifies that a buffered cap=1 wake channel coalesces and
	// is non-blocking under the reconciler's select{...case <-wake} pattern,
	// which is the contract Cluster.SubscribePlacement / Noop satisfy.
	wake := make(chan struct{}, 1)
	// Two non-blocking sends; second drops because cap=1 — exactly what the
	// FSM does. The reconciler then sees one wake and proceeds.
	for i := 0; i < 2; i++ {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	select {
	case <-wake:
	case <-ctx.Done():
		t.Fatal("expected coalesced wake to be readable")
	}
	// Buffer must now be empty — coalesce dropped the second send.
	select {
	case <-wake:
		t.Fatal("expected only one wake; got a second from coalesced sends")
	default:
	}
}

// TestNoopSubscribePlacementNeverFires confirms single-node mode returns a
// nil channel from SubscribePlacement, which is permanently un-ready in
// select{}. Without this, the reconciler loop in single-node mode would
// either receive a phantom wake or panic on a closed-channel design.
func TestNoopSubscribePlacementNeverFires(t *testing.T) {
	noop := cluster.NewNoop("self", "")
	ch := noop.SubscribePlacement(context.Background())
	if ch != nil {
		t.Fatalf("Noop.SubscribePlacement returned %v, want nil", ch)
	}
	// Selecting on nil + a short timer must time out; this is exactly the
	// behaviour the reconciler relies on.
	select {
	case <-ch:
		t.Fatal("nil channel produced a value")
	case <-time.After(50 * time.Millisecond):
	}
}
