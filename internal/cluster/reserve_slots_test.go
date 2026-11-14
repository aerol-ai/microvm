package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// F28: the leader holds at most ClusterReserveApplyLimit reservations in
// flight; one more is create backpressure at once (429, Retry-After), and a
// freed slot takes the next.
func TestReserveSlotsBoundTheLeader(t *testing.T) {
	c := &Cluster{cfg: config.Config{ClusterReserveApplyLimit: 2}}
	before := reserveAppliesRefused.Value()
	r1, err1 := c.acquireReserveSlot()
	r2, err2 := c.acquireReserveSlot()
	if err1 != nil || err2 != nil {
		t.Fatalf("within the limit: %v %v", err1, err2)
	}
	if _, err := c.acquireReserveSlot(); !errors.Is(err, ErrCreateBackpressure) {
		t.Fatalf("past the limit = %v, want create backpressure", err)
	}
	if ApplyErrorStatus(ErrCreateBackpressure) != 429 || ApplyErrorRetryAfterSeconds(ErrCreateBackpressure) <= 0 {
		t.Fatal("create backpressure is not a 429 with a Retry-After")
	}
	if got := reserveAppliesRefused.Value() - before; got != 1 {
		t.Fatalf("refusals counted %d, want 1", got)
	}
	r1()
	r3, err := c.acquireReserveSlot()
	if err != nil {
		t.Fatalf("a freed slot: %v", err)
	}
	r2()
	r3()

	// 0 turns the bound off.
	off := &Cluster{}
	for range 1000 {
		if _, err := off.acquireReserveSlot(); err != nil {
			t.Fatalf("no limit refused: %v", err)
		}
	}
}

// On a real leader the bound turns a reservation away at once, and only a
// reservation: other ops still apply while every slot is held.
func TestLeaderRefusesReservationsPastTheLimit(t *testing.T) {
	c, cleanup := newTestCluster(t, "reserve-bound", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	c.cfg.ClusterReserveApplyLimit = 1
	hold, err := c.acquireReserveSlot()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeCommand(reserveOn("sb-bound", "worker-x"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := c.ApplyEncoded(context.Background(), payload); !errors.Is(err, ErrCreateBackpressure) {
		t.Fatalf("a reservation with every slot held = %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the refusal took %s; it must not wait", took)
	}
	other, err := encodeCommand(place("sb-other", "worker-x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyEncoded(context.Background(), other); err != nil {
		t.Fatalf("a non-reservation op with every slot held = %v", err)
	}
	hold()
	if _, err := c.acquireReserveSlot(); err != nil {
		t.Fatalf("the slot did not come back: %v", err)
	}
}
