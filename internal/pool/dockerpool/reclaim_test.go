package dockerpool

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// chanSpawner reports destroyed slots on a channel: Reclaim tears containers
// down in the background, so the test waits for the teardown instead of
// racing it.
type chanSpawner struct{ destroyed chan string }

func (c *chanSpawner) Park(context.Context, string, Key) (*ParkedSlot, error) {
	return nil, errors.New("not implemented")
}

func (c *chanSpawner) DestroyParked(_ context.Context, slot *ParkedSlot) error {
	c.destroyed <- slot.ID
	return nil
}

func parkSlots(p *Pool, key Key, ids ...string) {
	for _, id := range ids {
		p.RecordLoaded(&ParkedSlot{ID: id, Key: key, Handle: &fakeHandle{alive: true}})
	}
}

// Reclaim is how a full node makes room for a real sandbox (the admitter
// calls it when only parked slots stand in the way). It must give back the
// least-recently-used miss-driven slots first, keep the operator's pinned
// target for last, release each park reservation before it returns, and
// destroy the containers off the caller's path.
func TestReclaimTakesLeastRecentlyUsedSlotsAndReleasesReservations(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(4)
	pinned := testKey()
	stale := Key{Image: "postgres:16", Runtime: models.RuntimeDocker}
	recent := Key{Image: "redis:7", Runtime: models.RuntimeDocker}
	p.PinTarget(pinned)
	p.NoteTarget(stale)
	p.NoteTarget(recent)
	p.mu.Lock()
	p.lastUsed[pinned.KeyString()] = time.Unix(10, 0) // oldest, but pinned
	p.lastUsed[stale.KeyString()] = time.Unix(100, 0)
	p.lastUsed[recent.KeyString()] = time.Unix(200, 0)
	p.mu.Unlock()
	parkSlots(p, pinned, "pin-1")
	parkSlots(p, stale, "stale-1", "stale-2")
	parkSlots(p, recent, "recent-1")

	var released []string
	p.SetParkReleaser(func(id string) { released = append(released, id) })
	sp := &chanSpawner{destroyed: make(chan string, 8)}
	p.SetSpawner(sp)

	if got := p.Reclaim(3); got != 3 {
		t.Fatalf("Reclaim(3) = %d, want 3", got)
	}
	want := []string{"stale-1", "stale-2", "recent-1"}
	if len(released) != len(want) {
		t.Fatalf("released before return = %v, want %v", released, want)
	}
	for i := range want {
		if released[i] != want[i] {
			t.Fatalf("released = %v, want %v (least recently used non-pinned first)", released, want)
		}
	}
	if !p.HasReady(pinned) {
		t.Fatal("the pinned slot was reclaimed while non-pinned slots remained")
	}
	if got := p.Metrics().Stats().Reclaims; got != 3 {
		t.Fatalf("reclaims metric = %d, want 3", got)
	}

	var destroyed []string
	for range want {
		select {
		case id := <-sp.destroyed:
			destroyed = append(destroyed, id)
		case <-time.After(5 * time.Second):
			t.Fatalf("reclaimed containers destroyed = %v, want %v", destroyed, want)
		}
	}
	sort.Strings(destroyed)
	sort.Strings(want)
	for i := range want {
		if destroyed[i] != want[i] {
			t.Fatalf("destroyed = %v, want %v", destroyed, want)
		}
	}

	// Asking for more than is parked takes what is left, pinned last.
	if got := p.Reclaim(5); got != 1 {
		t.Fatalf("Reclaim(5) with one pinned slot left = %d, want 1", got)
	}
	if got := p.Reclaim(1); got != 0 {
		t.Fatalf("Reclaim on an empty pool = %d, want 0", got)
	}
}

func TestReclaimNoop(t *testing.T) {
	var nilPool *Pool
	if got := nilPool.Reclaim(2); got != 0 {
		t.Fatalf("nil pool Reclaim = %d", got)
	}
	p := New(nil)
	parkSlots(p, testKey(), "s1")
	if got := p.Reclaim(0); got != 0 {
		t.Fatalf("Reclaim(0) = %d", got)
	}
	if !p.HasReady(testKey()) {
		t.Fatal("Reclaim(0) took a slot")
	}
}
