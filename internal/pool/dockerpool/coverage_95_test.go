package dockerpool

import (
	"context"
	"testing"
	"time"
)

func TestHasReadyAndReleaseParkCoverage95(t *testing.T) {
	p := New(nil)
	key := testKey()
	if p.HasReady(key) {
		t.Fatal("empty pool should not have ready")
	}

	released := ""
	p.SetParkReleaser(func(slotID string) { released = slotID })
	p.ReleasePark("")
	if released != "" {
		t.Fatal("empty slotID must not invoke releaser")
	}
	p.ReleasePark("park-x")
	if released != "park-x" {
		t.Fatalf("released = %q", released)
	}

	slot := &ParkedSlot{ID: "park-ready", Key: key, Handle: &fakeHandle{alive: true}}
	p.RecordLoaded(slot)
	if !p.HasReady(key) {
		t.Fatal("expected ready after RecordLoaded")
	}
}

func TestDestroySlotsNilAndNilSpawner(t *testing.T) {
	p := New(nil)
	released := []string{}
	p.SetParkReleaser(func(id string) { released = append(released, id) })
	p.destroySlots(context.Background(), []*ParkedSlot{nil, {ID: "park-nil-spawner"}})
	if len(released) != 1 || released[0] != "park-nil-spawner" {
		t.Fatalf("released = %v", released)
	}
}

func TestRecordAdoptMSNilReceiver(t *testing.T) {
	var m *Metrics
	m.RecordAdoptMS(12)
}

func TestReturnSlotAndRecordLoadedNil(t *testing.T) {
	p := New(nil)
	p.ReturnSlot(nil)
	p.RecordLoaded(nil)
}

func TestKickRefillLockedNilChannelAndDefault(t *testing.T) {
	p := New(nil)
	p.refillKick = nil
	p.kickRefillLocked()

	p.refillKick = make(chan struct{}, 1)
	p.kickRefillLocked()
	p.kickRefillLocked() // default branch when buffer full
}

func TestNoteTargetEmptyImageNoop(t *testing.T) {
	p := New(nil)
	p.NoteTarget(Key{})
	if len(p.ListTargets()) != 0 {
		t.Fatal("empty image must not register target")
	}
}

func TestEvictLRUTargetLockedAllPinned(t *testing.T) {
	p := New(nil)
	p.SetMaxImages(1)
	key := testKey()
	p.PinTarget(key)
	// Only pinned targets → evict returns nil (oldest == "").
	if slots := p.evictLRUTargetLocked(); slots != nil {
		t.Fatalf("slots = %v", slots)
	}
}

func TestSpawnBudgetDepthZeroAndMissingTarget(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(0)
	if b := p.SpawnBudget("x"); b != 0 {
		t.Fatalf("depth 0 budget = %d", b)
	}
	p.SetDefaultDepth(2)
	if b := p.SpawnBudget("missing"); b != 0 {
		t.Fatalf("missing target budget = %d", b)
	}
}

func TestReapIdleTTLDisabled(t *testing.T) {
	p := New(nil)
	if n := p.ReapIdle(time.Now()); n != 0 {
		t.Fatalf("reaped = %d", n)
	}
}

func TestAcquireNilSlotInQueue(t *testing.T) {
	p := New(nil)
	key := testKey()
	ks := key.KeyString()
	p.mu.Lock()
	p.ready[ks] = []*ParkedSlot{nil, {ID: "alive", Key: key, Handle: &fakeHandle{alive: true}}}
	p.mu.Unlock()

	got, err := p.Acquire(context.Background(), key, "")
	if err != nil || got == nil || got.ID != "alive" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
