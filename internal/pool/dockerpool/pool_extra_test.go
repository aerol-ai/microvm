package dockerpool

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestPoolEvictLRUOnMaxImages(t *testing.T) {
	p := New(nil)
	p.SetMaxImages(1)
	k1 := Key{Image: "img-a", Runtime: models.RuntimeDocker}
	k2 := Key{Image: "img-b", Runtime: models.RuntimeDocker}
	p.NoteTarget(k1)
	time.Sleep(time.Millisecond)
	p.NoteTarget(k2)
	if len(p.ListTargets()) != 1 {
		t.Fatalf("targets = %d, want 1 after LRU eviction", len(p.ListTargets()))
	}
}

func TestPoolAcquireOrphanSlot(t *testing.T) {
	p := New(nil)
	key := testKey()
	p.NoteTarget(key)
	p.RecordLoaded(&ParkedSlot{
		ID: "dead", Key: key, ImageID: "img-1",
		Handle: &fakeHandle{alive: false},
	})
	_, err := p.Acquire(context.Background(), key, "img-1")
	if err != ErrNoSlot {
		t.Fatalf("err = %v", err)
	}
	if p.Metrics().Stats().Orphans != 1 {
		t.Fatalf("orphans = %d", p.Metrics().Stats().Orphans)
	}
}

func TestPoolCloseReleasesParkReservations(t *testing.T) {
	p := New(nil)
	var released []string
	p.SetParkReleaser(func(id string) { released = append(released, id) })
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	key := testKey()
	p.RecordLoaded(&ParkedSlot{ID: "park-close", Key: key, Handle: &fakeHandle{alive: true}})
	if n := p.Close(); n != 1 {
		t.Fatalf("drained = %d", n)
	}
	if len(released) != 1 || released[0] != "park-close" {
		t.Fatalf("released = %v", released)
	}
}

func TestPoolPinnedTargetSurvivesReap(t *testing.T) {
	p := New(nil)
	p.SetIdleTTL(time.Millisecond)
	key := testKey()
	p.PinTarget(key)
	p.RecordLoaded(&ParkedSlot{ID: "park-pin", Key: key, Handle: &fakeHandle{alive: true}})
	time.Sleep(2 * time.Millisecond)
	if n := p.ReapIdle(time.Now().UTC()); n != 0 {
		t.Fatalf("reaped pinned = %d", n)
	}
}

func TestPoolMarkUnmarkSpawning(t *testing.T) {
	p := New(nil)
	ks := testKey().KeyString()
	p.MarkSpawning(ks)
	p.MarkSpawning(ks)
	p.UnmarkSpawning(ks)
	if b := p.SpawnBudget(ks); b < 0 {
		t.Fatalf("budget = %d", b)
	}
}

func TestNewSlotID(t *testing.T) {
	id, err := NewSlotID()
	if err != nil || id == "" {
		t.Fatalf("id = %q err = %v", id, err)
	}
}

func TestParkReservationID(t *testing.T) {
	if ParkReservationID("x") != "park:x" {
		t.Fatal()
	}
}
