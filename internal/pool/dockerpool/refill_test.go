package dockerpool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

type refillSpawner struct {
	err   error
	slots []*ParkedSlot
}

func (r *refillSpawner) Park(_ context.Context, slotID string, key Key) (*ParkedSlot, error) {
	if r.err != nil {
		return nil, r.err
	}
	slot := &ParkedSlot{
		ID: slotID, Key: key, Handle: &fakeHandle{alive: true},
	}
	r.slots = append(r.slots, slot)
	return slot, nil
}

func (r *refillSpawner) DestroyParked(context.Context, *ParkedSlot) error { return nil }

type refillGate struct {
	canPark  bool
	reserved []string
	released []string
	parkErr  error
}

func (g *refillGate) CanPark(ParkShape) bool { return g.canPark }
func (g *refillGate) ParkReservation(id string, _ ParkShape) error {
	if g.parkErr != nil {
		return g.parkErr
	}
	g.reserved = append(g.reserved, id)
	return nil
}
func (g *refillGate) ReleasePark(id string) { g.released = append(g.released, id) }

func TestRefillTickLoadsSlot(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(1)
	key := testKey()
	p.PinTarget(key)

	spawner := &refillSpawner{}
	gate := &refillGate{canPark: true}
	cfg := RefillConfig{ParkShape: ParkShape{Runtime: models.RuntimeDocker}}

	p.refillTick(context.Background(), cfg, spawner, gate)
	if len(spawner.slots) != 1 {
		t.Fatalf("slots = %d", len(spawner.slots))
	}
	if len(gate.reserved) != 1 {
		t.Fatalf("reserved = %v", gate.reserved)
	}
	if p.Metrics().Stats().Refilled != 1 {
		t.Fatalf("refilled = %d", p.Metrics().Stats().Refilled)
	}
}

func TestRefillTickParkFailureReleasesReservation(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(1)
	p.PinTarget(testKey())

	spawner := &refillSpawner{err: errors.New("park failed")}
	gate := &refillGate{canPark: true}
	cfg := RefillConfig{ParkShape: ParkShape{Runtime: models.RuntimeDocker}}

	p.refillTick(context.Background(), cfg, spawner, gate)
	if len(gate.released) != 1 {
		t.Fatalf("released = %v", gate.released)
	}
	if p.Metrics().Stats().SpawnFail != 1 {
		t.Fatalf("spawn fail = %d", p.Metrics().Stats().SpawnFail)
	}
}

func TestRefillTickGateBlocks(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(2)
	p.PinTarget(testKey())
	spawner := &refillSpawner{}
	gate := &refillGate{canPark: false}
	p.refillTick(context.Background(), RefillConfig{}, spawner, gate)
	if len(spawner.slots) != 0 {
		t.Fatal("expected no parks when gate blocks")
	}
}

func TestRunRefillStopsOnCancel(t *testing.T) {
	p := New(nil)
	p.PinTarget(testKey())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx, RefillConfig{RefillInterval: 5 * time.Millisecond}, &refillSpawner{}, &refillGate{canPark: true})
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refill loop did not stop")
	}
}

func TestRunRefillNilSpawnerNoop(t *testing.T) {
	p := New(nil)
	p.Run(context.Background(), RefillConfig{}, nil, nil)
}

func TestRunRefillWrapper(t *testing.T) {
	p := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RunRefill(ctx, p, RefillConfig{}, &refillSpawner{}, nil, nil)
}

// A target whose image is gone for good (image-GC'd one-off snapshot/build
// tag) must stop consuming refill ticks: without eviction the loop retries a
// doomed park every interval forever — the live v0.5.29 nodes accumulated
// ~190 spawn failures each retrying a deleted snapshot image.
func TestRefillTickEvictsTargetAfterConsecutiveFailures(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(1)
	key := testKey()
	p.NoteTarget(key)

	spawner := &refillSpawner{err: errors.New("no such image")}
	gate := &refillGate{canPark: true}
	cfg := RefillConfig{ParkShape: ParkShape{Runtime: models.RuntimeDocker}}

	for i := range maxConsecutiveSpawnFails {
		if len(p.ListTargets()) != 1 {
			t.Fatalf("target evicted early after %d failures", i)
		}
		p.refillTick(context.Background(), cfg, spawner, gate)
	}
	if len(p.ListTargets()) != 0 {
		t.Fatalf("target not evicted after %d consecutive failures", maxConsecutiveSpawnFails)
	}
	if got := p.Metrics().Stats().TargetEvicts; got != 1 {
		t.Fatalf("target evictions = %d, want 1", got)
	}
	// Every failed park must still have released its reservation.
	if len(gate.released) != maxConsecutiveSpawnFails {
		t.Fatalf("released = %d, want %d", len(gate.released), maxConsecutiveSpawnFails)
	}

	// A later miss re-registers the target — eviction is never sticky, and
	// the failure streak starts fresh.
	p.NoteMiss(key)
	if len(p.ListTargets()) != 1 {
		t.Fatal("NoteMiss did not re-register an evicted target")
	}
	p.refillTick(context.Background(), cfg, spawner, gate)
	if len(p.ListTargets()) != 1 {
		t.Fatal("re-registered target evicted after a single failure")
	}
}

// Pinned targets are operator config: dropping one would silently disable a
// deliberately warmed image, so they ride out any failure streak.
func TestRefillTickNeverEvictsPinnedTarget(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(1)
	p.PinTarget(testKey())

	spawner := &refillSpawner{err: errors.New("no such image")}
	gate := &refillGate{canPark: true}
	cfg := RefillConfig{ParkShape: ParkShape{Runtime: models.RuntimeDocker}}

	for range maxConsecutiveSpawnFails + 2 {
		p.refillTick(context.Background(), cfg, spawner, gate)
	}
	if len(p.ListTargets()) != 1 {
		t.Fatal("pinned target was evicted")
	}
}

// A success anywhere in the streak resets the count: the threshold measures
// an unbroken run of failures, not a lifetime tally.
func TestRefillTickSuccessResetsFailureStreak(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(1)
	key := testKey()
	p.NoteTarget(key)

	spawner := &refillSpawner{err: errors.New("transient")}
	gate := &refillGate{canPark: true}
	cfg := RefillConfig{ParkShape: ParkShape{Runtime: models.RuntimeDocker}}

	for range maxConsecutiveSpawnFails - 1 {
		p.refillTick(context.Background(), cfg, spawner, gate)
	}
	spawner.err = nil
	p.refillTick(context.Background(), cfg, spawner, gate) // success resets
	spawner.err = errors.New("transient again")
	for range maxConsecutiveSpawnFails - 1 {
		p.refillTick(context.Background(), cfg, spawner, gate)
	}
	if len(p.ListTargets()) != 1 {
		t.Fatal("streak did not reset on success")
	}
}

// Eviction must destroy any ready slots the target still holds and release
// their park reservations — otherwise the admitter leaks capacity.
func TestNoteSpawnFailureEvictionDestroysReadySlots(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(2)
	rec := &releaseRecorder{}
	p.SetParkReleaser(rec.record)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	key := testKey()
	p.NoteTarget(key)
	p.RecordLoaded(&ParkedSlot{ID: "park-live", Key: key, Handle: &fakeHandle{alive: true}})

	ks := key.KeyString()
	for range maxConsecutiveSpawnFails {
		p.NoteSpawnFailure(ks)
	}
	if len(p.ListTargets()) != 0 {
		t.Fatal("target not evicted")
	}
	if len(spawner.destroyed) != 1 || spawner.destroyed[0] != "park-live" {
		t.Fatalf("destroyed = %v", spawner.destroyed)
	}
	if len(rec.released) != 1 || rec.released[0] != "park-live" {
		t.Fatalf("released = %v", rec.released)
	}
}
