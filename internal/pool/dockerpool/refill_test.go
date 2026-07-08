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
