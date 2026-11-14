package dockerpool

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func entryKey(image string) Key { return Key{Image: image, Runtime: models.RuntimeDocker} }

func parkSlot(p *Pool, id string, key Key) *ParkedSlot {
	slot := &ParkedSlot{ID: id, Key: key, Handle: &fakeHandle{alive: true}}
	p.RecordLoaded(slot)
	return slot
}

// TestSetConfiguredDepth: an entry's depth replaces the default for its own
// key only, a depth of 0 turns warming off for that image, and keys no
// entry names keep the default.
func TestSetConfiguredDepth(t *testing.T) {
	cases := []struct {
		name         string
		defaultDepth int
		entryDepth   int
		wantEntry    int
		wantOther    int
	}{
		{"entry above the default", 2, 5, 5, 2},
		{"entry below the default", 4, 1, 1, 4},
		{"entry turns its image off", 2, 0, 0, 2},
		{"entry on a pool whose default is off", 0, 3, 3, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(nil)
			p.SetDefaultDepth(tc.defaultDepth)
			py, other := entryKey("python:3.12"), entryKey("alpine:3.20")
			p.NoteTarget(other)
			p.SetConfigured([]Configured{{Key: py, Depth: tc.entryDepth}})
			if got := p.SpawnBudget(py.KeyString()); got != tc.wantEntry {
				t.Fatalf("entry budget = %d, want %d", got, tc.wantEntry)
			}
			if got := p.SpawnBudget(other.KeyString()); got != tc.wantOther {
				t.Fatalf("other budget = %d, want %d", got, tc.wantOther)
			}
		})
	}
}

// TestSetConfiguredKicksRefill: a new entry starts parking now, not on the
// next ticker interval.
func TestSetConfiguredKicksRefill(t *testing.T) {
	p := New(nil)
	p.SetConfigured([]Configured{{Key: entryKey("python:3.12"), Depth: 1}})
	select {
	case <-p.refillKick:
	default:
		t.Fatal("SetConfigured must kick refill")
	}
}

// TestSetConfiguredRemovalDrains: deleting an entry destroys its slots and
// releases their reservations at once; an image that is also an env pin
// keeps its slots and drops back to the default depth instead.
func TestSetConfiguredRemovalDrains(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(1)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	var released []string
	p.SetParkReleaser(func(id string) { released = append(released, id) })

	py, envImg := entryKey("python:3.12"), entryKey("alpine:3.20")
	p.PinTarget(envImg)
	p.SetConfigured([]Configured{{Key: py, Depth: 3}, {Key: envImg, Depth: 4}})
	parkSlot(p, "py-1", py)
	parkSlot(p, "py-2", py)
	parkSlot(p, "env-1", envImg)

	p.SetConfigured(nil)
	if !reflect.DeepEqual(spawner.destroyed, []string{"py-1", "py-2"}) || !reflect.DeepEqual(released, []string{"py-1", "py-2"}) {
		t.Fatalf("destroyed = %v released = %v, want the entry's two slots", spawner.destroyed, released)
	}
	if p.HasReady(py) || p.SpawnBudget(py.KeyString()) != 0 {
		t.Fatal("a deleted entry's image must stop being warmed")
	}
	if !p.HasReady(envImg) || p.SpawnBudget(envImg.KeyString()) != 0 {
		t.Fatal("an env-pinned image must keep its slot and fall back to the default depth (1, already met)")
	}
	if len(p.ListTargets()) != 1 {
		t.Fatalf("targets = %v, want only the env pin", p.ListTargets())
	}
	if p.ReapIdle(time.Now().Add(time.Hour)) != 0 {
		t.Fatal("the env pin stays pinned")
	}
}

// TestConfiguredEntryIsPinned: an entry never idle-expires, like an env pin.
func TestConfiguredEntryIsPinned(t *testing.T) {
	p := New(nil)
	p.SetIdleTTL(time.Millisecond)
	py := entryKey("python:3.12")
	p.SetConfigured([]Configured{{Key: py, Depth: 1}})
	parkSlot(p, "py-1", py)
	if got := p.ReapIdle(time.Now().Add(time.Hour)); got != 0 || !p.HasReady(py) {
		t.Fatalf("reaped %d slots of a configured entry", got)
	}
}

// TestRefillTrimsLoweredDepth: lowering an entry's depth gives the extra
// slots back on the next tick, newest first, and keeps the oldest.
func TestRefillTrimsLoweredDepth(t *testing.T) {
	p := New(nil)
	destroyer := &fakeSpawner{}
	p.SetSpawner(destroyer)
	py := entryKey("python:3.12")
	p.SetConfigured([]Configured{{Key: py, Depth: 3}})
	for _, id := range []string{"old", "mid", "new"} {
		parkSlot(p, id, py)
	}
	p.SetConfigured([]Configured{{Key: py, Depth: 1}})
	spawner := &refillSpawner{}
	p.refillTick(context.Background(), RefillConfig{}, spawner, &refillGate{canPark: true})
	if !reflect.DeepEqual(destroyer.destroyed, []string{"mid", "new"}) {
		t.Fatalf("trimmed %v, want the two newest", destroyer.destroyed)
	}
	if len(spawner.slots) != 0 {
		t.Fatal("a pool at its depth must not park more")
	}
	got, err := p.Acquire(context.Background(), py, "")
	if err != nil || got.ID != "old" {
		t.Fatalf("acquire = %v %v, want the oldest slot", got, err)
	}
}

// deletingSpawner removes the entry while its park is in flight.
type deletingSpawner struct {
	refillSpawner
	pool      *Pool
	destroyed []string
}

func (d *deletingSpawner) Park(ctx context.Context, slotID string, key Key) (*ParkedSlot, error) {
	d.pool.SetConfigured(nil)
	return d.refillSpawner.Park(ctx, slotID, key)
}

func (d *deletingSpawner) DestroyParked(_ context.Context, slot *ParkedSlot) error {
	d.destroyed = append(d.destroyed, slot.ID)
	return nil
}

// TestRefillDropsParkForDeletedEntry: a park that finishes after its entry
// was deleted is destroyed and its reservation given back, never queued
// under a key nothing acquires or reaps.
func TestRefillDropsParkForDeletedEntry(t *testing.T) {
	p := New(nil)
	py := entryKey("python:3.12")
	p.SetConfigured([]Configured{{Key: py, Depth: 2}})
	spawner := &deletingSpawner{pool: p}
	gate := &refillGate{canPark: true}
	p.refillTick(context.Background(), RefillConfig{}, spawner, gate)
	if len(spawner.destroyed) != 1 || !reflect.DeepEqual(gate.released, gate.reserved) || len(gate.reserved) != 1 {
		t.Fatalf("destroyed = %v reserved = %v released = %v", spawner.destroyed, gate.reserved, gate.released)
	}
	if p.HasReady(py) || p.spawning[py.KeyString()] != 0 {
		t.Fatal("the dropped slot must not be queued, and the in-flight count must be back to zero")
	}
	if p.Metrics().Stats().Refilled != 0 {
		t.Fatal("a dropped park is not a refill")
	}
}

func TestConfiguredStatus(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(2)
	py, node := entryKey("python:3.12"), entryKey("node:22")
	p.NoteTarget(entryKey("alpine:3.20"))
	p.SetConfigured([]Configured{{Key: py, Depth: 3}, {Key: node, Depth: 0}, {Key: Key{}, Depth: 9}})
	parkSlot(p, "py-1", py)
	got := p.ConfiguredStatus()
	want := []TargetStatus{{Key: node, Ready: 0, Target: 0}, {Key: py, Ready: 1, Target: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v, want %+v (entries only, sorted, the empty key skipped)", got, want)
	}
	var nilPool *Pool
	nilPool.SetConfigured([]Configured{{Key: py, Depth: 1}})
	if nilPool.ConfiguredStatus() != nil {
		t.Fatal("a nil pool reports nothing")
	}
}
