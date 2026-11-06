package dockerpool

import (
	"context"
	"testing"
	"time"
)

// fakeClock drives the demand sampler: tests move it by whole windows.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func demandPool(t *testing.T, minDepth, maxDepth int) (*Pool, *fakeClock, Key) {
	t.Helper()
	p := New(nil)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	key := entryKey("python:3.12")
	p.SetConfigured([]Configured{{Key: key, MinDepth: minDepth, MaxDepth: maxDepth}})
	// The first sample starts the first window.
	p.sampleDemand()
	return p, clk, key
}

func creates(p *Pool, key Key, n int) {
	for i := 0; i < n; i++ {
		p.NoteMiss(key)
	}
}

func target(p *Pool, key Key) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.depthLocked(key.KeyString())
}

// TestDemandTargetFollowsCreates walks one entry through the windows a
// real image sees: idle at its floor, a burst, a cap, and the decay back.
func TestDemandTargetFollowsCreates(t *testing.T) {
	p, clk, key := demandPool(t, 0, 4)
	if got := target(p, key); got != 0 || p.SpawnBudget(key.KeyString()) != 0 {
		t.Fatalf("a new entry starts at its floor: target %d", got)
	}
	steps := []struct {
		name    string
		creates int
		windows int
		want    int
	}{
		{"three creates in a window: average 1.5, rounded up", 3, 1, 2},
		{"a window with half the demand: 0.5*1 + 0.5*1.5 = 1.25", 1, 1, 2},
		{"a burst of twenty is capped at max_depth", 20, 1, 4},
		{"idle: 10.625 halves to 5.3", 0, 1, 4},
		{"idle: 2.66", 0, 1, 3},
		{"two idle windows at once: 0.66", 0, 2, 1},
		{"idle: 0.33", 0, 1, 1},
		{"idle: 0.17", 0, 1, 1},
		{"idle: 0.08 is no demand, so zero", 0, 1, 0},
	}
	for _, s := range steps {
		creates(p, key, s.creates)
		// A sample inside the window changes nothing.
		clk.advance(demandWindow / 2)
		p.sampleDemand()
		clk.advance(time.Duration(s.windows)*demandWindow - demandWindow/2)
		p.sampleDemand()
		if got := target(p, key); got != s.want {
			t.Fatalf("%s: target = %d, want %d (avg %.3f)", s.name, got, s.want, p.demand[key.KeyString()].avg)
		}
	}
}

// TestDemandFloorAndHits: min_depth is a floor the average never takes the
// target under, and hits count as demand like misses do.
func TestDemandFloorAndHits(t *testing.T) {
	p, clk, key := demandPool(t, 1, 3)
	if got := target(p, key); got != 1 {
		t.Fatalf("starts at min_depth: %d", got)
	}
	for i := 0; i < 4; i++ {
		parkSlot(p, "s", key)
		if _, err := p.Acquire(context.Background(), key, ""); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(demandWindow)
	p.sampleDemand()
	if got := target(p, key); got != 2 {
		t.Fatalf("four hits: average 2, target %d", got)
	}
	clk.advance(20 * demandWindow)
	p.sampleDemand()
	if got := target(p, key); got != 1 {
		t.Fatalf("idle for a long time: back to the floor, got %d", got)
	}
}

// TestDemandStateAcrossReconfigure: new limits keep the average (demand did
// not change) and re-clamp at once; switching the entry to a fixed depth,
// or deleting it, drops the state; other keys are never counted.
func TestDemandStateAcrossReconfigure(t *testing.T) {
	p, clk, key := demandPool(t, 0, 8)
	creates(p, key, 12)
	clk.advance(demandWindow)
	p.sampleDemand()
	if got := target(p, key); got != 6 {
		t.Fatalf("target = %d, want 6", got)
	}
	p.SetConfigured([]Configured{{Key: key, MinDepth: 0, MaxDepth: 3}})
	if got := target(p, key); got != 3 {
		t.Fatalf("a lower max re-clamps at once: %d", got)
	}
	p.SetConfigured([]Configured{{Key: key, MinDepth: 0, MaxDepth: 8}})
	if got := target(p, key); got != 6 {
		t.Fatalf("raising it back keeps the average: %d", got)
	}
	p.SetConfigured([]Configured{{Key: key, Depth: 2}})
	if _, ok := p.demand[key.KeyString()]; ok || target(p, key) != 2 {
		t.Fatal("a fixed entry has no demand state and uses its depth")
	}
	other := entryKey("node:22")
	p.NoteTarget(other)
	creates(p, other, 5)
	creates(p, key, 5)
	if len(p.demand) != 0 {
		t.Fatalf("only demand-following entries are counted: %v", p.demand)
	}
	p.SetConfigured([]Configured{{Key: key, MaxDepth: 2}})
	p.SetConfigured(nil)
	if len(p.demand) != 0 {
		t.Fatal("a deleted entry's state is dropped")
	}
}

// TestRefillFollowsDemand: the refill tick samples first, parks up to a
// risen target and gives back slots past a fallen one.
func TestRefillFollowsDemand(t *testing.T) {
	p, clk, key := demandPool(t, 0, 4)
	destroyer := &fakeSpawner{}
	p.SetSpawner(destroyer)
	spawner := &refillSpawner{}
	gate := &refillGate{canPark: true}
	p.refillTick(context.Background(), RefillConfig{}, spawner, gate)
	if len(spawner.slots) != 0 {
		t.Fatal("no demand yet: nothing parked")
	}
	creates(p, key, 6)
	clk.advance(demandWindow)
	p.refillTick(context.Background(), RefillConfig{}, spawner, gate)
	if len(spawner.slots) != 3 {
		t.Fatalf("six creates in a window: parked %d, want 3", len(spawner.slots))
	}
	if st := p.ConfiguredStatus(); len(st) != 1 || st[0].Target != 3 || st[0].Ready != 3 {
		t.Fatalf("status = %+v", st)
	}
	clk.advance(10 * demandWindow)
	p.refillTick(context.Background(), RefillConfig{}, spawner, gate)
	if len(destroyer.destroyed) != 3 || p.HasReady(key) {
		t.Fatalf("idle: gave back %v, want all three", destroyer.destroyed)
	}
}

func TestDemandTargetClamp(t *testing.T) {
	c := Configured{MinDepth: 1, MaxDepth: 5}
	for _, tc := range []struct {
		avg  float64
		want int
	}{{0, 1}, {0.05, 1}, {1.01, 2}, {4.2, 5}, {99, 5}} {
		if got := demandTarget(tc.avg, c); got != tc.want {
			t.Errorf("demandTarget(%v) = %d, want %d", tc.avg, got, tc.want)
		}
	}
	if (&Pool{}).clock().IsZero() {
		t.Fatal("a pool with no clock uses the wall clock")
	}
	lit := &Pool{configured: map[string]Configured{"k": {MaxDepth: 2}}}
	lit.countDemandLocked("k")
	if lit.demand["k"].count != 1 {
		t.Fatal("a pool built as a literal still counts")
	}
}
