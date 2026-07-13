package netns

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

func TestPoolReassignOwner(t *testing.T) {
	p := testPool(t, 4)
	ctx := context.Background()
	now := time.Unix(200, 0).UTC()
	host := NewFakeHost()

	// Build an adopted slot owned by the park id.
	if _, err := NewBuilder(p, host).Build(ctx, "park-1"); err != nil {
		t.Fatal(err)
	}
	if err := p.ReassignOwner(ctx, "park-1", "sb-1", now); err != nil {
		t.Fatalf("ReassignOwner: %v", err)
	}
	// Ownership moved park-1 -> sb-1.
	if got, _ := p.Get(ctx, "sb-1"); got == nil {
		t.Fatal("sb-1 should own the slot after reassign")
	}
	if got, _ := p.Get(ctx, "park-1"); got != nil {
		t.Fatalf("park-1 should no longer own a slot, got %+v", got)
	}
	// Idempotent: target already owns → no-op, no error.
	if err := p.ReassignOwner(ctx, "park-1", "sb-1", now); err != nil {
		t.Fatalf("idempotent ReassignOwner: %v", err)
	}
	// from == to → no-op.
	if err := p.ReassignOwner(ctx, "sb-1", "sb-1", now); err != nil {
		t.Fatalf("self ReassignOwner: %v", err)
	}
	// nil pool → no-op.
	if err := (*Pool)(nil).ReassignOwner(ctx, "a", "b", now); err != nil {
		t.Fatalf("nil pool ReassignOwner: %v", err)
	}
}

func TestRuntimeHandoffReassignOwner(t *testing.T) {
	p := testPool(t, 4)
	ctx := context.Background()
	host := NewFakeHost()
	h := NewRuntimeHandoff(p, host)
	if _, err := NewBuilder(p, host).Build(ctx, "park-2"); err != nil {
		t.Fatal(err)
	}
	if err := h.ReassignOwner(ctx, "park-2", "sb-2"); err != nil {
		t.Fatalf("handoff ReassignOwner: %v", err)
	}
	if got, _ := p.Get(ctx, "sb-2"); got == nil {
		t.Fatal("sb-2 should own the slot after handoff reassign")
	}
	if err := (*RuntimeHandoff)(nil).ReassignOwner(ctx, "a", "b"); err != nil {
		t.Fatalf("nil handoff ReassignOwner: %v", err)
	}
}

func TestReconcileReapsDeadAdopted(t *testing.T) {
	p := testPool(t, 4)
	ctx := context.Background()
	now := time.Unix(300, 0).UTC()
	host := NewFakeHost()
	for _, id := range []string{"sb-a", "sb-b"} {
		if _, err := NewBuilder(p, host).Build(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	// live==nil treats every adopted owner as dead → both reaped.
	reaped, err := p.Reconcile(ctx, host, nil, func(string) bool { return true }, now)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 2 {
		t.Fatalf("reaped = %d, want 2", reaped)
	}
	stats, _ := p.Stats(ctx)
	if stats.Free != 4 || stats.Adopted != 0 {
		t.Fatalf("pool not fully freed after reconcile: %+v", stats)
	}
}

// TestReserveConcurrentSameSandboxNoDoubleAlloc is the fragile-allocator
// regression (pr-review §6 / CLAUDE.md): N callers on SEPARATE *Store handles
// (defeating single-writer serialization) race Reserve for the SAME sandbox.
// The partial unique index on sandbox_id must guarantee exactly one slot ends
// owned by it — no double allocation — even though losers may see a raw
// constraint error.
func TestReserveConcurrentSameSandboxNoDoubleAlloc(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	now := time.Unix(100, 0).UTC()
	seed, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := New(seed).Seed(context.Background(), SeedConfig{PoolSize: 8}, now); err != nil {
		t.Fatal(err)
	}
	_ = seed.Close()

	const n = 6
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			st, err := store.Open(path)
			if err != nil {
				return
			}
			defer st.Close()
			_, _ = New(st).Reserve(context.Background(), "sb-race", now)
		}()
	}
	wg.Wait()

	check, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	if slot, err := check.GetContainerNetnsSlotBySandbox(context.Background(), "sb-race"); err != nil || slot == nil {
		t.Fatalf("sb-race must own exactly one slot: slot=%v err=%v", slot, err)
	}
	reserved, err := check.ListContainerNetnsSlotsByState(context.Background(), store.NetnsSlotStateReserved)
	if err != nil {
		t.Fatal(err)
	}
	owned := 0
	for _, s := range reserved {
		if s.SandboxID == "sb-race" {
			owned++
		}
	}
	if owned != 1 {
		t.Fatalf("sb-race owns %d slots, want exactly 1 (no double allocation)", owned)
	}
}
