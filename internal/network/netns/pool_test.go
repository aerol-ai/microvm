package netns

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testPool(t *testing.T, size int) *Pool {
	t.Helper()
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(100, 0).UTC()
	p := New(st)
	if err := p.Seed(ctx, SeedConfig{PoolSize: size}, now); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPoolSeedIdempotent(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1, 0).UTC()
	p := New(st)
	if err := p.Seed(ctx, SeedConfig{PoolSize: 4}, now); err != nil {
		t.Fatal(err)
	}
	if err := p.Seed(ctx, SeedConfig{PoolSize: 4}, now); err != nil {
		t.Fatal(err)
	}
	stats, err := p.Stats(ctx)
	if err != nil || stats.Total != 4 || stats.Free != 4 {
		t.Fatalf("stats = %+v err=%v", stats, err)
	}
}

func TestPoolSeedRejectsInvalidSize(t *testing.T) {
	p := New(openTestStore(t))
	err := p.Seed(context.Background(), SeedConfig{PoolSize: 0}, time.Now())
	if err == nil {
		t.Fatal("want error for zero pool size")
	}
	err = p.Seed(context.Background(), SeedConfig{PoolSize: 20000}, time.Now())
	if err == nil {
		t.Fatal("want error for oversized pool")
	}
}

func TestPoolReserveReleaseRoundTrip(t *testing.T) {
	p := testPool(t, 2)
	ctx := context.Background()
	now := time.Unix(2, 0).UTC()
	slot, err := p.Reserve(ctx, "sb-1", now)
	if err != nil || slot.State != store.NetnsSlotStateReserved {
		t.Fatalf("reserve: %+v err=%v", slot, err)
	}
	if err := p.Release(ctx, "sb-1", now); err != nil {
		t.Fatal(err)
	}
	stats, _ := p.Stats(ctx)
	if stats.Free != 2 {
		t.Fatalf("free=%d want 2", stats.Free)
	}
}

func TestPoolExhaustion(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := p.Reserve(ctx, "a", now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reserve(ctx, "b", now); !errors.Is(err, store.ErrNoFreeContainerNetnsSlot) {
		t.Fatalf("want exhaustion, got %v", err)
	}
}

func TestBuilderHappyPath(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	b := NewBuilder(p, host)
	slot, err := b.Build(context.Background(), "sb-ok")
	if err != nil {
		t.Fatal(err)
	}
	if slot.State != store.NetnsSlotStateAdopted || slot.ContainerIP == "" {
		t.Fatalf("slot = %+v", slot)
	}
	if host.RealizedCount() != 1 {
		t.Fatal("host should still track until explicit remove")
	}
}

func TestBuilderLIFOTeardownOnAdoptFailure(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	host.SetRealizeError(errors.New("cni boom"))
	b := NewBuilder(p, host)
	if _, err := b.Build(context.Background(), "sb-fail"); err == nil {
		t.Fatal("want realize error")
	}
	stats, _ := p.Stats(context.Background())
	if stats.Free != 2 {
		t.Fatalf("slot should be released on failure, free=%d", stats.Free)
	}
}

func TestHostRealizeRemoveWithCNI(t *testing.T) {
	runner := cni.NewFakeRunner()
	h := &Host{
		Runner:    runner,
		NetnsRoot: t.TempDir(),
	}
	ctx := context.Background()
	slot := Slot{SandboxID: "sb-h"}
	path, ip, err := h.Realize(ctx, slot)
	if err != nil || ip == "" || path == "" {
		t.Fatalf("realize: path=%s ip=%s err=%v", path, ip, err)
	}
	slot.NetnsPath = path
	slot.ContainerIP = ip
	if err := h.Remove(ctx, slot); err != nil {
		t.Fatal(err)
	}
	if len(runner.Dels()) != 1 {
		t.Fatalf("dels=%d", len(runner.Dels()))
	}
}

func TestHostRealizeRequiresRunner(t *testing.T) {
	_, _, err := (&Host{}).Realize(context.Background(), Slot{SandboxID: "x"})
	if err == nil {
		t.Fatal("want error")
	}
}

func TestHostRemoveIdempotent(t *testing.T) {
	runner := cni.NewFakeRunner()
	h := &Host{Runner: runner, NetnsRoot: t.TempDir()}
	if err := h.Remove(context.Background(), Slot{}); err != nil {
		t.Fatal(err)
	}
}

func TestPoolMarkRealizedAndAdopt(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	now := time.Unix(3, 0).UTC()
	_, _ = p.Reserve(ctx, "sb-m", now)
	slot, err := p.MarkRealized(ctx, "sb-m", "/run/n", "10.1.1.1", now)
	if err != nil || slot.State != store.NetnsSlotStateRealized {
		t.Fatalf("mark: %+v err=%v", slot, err)
	}
	slot, err = p.Adopt(ctx, "sb-m", now)
	if err != nil || slot.State != store.NetnsSlotStateAdopted {
		t.Fatalf("adopt: %+v err=%v", slot, err)
	}
}

func TestPoolGetMissing(t *testing.T) {
	p := testPool(t, 1)
	slot, err := p.Get(context.Background(), "missing")
	if err != nil || slot != nil {
		t.Fatalf("got slot=%+v err=%v", slot, err)
	}
}

func TestBuilderConcurrentSandboxes(t *testing.T) {
	p := testPool(t, 8)
	host := NewFakeHost()
	b := NewBuilder(p, host)
	for i := 0; i < 5; i++ {
		id := "sb-" + string(rune('a'+i))
		if _, err := b.Build(context.Background(), id); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	stats, _ := p.Stats(context.Background())
	if stats.Adopted != 5 || stats.Free != 3 {
		t.Fatalf("stats=%+v", stats)
	}
}
