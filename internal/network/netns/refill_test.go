package netns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/store"
)

func TestPrewarmAndClaimPooled(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	ctx := context.Background()
	now := time.Unix(10, 0).UTC()

	if err := p.Prewarm(ctx, host, now); err != nil {
		t.Fatal(err)
	}
	stats, _ := p.Stats(ctx)
	if stats.Pooled != 1 {
		t.Fatalf("pooled=%d", stats.Pooled)
	}

	slot, hit, err := p.ClaimPooled(ctx, "sb-warm", now)
	if err != nil || !hit {
		t.Fatalf("claim: hit=%v err=%v", hit, err)
	}
	if slot.ContainerIP == "" || slot.NetnsPath == "" {
		t.Fatalf("slot=%+v", slot)
	}
	stats, _ = p.Stats(ctx)
	if stats.Adopted != 1 || stats.Pooled != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestClaimPooledMiss(t *testing.T) {
	p := testPool(t, 1)
	slot, hit, err := p.ClaimPooled(context.Background(), "sb-cold", time.Now())
	if err != nil || hit || slot != nil {
		t.Fatalf("want miss, got hit=%v slot=%+v err=%v", hit, slot, err)
	}
}

func TestRefillerFillsToDepth(t *testing.T) {
	p := testPool(t, 4)
	host := NewFakeHost()
	r := NewRefiller(p, host, 3, time.Hour)
	r.refillOnce(context.Background())
	stats, _ := p.Stats(context.Background())
	if stats.Pooled != 3 {
		t.Fatalf("pooled=%d want 3", stats.Pooled)
	}
}

func TestRefillerStop(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	r := NewRefiller(p, host, 1, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	time.Sleep(30 * time.Millisecond)
	cancel()
	r.Stop()
}

func TestReconcileReapsStalePooled(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = p.Seed(ctx, SeedConfig{PoolSize: 1}, now)
	slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/gone/netns", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	reaped, err := p.Reconcile(ctx, NewFakeHost(), nil, func(string) bool { return false }, now)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped=%d", reaped)
	}
	stats, _ := p.Stats(ctx)
	if stats.Free != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestReconcileKeepsLiveAdopted(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	ctx := context.Background()
	now := time.Now().UTC()
	_, _, _ = NewRuntimeHandoff(p, host).Provision(ctx, "sb-live")
	live := func(_ context.Context, id string) bool { return id == "sb-live" }
	reaped, err := p.Reconcile(ctx, host, live, nil, now)
	if err != nil || reaped != 0 {
		t.Fatalf("reaped=%d err=%v", reaped, err)
	}
}

// Crash after reserve but before CNI ADD: reserved row with empty netns path
// must reset to free on reconcile when the sandbox is not live.
func TestReconcileReapsCrashBeforeCNI(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	host := NewFakeHost()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{PoolSize: 1}, now); err != nil {
		t.Fatal(err)
	}
	slot, err := st.ReserveContainerNetnsSlot(ctx, "sb-pre-cni", now)
	if err != nil {
		t.Fatal(err)
	}
	if slot.NetnsPath != "" {
		t.Fatalf("pre-CNI slot should have empty path, got %q", slot.NetnsPath)
	}
	reaped, err := p.Reconcile(ctx, host, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped=%d want 1", reaped)
	}
	stats, _ := p.Stats(ctx)
	if stats.Free != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

// Crash between CNI ADD and store MarkRealized: reserved row + live netns path
// must be reaped on boot reconcile when live==nil (daemon restart).
func TestReconcileReapsCrashBetweenRealizeAndRecord(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	host := NewFakeHost()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{PoolSize: 1}, now); err != nil {
		t.Fatal(err)
	}
	slot, err := st.ReserveContainerNetnsSlot(ctx, "sb-crash", now)
	if err != nil {
		t.Fatal(err)
	}
	path, ip, err := host.Realize(ctx, Slot{SlotID: slot.SlotID, SandboxID: "sb-crash"})
	if err != nil || path == "" || ip == "" {
		t.Fatalf("realize: %s %s %v", path, ip, err)
	}
	reaped, err := p.Reconcile(ctx, host, nil, func(p string) bool { return p == path }, now)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped=%d want 1", reaped)
	}
	stats, _ := p.Stats(ctx)
	if stats.Free != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	if host.RemovedCount() != 1 {
		t.Fatalf("host removes=%d", host.RemovedCount())
	}
}

func TestHandoffUsesPooledSlot(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	ctx := context.Background()
	if err := p.Prewarm(ctx, host, time.Now()); err != nil {
		t.Fatal(err)
	}
	path, ip, err := NewRuntimeHandoff(p, host).Provision(ctx, "sb-hit")
	if err != nil || path == "" || ip == "" {
		t.Fatalf("provision: %s %s %v", path, ip, err)
	}
	if host.RealizedCount() != 1 {
		t.Fatal("prewarm should not re-realize on claim")
	}
}

func TestPrewarmFailureResetsSlot(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	host.SetRealizeError(errors.New("boom"))
	if err := p.Prewarm(context.Background(), host, time.Now()); err == nil {
		t.Fatal("want error")
	}
	stats, _ := p.Stats(context.Background())
	if stats.Free != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestTargetDepth(t *testing.T) {
	p := testPool(t, 3)
	need, err := p.TargetDepth(context.Background(), 2)
	if err != nil || need != 2 {
		t.Fatalf("need=%d err=%v", need, err)
	}
	runner := cni.NewFakeRunner()
	_ = p.Prewarm(context.Background(), &Host{Runner: runner, NetnsRoot: t.TempDir()}, time.Now())
	need, _ = p.TargetDepth(context.Background(), 2)
	if need != 1 {
		t.Fatalf("need=%d want 1", need)
	}
}

func TestStorePrewarmRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if slot.SandboxID != slot.SlotID {
		t.Fatalf("owner=%q", slot.SandboxID)
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/n", "10.1.1.1", now); err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.State != store.NetnsSlotStateAdopted {
		t.Fatalf("state=%s", claimed.State)
	}
}
