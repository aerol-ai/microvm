package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/netns"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/store"
)

func TestWireContainerdNativeNetnsPoolDisabled(t *testing.T) {
	st := openDaemonTestStore(t)
	driver := cntr.New(cntr.FromDaemonConfig(config.Config{}), nil, testLogger())
	pool, err := wireContainerdNativeNetnsPool(context.Background(), config.Config{}, testLogger(), st, driver)
	if err != nil || pool != nil {
		t.Fatalf("pool=%v err=%v", pool, err)
	}
}

func TestWireContainerdNativeNetnsPoolEnabledRequiresCNIPaths(t *testing.T) {
	st := openDaemonTestStore(t)
	cfg := config.Config{
		ContainerEngine:                  "containerd",
		ContainerdNativeNetnsPoolEnabled: true,
		ContainerdNetnsPoolDepth:         2,
		ContainerdCNIPluginDir:           "",
		ContainerdCNIConfPath:            "",
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
	pool, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), st, driver)
	if err == nil {
		if pool != nil {
			pool.Stop()
		}
		t.Fatal("want cni config error")
	}
}

func TestContainerdNetnsPoolStopNilSafe(t *testing.T) {
	var p *containerdNetnsPool
	p.Stop()

	(&containerdNetnsPool{}).Stop()
}

func TestWireContainerdNativeNetnsPoolRequiresDriverAndStore(t *testing.T) {
	cfg := config.Config{
		ContainerEngine:                  "containerd",
		ContainerdNativeNetnsPoolEnabled: true,
	}
	if _, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), nil, nil); err == nil {
		t.Fatal("want driver/store required error")
	}
}

func TestWireContainerdNativeNetnsPoolSuccessWithoutWarmRealization(t *testing.T) {
	st := openDaemonTestStore(t)
	work := t.TempDir()
	origSysctls := ensureForwardingSysctls
	ensureForwardingSysctls = func() error { return nil }
	t.Cleanup(func() { ensureForwardingSysctls = origSysctls })
	cfg := config.Config{
		ContainerEngine:                   "containerd",
		ContainerdNativeNetnsPoolEnabled:  true,
		ContainerdNetnsPoolDepth:          0,
		ContainerdNetnsPoolSize:           1,
		ContainerdNetnsPoolRefillInterval: 10,
		ContainerdCNIPluginDir:            filepath.Join(work, "cni-bin"),
		ContainerdCNIConfPath:             filepath.Join(work, "cni", "aerolvm.conflist"),
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())

	pool, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), st, driver)
	if err != nil {
		t.Fatalf("wireContainerdNativeNetnsPool: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	pool.Stop()

	stats, err := netns.New(st).Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 1 {
		t.Fatalf("seeded %d netns slots, want 1", stats.Total)
	}
}

// TestWireContainerdNativeNetnsPoolSeedsFullSize is the density-cap regression:
// the pool must be seeded to ContainerdNetnsPoolSize (the concurrency ceiling),
// NOT the warm ContainerdNetnsPoolDepth. Seeding to depth once capped every node
// at 4 concurrent sandboxes. CNI paths are left empty so wiring errors AFTER the
// seed step (Seed commits before the CNI conflist check), letting us assert the
// seeded count offline without a real CNI host.
func TestWireContainerdNativeNetnsPoolSeedsFullSize(t *testing.T) {
	st := openDaemonTestStore(t)
	cfg := config.Config{
		ContainerEngine:                  "containerd",
		ContainerdNativeNetnsPoolEnabled: true,
		ContainerdNetnsPoolDepth:         4,
		ContainerdNetnsPoolSize:          64,
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
	// Errors on the missing CNI conflist; the seed has already committed.
	if pool, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), st, driver); err == nil {
		if pool != nil {
			pool.Stop()
		}
		t.Fatal("want cni config error (empty CNI paths)")
	}
	stats, err := netns.New(st).Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 64 {
		t.Fatalf("seeded %d netns slots, want 64 (pool size, not warm depth 4) — density-cap regression", stats.Total)
	}
}

// TestWireContainerdNativeNetnsPoolSizeFloorIsDepth guards the misconfiguration
// clamp: an unset/too-small size must floor to the warm depth so the refiller
// can still reach its target.
func TestWireContainerdNativeNetnsPoolSizeFloorIsDepth(t *testing.T) {
	st := openDaemonTestStore(t)
	cfg := config.Config{
		ContainerEngine:                  "containerd",
		ContainerdNativeNetnsPoolEnabled: true,
		ContainerdNetnsPoolDepth:         5,
		ContainerdNetnsPoolSize:          0, // unset → floor to depth
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
	if pool, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), st, driver); err == nil {
		if pool != nil {
			pool.Stop()
		}
		t.Fatal("want cni config error (empty CNI paths)")
	}
	stats, err := netns.New(st).Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 5 {
		t.Fatalf("seeded %d netns slots, want 5 (floored to warm depth)", stats.Total)
	}
}

func openDaemonTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

type fakeNetnsOwnerProber struct {
	exists map[string]bool
	err    error
}

func (f *fakeNetnsOwnerProber) SandboxContainerExists(_ context.Context, id string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.exists[id], nil
}

// The boot reconcile reaps a netns slot (CNI DEL inside its netns, then
// delete it) when this callback says the owner is dead. It used to say dead
// whenever Inspect failed or the task was not running, which reaped the
// network of every gVisor sandbox (Inspect cannot read its IP from the netns)
// and of every stopped sandbox at each daemon restart. Only a confirmed
// missing container may count as dead now.
func TestNetnsSlotOwnerLiveOnlyConfirmedGoneIsDead(t *testing.T) {
	ctx := context.Background()
	live := netnsSlotOwnerLive(&fakeNetnsOwnerProber{exists: map[string]bool{"sb-running-or-stopped": true}}, testLogger())
	if !live(ctx, "sb-running-or-stopped") {
		t.Fatal("a sandbox whose container exists must keep its slot")
	}
	if live(ctx, "sb-gone") {
		t.Fatal("a sandbox whose container is gone must lose its slot")
	}
	unsure := netnsSlotOwnerLive(&fakeNetnsOwnerProber{err: errors.New("containerd: connection refused")}, testLogger())
	if !unsure(ctx, "sb-unknown") {
		t.Fatal("an owner check that errored must keep the slot, not reap a possibly live sandbox")
	}
	if netnsSlotOwnerLive(nil, nil)(ctx, "sb-x") {
		t.Fatal("no prober means no owner can be confirmed")
	}
	if !netnsSlotOwnerLive(&fakeNetnsOwnerProber{err: errors.New("boom")}, nil)(ctx, "sb-x") {
		t.Fatal("nil logger must not change the answer")
	}
}

// End to end through Reconcile: a live owner's slot survives, a gone owner's
// slot is reaped.
func TestNetnsReconcileKeepsSlotOfExistingContainer(t *testing.T) {
	st := openDaemonTestStore(t)
	ctx := context.Background()
	pool := netns.New(st)
	if err := pool.Seed(ctx, netns.SeedConfig{PoolSize: 2}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	host := netns.NewFakeHost()
	h := netns.NewRuntimeHandoff(pool, host)
	for _, id := range []string{"sb-gvisor-live", "sb-gone"} {
		if _, _, err := h.Provision(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	live := netnsSlotOwnerLive(&fakeNetnsOwnerProber{exists: map[string]bool{"sb-gvisor-live": true}}, testLogger())
	reaped, err := pool.Reconcile(ctx, host, live, nil, time.Unix(2, 0))
	if err != nil || reaped != 1 {
		t.Fatalf("reaped=%d err=%v, want only the gone sandbox reaped", reaped, err)
	}
	if slot, _ := pool.Get(ctx, "sb-gvisor-live"); slot == nil {
		t.Fatal("the live sandbox lost its netns slot")
	}
	if got := host.Removed(); len(got) != 1 || got[0] != "sb-gone" {
		t.Fatalf("host teardown ran for %v, want only sb-gone", got)
	}
}
