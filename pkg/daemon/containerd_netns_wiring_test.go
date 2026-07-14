package daemon

import (
	"context"
	"testing"

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
