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
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage95WireContainerdNativeNetnsPoolBranches(t *testing.T) {
	st := openDaemonTestStore(t)
	work := t.TempDir()
	origSysctls := ensureForwardingSysctls
	t.Cleanup(func() { ensureForwardingSysctls = origSysctls })

	cfg := config.Config{
		ContainerEngine:                   models.ContainerEngineContainerd,
		ContainerdNativeNetnsPoolEnabled:  true,
		ContainerdNetnsPoolDepth:          0,
		ContainerdNetnsPoolSize:           1,
		ContainerdNetnsPoolRefillInterval: time.Hour,
		ContainerdCNIPluginDir:            filepath.Join(work, "cni-bin"),
		ContainerdCNIConfPath:             filepath.Join(work, "cni", "aerolvm.conflist"),
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())

	t.Run("sysctl_error", func(t *testing.T) {
		ensureForwardingSysctls = func() error { return errors.New("sysctl boom") }
		if _, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), st, driver); err == nil {
			t.Fatal("want sysctl error")
		}
	})

	t.Run("cni_runner_error", func(t *testing.T) {
		ensureForwardingSysctls = func() error { return nil }
		bad := cfg
		bad.ContainerdCNIPluginDir = ""
		if _, err := wireContainerdNativeNetnsPool(context.Background(), bad, testLogger(), st, driver); err == nil {
			t.Fatal("want cni runner error")
		}
	})

	t.Run("reconcile_reaps_orphans", func(t *testing.T) {
		ensureForwardingSysctls = func() error { return nil }
		st2 := openDaemonTestStore(t)
		ctx := context.Background()
		now := time.Now().UTC()
		if err := netns.New(st2).Seed(ctx, netns.SeedConfig{PoolSize: 1}, now); err != nil {
			t.Fatal(err)
		}
		slot, err := st2.BeginPrewarmContainerNetnsSlot(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := st2.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/gone/netns", "10.0.0.9", now); err != nil {
			t.Fatal(err)
		}
		pool, err := wireContainerdNativeNetnsPool(ctx, cfg, testLogger(), st2, driver)
		if err != nil {
			t.Fatalf("wire: %v", err)
		}
		if pool == nil {
			t.Fatal("expected pool")
		}
		pool.Stop()
	})
}
