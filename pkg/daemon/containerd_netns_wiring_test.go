package daemon

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
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

func openDaemonTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
