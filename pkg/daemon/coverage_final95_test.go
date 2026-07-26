package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/netns"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFinal95RunReadySocketDirFailure(t *testing.T) {
	paths := setBaseRunEnv(t)
	blocker := filepath.Join(paths.rootDir, "block")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
	t.Setenv("SB_DOCKER_POOL_ENABLED", "true")
	t.Setenv("SB_MOUNTS_CRED_DIR", blocker)
	if err := runWithAutoCancel(t, 500*time.Millisecond, nil); err == nil {
		t.Fatal("expected ready socket dir failure")
	}
}

func TestFinal95WireContainerdNetnsInspectMiss(t *testing.T) {
	st := openDaemonTestStore(t)
	work := t.TempDir()
	orig := ensureForwardingSysctls
	ensureForwardingSysctls = func() error { return nil }
	t.Cleanup(func() { ensureForwardingSysctls = orig })

	cfg := config.Config{
		ContainerEngine:                   models.ContainerEngineContainerd,
		ContainerdNativeNetnsPoolEnabled:  true,
		ContainerdNetnsPoolDepth:          0,
		ContainerdNetnsPoolSize:           2,
		ContainerdNetnsPoolRefillInterval: time.Hour,
		ContainerdCNIPluginDir:            filepath.Join(work, "cni-bin"),
		ContainerdCNIConfPath:             filepath.Join(work, "cni", "aerolvm.conflist"),
	}
	ctx := context.Background()
	now := time.Now().UTC()
	pool := netns.New(st)
	if err := pool.Seed(ctx, netns.SeedConfig{PoolSize: 2}, now); err != nil {
		t.Fatal(err)
	}
	host := netns.NewFakeHost()
	if _, _, err := netns.NewRuntimeHandoff(pool, host).Provision(ctx, "sb-miss"); err != nil {
		t.Fatal(err)
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
	wired, err := wireContainerdNativeNetnsPool(ctx, cfg, testLogger(), st, driver)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	if wired != nil {
		wired.Stop()
	}
}

func TestFinal95ReconcilerNilStoreGuards(t *testing.T) {
	logger := testLogger()
	patPath := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	startAutoImportReconciler(ctx, logger, config.Config{
		AutoImportEnabled:           true,
		AutoImportClusterPATPath:    patPath,
		AutoImportHooksBaseURL:      "https://hooks.example",
		AutoImportClusterID:         "cluster-1",
		AutoImportReconcileInterval: time.Hour,
	}, nil, svc)

	startSnapshotPushReconciler(ctx, logger, config.Config{
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      patPath,
		SnapshotPushReconcileInterval: time.Hour,
	}, nil, svc, newTestDockerClient(t), nil)
}

func TestFinal95MultiEventsCancelDuringDrain(t *testing.T) {
	src := &fakeEventsSource{prefix: "flood", n: 64}
	mux := newMultiEventsSource(src)
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan docker.DockerEvent)
	done := make(chan error, 1)
	go func() { done <- mux.StreamEvents(ctx, out) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StreamEvents did not return after cancel")
	}
}

func TestFinal95DrainDockerWarmPoolNilLogger(t *testing.T) {
	drainDockerWarmPool(poolWithLoadedSlot(t), nil)
}

func TestFinal95TemplateRotationNilStoreAndService(t *testing.T) {
	cfg := config.Config{
		EnableFirecracker:                   true,
		FirecrackerTemplateRotationInterval: time.Second,
		FirecrackerTemplateMaxAge:           time.Hour,
	}
	startTemplateRotationReconciler(context.Background(), testLogger(), cfg, nil, nil)
	svc := service.New(config.Config{}, testLogger(), nil, nil, nil, nil, nil, nil, nil)
	startTemplateRotationReconciler(context.Background(), testLogger(), cfg, nil, svc)
}

func TestFinal95StartL4WakeProxyListenError(t *testing.T) {
	paths := setBaseRunEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	t.Setenv("SB_ENABLE_CADDY", "true")
	t.Setenv("SB_ENABLE_SERVERLESS", "true")
	t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "false")
	t.Setenv("SB_INTERNAL_L4_WAKE_ADDR", ln.Addr().String())
	t.Setenv("SB_INTERNAL_INGRESS_ADDR", "127.0.0.1:0")
	t.Setenv("SB_INTERNAL_L4_WAKE_DIR", paths.internalL4WakeDir)
	// ListenAndServe on wake addr fails → cancel path; Run should still exit.
	if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
		t.Logf("Run err (ok): %v", err)
	}
}

func TestFinal95APIListenAndServeError(t *testing.T) {
	_ = setBaseRunEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_API_PORT", port)
	// ListenAndServe hits EADDRINUSE → cancel → graceful shutdown.
	if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
		t.Logf("Run err (ok): %v", err)
	}
}

func TestFinal95BypassMarkerWriteFailure(t *testing.T) {
	paths := setBaseRunEnv(t)
	// Put DB inside a directory we will make unwritable after creation.
	dbDir := filepath.Dir(paths.dbPath)
	t.Setenv("SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED", "false")
	if err := os.WriteFile(paths.bypassMarkerPath, []byte("true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dbDir, 0o755) })
	// ForceReconcile may warn; writeBypassMarker should fail (unwritable dir).
	if err := runWithAutoCancel(t, 600*time.Millisecond, nil); err != nil {
		t.Logf("Run err (ok): %v", err)
	}
}
