package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage95LiftSnapshotPushBuildFailures(t *testing.T) {
	logger := testLogger()
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Nil docker fails pusher construction so the feature stays off.
	startSnapshotPushReconciler(ctx, logger, config.Config{
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      filepath.Join(t.TempDir(), "missing.pat"),
		SnapshotPushReconcileInterval: time.Hour,
	}, nil, svc, nil, nil)

	// Valid PAT + docker, but wasm checkpoint pusher can still fail independently.
	pat := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(pat, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	startSnapshotPushReconciler(ctx, logger, config.Config{
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      pat,
		SnapshotPushReconcileInterval: time.Hour,
	}, nil, svc, newTestDockerClient(t), nil)

	if p := wireDockerWarmPool(ctx, config.Config{DockerPoolEnabled: true, DockerReadySocketEnabled: false}, logger, nil, nil); p != nil {
		t.Fatal("pool should stay off when ready sockets are disabled")
	}

	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_WASM_COMPILE_CACHE_DIR", blocked)
	wireWasmRuntime(ctx, config.Config{
		WasmCompileCacheDir: blocked,
		WasmModulesDir:      t.TempDir(),
		WasmRunDir:          t.TempDir(),
	}, logger, svc, nil)

	// Enabled manager + failing bootstrap backend exercises the re-assert
	// warn path without needing Linux iptables.
	prevInterval := chainReassertInterval
	chainReassertInterval = 5 * time.Millisecond
	t.Cleanup(func() { chainReassertInterval = prevInterval })
	reassertCtx, reassertCancel := context.WithCancel(context.Background())
	t.Cleanup(reassertCancel)
	stop := startChainReassert(reassertCtx, netrules.NewWithBackend(failReassertBackend{}), logger)
	t.Cleanup(stop)
	time.Sleep(20 * time.Millisecond)
}

type failReassertBackend struct{}

func (failReassertBackend) Exists(string, string, ...string) (bool, error) { return false, nil }

func (failReassertBackend) Insert(string, string, int, ...string) error { return nil }

func (failReassertBackend) Delete(string, string, ...string) error { return nil }

func (failReassertBackend) EnsureUserChain(string) error {
	return errors.New("reassert boom")
}

func (failReassertBackend) EnsureForwardJump(string) error { return nil }

func TestCoverage95ContainerEngineWiringBranches(t *testing.T) {
	st := openDaemonTestStore(t)
	svc := &service.Service{}
	logger := testLogger()

	t.Run("netrules_backend_error", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("netrules backend validation requires linux")
		}
		_, err := wireContainerEngine(context.Background(), config.Config{
			ContainerEngine:    models.ContainerEngineContainerd,
			EnableNetworkRules: true,
			NetrulesBackend:    "bogus-backend",
		}, logger, svc, st, nil, nil, nil)
		if err == nil {
			t.Fatal("want netrules error")
		}
	})

	t.Run("netns_wire_error", func(t *testing.T) {
		orig := ensureForwardingSysctls
		ensureForwardingSysctls = func() error { return errors.New("sysctl") }
		t.Cleanup(func() { ensureForwardingSysctls = orig })
		_, err := wireContainerEngine(context.Background(), config.Config{
			ContainerEngine:                  models.ContainerEngineContainerd,
			EnableNetworkRules:               false,
			NetrulesBackend:                  "exec",
			ContainerdNativeNetnsPoolEnabled: true,
			ContainerdNetnsPoolSize:          1,
		}, logger, svc, st, nil, nil, nil)
		if err == nil {
			t.Fatal("want netns wire error")
		}
	})

	t.Run("with_docker_client_multi_events", func(t *testing.T) {
		dc := newTestDockerClient(t)
		w, err := wireContainerEngine(context.Background(), config.Config{
			ContainerEngine:                  models.ContainerEngineContainerd,
			EnableNetworkRules:               false,
			NetrulesBackend:                  "exec",
			ContainerdNativeNetnsPoolEnabled: false,
			ContainerdPoolEnabled:            false,
		}, logger, svc, st, dc, nil, nil)
		if err != nil {
			t.Fatalf("wireContainerEngine: %v", err)
		}
		if w == nil {
			t.Fatal("expected wiring")
		}
		w.Stop()
	})

	t.Run("chain_reassert_tick", func(t *testing.T) {
		old := chainReassertInterval
		chainReassertInterval = 5 * time.Millisecond
		t.Cleanup(func() { chainReassertInterval = old })

		mgr, err := netrules.NewWithOptions(false, netrules.BackendExec, netrules.ChainAerolvmUser)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stop := startChainReassert(ctx, mgr, logger)
		time.Sleep(20 * time.Millisecond)
		stop()
		cancel()
	})
}

func TestCoverage95MultiEventsSourceEdgeCases(t *testing.T) {
	t.Run("empty_sources", func(t *testing.T) {
		mux := newMultiEventsSource()
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- mux.StreamEvents(ctx, make(chan docker.DockerEvent)) }()
		cancel()
		if err := <-errCh; !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamEvents = %v, want context.Canceled", err)
		}
	})

	t.Run("single_source", func(t *testing.T) {
		src := &fakeEventsSource{prefix: "only", n: 1}
		mux := newMultiEventsSource(src)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out := make(chan docker.DockerEvent, 1)
		go func() { _ = mux.StreamEvents(ctx, out) }()
		select {
		case ev := <-out:
			if ev.SandboxID != "only" {
				t.Fatalf("event = %+v", ev)
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for event")
		}
	})

	t.Run("cancel_during_forward", func(t *testing.T) {
		src := &fakeEventsSource{prefix: "slow", n: 100}
		mux := newMultiEventsSource(src)
		ctx, cancel := context.WithCancel(context.Background())
		out := make(chan docker.DockerEvent)
		go func() { _ = mux.StreamEvents(ctx, out) }()
		time.Sleep(10 * time.Millisecond)
		cancel()
	})

	t.Run("first_source_error_cancels_mux", func(t *testing.T) {
		mux := newMultiEventsSource(&fakeEventsSource{prefix: "a", n: 5}, &boomEventsSource{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out := make(chan docker.DockerEvent, 8)
		if err := mux.StreamEvents(ctx, out); err == nil {
			t.Fatal("expected stream error")
		}
	})
}

type boomEventsSource struct{}

func (b *boomEventsSource) StreamEvents(context.Context, chan<- docker.DockerEvent) error {
	return errors.New("stream boom")
}

func (b *boomEventsSource) ContainerPID(context.Context, string) (int, error) {
	return 0, nil
}

func TestCoverage95WireContainerEngineUnknownNetrulesBackend(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("enabled netrules backends are linux-only")
	}
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	_, err := wireContainerEngine(context.Background(), config.Config{
		ContainerEngine:    models.ContainerEngineContainerd,
		EnableNetworkRules: true,
		NetrulesBackend:    "not-a-backend",
	}, testLogger(), svc, st, nil, nil, nil)
	if err == nil {
		t.Fatal("want unknown netrules backend error")
	}
}
