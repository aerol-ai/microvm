package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
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
		mux := newMultiEventsSource(testLogger())
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- mux.StreamEvents(ctx, make(chan docker.DockerEvent)) }()
		cancel()
		if err := <-errCh; !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamEvents = %v, want context.Canceled", err)
		}
	})

	t.Run("single_source_nil_logger", func(t *testing.T) {
		src := &fakeEventsSource{prefix: "only", n: 1}
		mux := newMultiEventsSource(nil, src)
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
		mux := newMultiEventsSource(testLogger(), src)
		ctx, cancel := context.WithCancel(context.Background())
		out := make(chan docker.DockerEvent)
		go func() { _ = mux.StreamEvents(ctx, out) }()
		time.Sleep(10 * time.Millisecond)
		cancel()
	})

	t.Run("failing_source_does_not_stop_the_others", func(t *testing.T) {
		oldInitial, oldMax := eventSourceRetryInitial, eventSourceRetryMax
		eventSourceRetryInitial, eventSourceRetryMax = time.Millisecond, 4*time.Millisecond
		t.Cleanup(func() { eventSourceRetryInitial, eventSourceRetryMax = oldInitial, oldMax })

		// Docker on a host where dockerd is stopped or absent: every
		// subscribe fails at once. containerd keeps producing.
		boom := &boomEventsSource{}
		healthy := &tickEventsSource{prefix: "ctd", every: time.Millisecond}
		mux := newMultiEventsSource(testLogger(), boom, healthy)
		ctx, cancel := context.WithCancel(context.Background())
		out := make(chan docker.DockerEvent, 8)
		done := make(chan error, 1)
		go func() { done <- mux.StreamEvents(ctx, out) }()

		got := 0
		deadline := time.After(5 * time.Second)
		for got < 50 {
			select {
			case ev := <-out:
				if ev.SandboxID != "ctd" {
					t.Fatalf("event = %+v", ev)
				}
				got++
			case err := <-done:
				t.Fatalf("StreamEvents returned %v after %d events: one failing source ended the others (finding F12)", err, got)
			case <-deadline:
				t.Fatalf("only %d of 50 events from the healthy source", got)
			}
		}
		if calls := boom.calls.Load(); calls < 2 {
			t.Fatalf("the failing source was subscribed %d times; it must be retried on its own", calls)
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamEvents = %v after cancel, want context.Canceled", err)
		}
	})
}

func TestMultiEventsSourceRetriesAStreamThatDropsLater(t *testing.T) {
	oldInitial, oldMax := eventSourceRetryInitial, eventSourceRetryMax
	eventSourceRetryInitial, eventSourceRetryMax = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { eventSourceRetryInitial, eventSourceRetryMax = oldInitial, oldMax })

	// dockerd restarting on a VM: the stream stays up longer than the
	// longest wait, then drops. Each drop is followed by a new subscribe.
	flaky := &dropAfterEventsSource{after: 10 * time.Millisecond}
	mux := newMultiEventsSource(testLogger(), flaky, &tickEventsSource{prefix: "ctd", every: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan docker.DockerEvent, 64)
	done := make(chan error, 1)
	go func() { done <- mux.StreamEvents(ctx, out) }()
	go func() {
		for range out {
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for flaky.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamEvents = %v, want context.Canceled", err)
	}
	if calls := flaky.calls.Load(); calls < 3 {
		t.Fatalf("a stream that dropped was subscribed %d times, want it retried after each drop", calls)
	}
}

// dropAfterEventsSource stays subscribed for `after`, then fails.
type dropAfterEventsSource struct {
	after time.Duration
	calls atomic.Int32
}

func (s *dropAfterEventsSource) StreamEvents(ctx context.Context, _ chan<- docker.DockerEvent) error {
	s.calls.Add(1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.after):
		return errors.New("dockerd went away")
	}
}

func (s *dropAfterEventsSource) ContainerPID(context.Context, string) (int, error) { return 0, nil }

type boomEventsSource struct{ calls atomic.Int32 }

func (b *boomEventsSource) StreamEvents(context.Context, chan<- docker.DockerEvent) error {
	b.calls.Add(1)
	return errors.New("stream boom")
}

// tickEventsSource sends one event every `every` until ctx ends: a stream
// that stays up.
type tickEventsSource struct {
	prefix string
	every  time.Duration
}

func (s *tickEventsSource) StreamEvents(ctx context.Context, out chan<- docker.DockerEvent) error {
	t := time.NewTicker(s.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			select {
			case out <- docker.DockerEvent{SandboxID: s.prefix, Action: "die"}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (s *tickEventsSource) ContainerPID(context.Context, string) (int, error) { return 0, nil }

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
