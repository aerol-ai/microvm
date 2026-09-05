package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type fakeCheckpointRuntime struct {
	wasmRecordingRuntime
	checkpointErr       error
	checkpointPath      string
	cloneGen            string
	checkpointCalls     int
	liveCheckpointErr   error
	liveCheckpointCalls int
}

func (f *fakeCheckpointRuntime) CheckpointSandbox(_ context.Context, sandbox *models.Sandbox) (string, string, error) {
	f.checkpointCalls++
	return f.checkpointPath, f.cloneGen, f.checkpointErr
}

func (f *fakeCheckpointRuntime) RehydrateSandbox(_ context.Context, sandbox *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return &models.SandboxRuntimeState{
		SandboxID: sandbox.ID,
		Status:    models.SandboxStatusStarted,
	}, nil
}

func (f *fakeCheckpointRuntime) CheckpointLiveSandbox(_ context.Context, sandbox *models.Sandbox) (string, string, error) {
	f.liveCheckpointCalls++
	return f.checkpointPath, f.cloneGen, f.liveCheckpointErr
}

type fakeCheckpointDrainRuntime struct {
	fakeCheckpointRuntime
	listManagedErr error
}

func (f *fakeCheckpointDrainRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	if f.listManagedErr != nil {
		return nil, f.listManagedErr
	}
	return f.fakeCheckpointRuntime.ListManaged(context.Background())
}

func TestRunWasmCheckpointPoolReturnsCancellationAfterInFlightWork(t *testing.T) {
	svc := &Service{cfg: config.Config{WasmCheckpointMaxParallel: 1}}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)

	go func() {
		result <- svc.runWasmCheckpointPool(ctx, []*models.Sandbox{{ID: "sb-1"}}, func(*models.Sandbox) error {
			close(started)
			<-release
			return nil
		})
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("checkpoint worker did not start")
	}
	cancel()
	close(release)

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runWasmCheckpointPool = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("checkpoint pool did not return after cancellation")
	}
}

func TestDrainWasmSandboxes(t *testing.T) {
	ctx := context.Background()
	rt := &fakeCheckpointRuntime{
		checkpointPath: "/tmp/checkpoint",
		cloneGen:       "gen-1",
		wasmRecordingRuntime: wasmRecordingRuntime{
			managed: map[string]*models.SandboxRuntimeState{
				"sb-live": {SandboxID: "sb-live"},
			},
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)

	now := time.Now().UTC()
	// Insert eligible sandbox
	err := st.Create(ctx, &models.Sandbox{
		ID:         "sb-live",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityPassivatable,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}
	// Insert ineligible sandbox (not managed)
	err = st.Create(ctx, &models.Sandbox{
		ID:         "sb-dead",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityPassivatable,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}

	if err := svc.DrainWasmSandboxes(ctx); err != nil {
		t.Fatalf("DrainWasmSandboxes failed: %v", err)
	}

	managed, _ := rt.ListManaged(ctx)
	t.Logf("managed: %v", managed)
	known, _ := st.List(ctx)
	for _, sb := range known {
		t.Logf("known: %s (status=%s, dur=%s, rt=%s)", sb.ID, sb.Status, sb.Durability, sb.Runtime)
	}

	if rt.checkpointCalls != 1 {
		t.Fatalf("Expected 1 checkpoint call, got %d", rt.checkpointCalls)
	}

	got, err := st.Get(ctx, "sb-live")
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if got.Status != models.SandboxStatusPassivated {
		t.Fatalf("Expected status passivated, got %s", got.Status)
	}
}

func TestCheckpointLiveWasmSandbox(t *testing.T) {
	ctx := context.Background()
	rt := &fakeCheckpointRuntime{
		checkpointPath: "/tmp/checkpoint",
		cloneGen:       "gen-2",
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:         "sb-live-cp",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityPassivatable,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	err := st.Create(ctx, sandbox)
	if err != nil {
		t.Fatalf("Create sandbox failed: %v", err)
	}

	if err := svc.checkpointLiveWasmSandbox(ctx, rt, sandbox); err != nil {
		t.Fatalf("checkpointLiveWasmSandbox failed: %v", err)
	}

	if rt.liveCheckpointCalls != 1 {
		t.Fatalf("Expected 1 live checkpoint call, got %d", rt.liveCheckpointCalls)
	}

	got, err := st.Get(ctx, "sb-live-cp")
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("Expected status started, got %s", got.Status)
	}
	if got.CheckpointPath != "/tmp/checkpoint" {
		t.Fatalf("Expected checkpoint path /tmp/checkpoint, got %s", got.CheckpointPath)
	}
}

func TestStartWasmPeriodicCheckpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.WasmCheckpointInterval = time.Millisecond * 10
	svc.SetWasmRuntime(&fakeCheckpointRuntime{})

	svc.StartWasmPeriodicCheckpoint(ctx)
	time.Sleep(time.Millisecond * 30) // allow ticker to fire
}

func TestStartWasmDurablePushSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.WasmDurablePushInterval = time.Millisecond * 10
	svc.wasmCheckpointPusher = &wasmCheckpointPusherStub{}

	now := time.Now().UTC()
	st.Create(ctx, &models.Sandbox{
		ID:         "sb-durable",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusPassivated,
		Durability: models.DurabilityDurable,
		CreatedAt:  now,
		UpdatedAt:  now,
	})

	svc.StartWasmDurablePushSweep(ctx)
	time.Sleep(time.Millisecond * 30) // allow ticker to fire
}

func TestDrainWasmSandboxesEdgeBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("disabled or missing host are no-op", func(t *testing.T) {
		var svc *Service
		svc = &Service{}
		if err := svc.DrainWasmSandboxes(ctx); err != nil {
			t.Fatalf("empty service should no-op: %v", err)
		}

		svc = &Service{cfg: config.Config{EnableWasm: false}, wasm: &fakeCheckpointRuntime{}}
		if err := svc.DrainWasmSandboxes(ctx); err != nil {
			t.Fatalf("disabled service should no-op: %v", err)
		}

		svc = &Service{cfg: config.Config{EnableWasm: true}, wasm: wasmModuleAPINoopRuntime{}}
		if err := svc.DrainWasmSandboxes(ctx); err != nil {
			t.Fatalf("runtime without checkpoint host should no-op: %v", err)
		}
	})

	t.Run("store list error", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&fakeCheckpointRuntime{})
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		if err := svc.DrainWasmSandboxes(ctx); err == nil {
			t.Fatal("closed store should fail DrainWasmSandboxes")
		}
	})

	t.Run("runtime list managed error", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		rt := &fakeCheckpointDrainRuntime{
			fakeCheckpointRuntime: fakeCheckpointRuntime{
				wasmRecordingRuntime: wasmRecordingRuntime{
					managed: map[string]*models.SandboxRuntimeState{},
				},
			},
			listManagedErr: errors.New("managed list failed"),
		}
		svc.SetWasmRuntime(rt)
		if err := st.Create(ctx, &models.Sandbox{
			ID:         "sb-live",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusStarted,
			Durability: models.DurabilityPassivatable,
			CreatedAt:  time.Now().UTC(),
			UpdatedAt:  time.Now().UTC(),
		}); err != nil {
			t.Fatalf("Create sandbox: %v", err)
		}
		if err := svc.DrainWasmSandboxes(ctx); err == nil {
			t.Fatal("managed list failure should fail DrainWasmSandboxes")
		}
	})
}

func TestWasmShouldCheckpoint(t *testing.T) {
	cases := []struct {
		durability string
		want       bool
	}{
		{models.DurabilityPassivatable, true},
		{models.DurabilityDurable, true},
		{"", false},
		{"transient", false},
	}
	for _, tc := range cases {
		if got := wasmShouldCheckpoint(tc.durability); got != tc.want {
			t.Fatalf("wasmShouldCheckpoint(%q) = %v, want %v", tc.durability, got, tc.want)
		}
	}
}

type wasmCheckpointPusherStub struct{}

func (s *wasmCheckpointPusherStub) DestRefFor(sandboxID string) string { return "test://sb" }
func (s *wasmCheckpointPusherStub) DestRefTagged(sandboxID, tag string) string {
	return "test://sb:" + tag
}
func (s *wasmCheckpointPusherStub) PushOnceTo(ctx context.Context, sandboxID, memSnapDir, destRef string) (WasmCheckpointPushResult, error) {
	return WasmCheckpointPushResult{RegistryRef: destRef, Digest: "sha256:123"}, nil
}
func (s *wasmCheckpointPusherStub) PullOnce(ctx context.Context, registryRef, destDir string) error {
	return nil
}
func (s *wasmCheckpointPusherStub) DeleteRef(ctx context.Context, registryRef string) error {
	return nil
}

type failingWasmCheckpointPusher struct{}

func (f failingWasmCheckpointPusher) DestRefFor(string) string { return "test://checkpoint" }
func (f failingWasmCheckpointPusher) DestRefTagged(sandboxID, tag string) string {
	return "test://" + sandboxID + ":" + tag
}
func (f failingWasmCheckpointPusher) PushOnceTo(context.Context, string, string, string) (WasmCheckpointPushResult, error) {
	return WasmCheckpointPushResult{}, errors.New("push failed")
}
func (f failingWasmCheckpointPusher) PullOnce(context.Context, string, string) error { return nil }
func (f failingWasmCheckpointPusher) DeleteRef(context.Context, string) error        { return nil }

func TestWasmCheckpointPushAndPruneBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.WasmCheckpointKeepLastN = 1
	svc.wasmCheckpointPusher = failingWasmCheckpointPusher{}
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:              "sb-wasm-push",
		Runtime:         models.RuntimeWasm,
		Status:          models.SandboxStatusPassivated,
		Durability:      models.DurabilityDurable,
		CheckpointPath:  "/tmp/checkpoint",
		CloneGeneration: "gen-1",
		WasmRegistryRef: "",
		CreatedAt:       now,
		UpdatedAt:       now,
		LastActiveAt:    now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	// pushWasmCheckpointBestEffort should swallow the push error and return.
	svc.pushWasmCheckpointBestEffort("sb-wasm-push", "/tmp/checkpoint")

	// Reopen a fresh store so we can exercise the success/prune path.
	svc2, st2, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.EnableWasm = true
	svc2.cfg.WasmCheckpointKeepLastN = 1
	pusher := &recordingCheckpointStore{destRef: "test://sb-wasm-push:latest"}
	svc2.wasmCheckpointPusher = pusher
	if err := st2.Create(ctx, &models.Sandbox{
		ID:              "sb-wasm-push",
		Runtime:         models.RuntimeWasm,
		Status:          models.SandboxStatusPassivated,
		Durability:      models.DurabilityDurable,
		CheckpointPath:  "/tmp/checkpoint",
		CloneGeneration: "gen-1",
		CreatedAt:       now,
		UpdatedAt:       now,
		LastActiveAt:    now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	svc2.pushWasmCheckpointBestEffort("sb-wasm-push", "/tmp/checkpoint")
	svc2.pushWasmCheckpointBestEffort("sb-wasm-push", "/tmp/checkpoint")
	if len(pusher.deleteCalls) == 0 {
		t.Fatal("expected prune to delete an older checkpoint ref")
	}

	if err := st2.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}
	svc2.pruneWasmCheckpointPushes(ctx, "sb-wasm-push")
}
