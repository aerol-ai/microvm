package service

import (
	"context"
	"testing"
	"time"

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
