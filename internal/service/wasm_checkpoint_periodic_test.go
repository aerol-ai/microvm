package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeLiveCheckpointRuntime struct {
	wasmModuleAPINoopRuntime
	live  map[string]*models.SandboxRuntimeState
	calls int
}

func (f *fakeLiveCheckpointRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return f.live, nil
}

func (f *fakeLiveCheckpointRuntime) CheckpointLiveSandbox(_ context.Context, sandbox *models.Sandbox) (string, string, error) {
	f.calls++
	return "/tmp/" + sandbox.ID + "/mem.snap", "gen-live", nil
}

func TestRunWasmPeriodicCheckpointKeepsSandboxStarted(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:         "sb-live",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityDurable,
		ModuleRef:  "demo.wasm",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	rt := &fakeLiveCheckpointRuntime{
		live: map[string]*models.SandboxRuntimeState{
			"sb-live": {SandboxID: "sb-live", Status: models.SandboxStatusStarted},
		},
	}
	svc := &Service{
		cfg:    config.Config{EnableWasm: true, WasmCheckpointMaxParallel: 1},
		store:  st,
		wasm:   rt,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := svc.runWasmPeriodicCheckpoint(ctx); err != nil {
		t.Fatalf("runWasmPeriodicCheckpoint: %v", err)
	}
	if rt.calls != 1 {
		t.Fatalf("live checkpoint calls = %d, want 1", rt.calls)
	}
	got, err := st.Get(ctx, "sb-live")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q, want started", got.Status)
	}
	if got.CheckpointPath != "/tmp/sb-live/mem.snap" {
		t.Fatalf("checkpoint_path = %q", got.CheckpointPath)
	}
	if got.CloneGeneration != "gen-live" {
		t.Fatalf("clone_generation = %q", got.CloneGeneration)
	}
}

func TestWasmPeriodicCheckpointEdgeBranches(t *testing.T) {
	ctx := context.Background()

	var nilSvc *Service
	nilSvc.StartWasmPeriodicCheckpoint(ctx)
	nilSvc.StartWasmDurablePushSweep(ctx)

	svc := &Service{cfg: config.Config{EnableWasm: false, WasmCheckpointInterval: time.Millisecond, WasmDurablePushInterval: time.Millisecond}, wasm: &recordingRuntime{}}
	svc.StartWasmPeriodicCheckpoint(ctx)
	svc.StartWasmDurablePushSweep(ctx)

	svc = &Service{cfg: config.Config{EnableWasm: true, WasmCheckpointInterval: 0, WasmDurablePushInterval: 0}, wasm: &recordingRuntime{}}
	svc.StartWasmPeriodicCheckpoint(ctx)
	svc.StartWasmDurablePushSweep(ctx)
}

func TestRunWasmPeriodicCheckpointNonLiveHostIsNoop(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&recordingRuntime{})
	if err := st.Create(ctx, &models.Sandbox{
		ID:         "sb-non-live",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityDurable,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := svc.runWasmPeriodicCheckpoint(ctx); err != nil {
		t.Fatalf("runWasmPeriodicCheckpoint non-live host: %v", err)
	}
}

func TestWasmPeriodicAndDurableSweepErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("periodic checkpoint list errors", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&fakeCheckpointRuntime{})
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		if err := svc.runWasmPeriodicCheckpoint(ctx); err == nil {
			t.Fatal("runWasmPeriodicCheckpoint should fail when the store is closed")
		}
	})

	t.Run("periodic checkpoint managed list error", func(t *testing.T) {
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
			ID:         "sb-periodic",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusStarted,
			Durability: models.DurabilityPassivatable,
			CreatedAt:  time.Now().UTC(),
			UpdatedAt:  time.Now().UTC(),
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if err := svc.runWasmPeriodicCheckpoint(ctx); err == nil {
			t.Fatal("runWasmPeriodicCheckpoint should fail when ListManaged fails")
		}
	})

	t.Run("durable push sweep list error", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.wasmCheckpointPusher = &recordingCheckpointStore{}
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc.runWasmDurablePushSweep(ctx)
	})
}
