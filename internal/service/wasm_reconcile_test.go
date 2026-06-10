package service

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestReconcileWasmOfflineRowBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		sb := &models.Sandbox{
			ID:         "sb-disabled",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusStarted,
			Durability: models.DurabilityDurable,
		}
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if got := svc.reconcileWasmOfflineRow(ctx, sb); !got {
			t.Fatal("durable started row should be handled when wasm is disabled")
		}
		updated, err := st.Get(ctx, sb.ID)
		if err != nil {
			t.Fatalf("get sandbox: %v", err)
		}
		if updated.Status != models.SandboxStatusAwaitingRuntime {
			t.Fatalf("status = %s, want awaiting_runtime", updated.Status)
		}

		awaiting := &models.Sandbox{
			ID:         "sb-awaiting",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusAwaitingRuntime,
			Durability: models.DurabilityDurable,
		}
		if err := st.Create(ctx, awaiting); err != nil {
			t.Fatalf("seed awaiting: %v", err)
		}
		if got := svc.reconcileWasmOfflineRow(ctx, awaiting); !got {
			t.Fatal("awaiting_runtime row should be handled when wasm is disabled")
		}
	})

	t.Run("enabled", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true

		passivated := &models.Sandbox{
			ID:         "sb-passivated",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusPassivated,
			Durability: models.DurabilityEphemeral,
		}
		if err := st.Create(ctx, passivated); err != nil {
			t.Fatalf("seed passivated: %v", err)
		}
		if got := svc.reconcileWasmOfflineRow(ctx, passivated); !got {
			t.Fatal("passivated row should be handled")
		}

		passivateFailed := &models.Sandbox{
			ID:         "sb-passivate-failed",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusPassivateFailed,
			Durability: models.DurabilityEphemeral,
		}
		if err := st.Create(ctx, passivateFailed); err != nil {
			t.Fatalf("seed passivate_failed: %v", err)
		}
		if got := svc.reconcileWasmOfflineRow(ctx, passivateFailed); !got {
			t.Fatal("passivate_failed row should be handled when wasm is enabled")
		}

		started := &models.Sandbox{
			ID:         "sb-started",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusStarted,
			Durability: models.DurabilityEphemeral,
		}
		if err := st.Create(ctx, started); err != nil {
			t.Fatalf("seed started: %v", err)
		}
		if got := svc.reconcileWasmOfflineRow(ctx, started); !got {
			t.Fatal("ephemeral started row should be handled")
		}
		updated, err := st.Get(ctx, started.ID)
		if err != nil {
			t.Fatalf("get started: %v", err)
		}
		if updated.Status != models.SandboxStatusStopped {
			t.Fatalf("status = %s, want stopped", updated.Status)
		}

		ignored := &models.Sandbox{
			ID:         "sb-ignored",
			Runtime:    models.RuntimeWasm,
			Status:     models.SandboxStatusStarted,
			Durability: models.DurabilityDurable,
		}
		if got := svc.reconcileWasmOfflineRow(ctx, ignored); got {
			t.Fatal("durable started row should not be handled when wasm is enabled")
		}
	})

	t.Run("non-wasm", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		if got := svc.reconcileWasmOfflineRow(ctx, &models.Sandbox{Runtime: models.RuntimeDocker}); got {
			t.Fatal("non-wasm sandbox should not be handled")
		}
		if got := svc.reconcileWasmOfflineRow(ctx, nil); got {
			t.Fatal("nil sandbox should not be handled")
		}
	})
}
