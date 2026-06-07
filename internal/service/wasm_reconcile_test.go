package service

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestReconcileWasmOfflineRowAwaitingRuntimeWhenDisabled(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := New(config.Config{EnableWasm: false}, nil, st, nil, nil, nil, nil, nil, nil)
	sb := &models.Sandbox{
		ID:         "sb-wasm-offline",
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		Status:     models.SandboxStatusPassivated,
	}
	if !svc.reconcileWasmOfflineRow(ctx, sb) {
		t.Fatal("expected passivated durable wasm row to be held when wasm disabled")
	}

	sb.Status = models.SandboxStatusAwaitingRuntime
	if !svc.reconcileWasmOfflineRow(ctx, sb) {
		t.Fatal("expected awaiting_runtime row to be held when wasm disabled")
	}
}

func TestReconcileWasmOfflineRowEphemeralLostOnRestart(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := New(config.Config{EnableWasm: true}, nil, st, nil, nil, nil, nil, nil, nil)
	sb := &models.Sandbox{
		ID:         "sb-wasm-ephemeral",
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityEphemeral,
		Status:     models.SandboxStatusStarted,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !svc.reconcileWasmOfflineRow(ctx, sb) {
		t.Fatal("expected ephemeral wasm offline row to be handled")
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("status = %q, want stopped", got.Status)
	}
}

func TestReconcileWasmOfflineRowPassivatedWhenEnabled(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := New(config.Config{EnableWasm: true}, nil, st, nil, nil, nil, nil, nil, nil)
	sb := &models.Sandbox{
		ID:         "sb-wasm-passivated",
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityPassivatable,
		Status:     models.SandboxStatusPassivated,
	}
	if !svc.reconcileWasmOfflineRow(ctx, sb) {
		t.Fatal("expected passivated wasm row to be held when wasm enabled")
	}
}
