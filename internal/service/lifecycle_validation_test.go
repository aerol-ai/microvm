package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestValidateLifecycleUsesBypassFloor(t *testing.T) {
	lifecycle := models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}
	svc := &Service{cfg: config.Config{
		NetstatsPollInterval: time.Minute,
		ReconcileInterval:    time.Minute,
	}}

	if err := svc.validateLifecycle(lifecycle); err != nil {
		t.Fatalf("validateLifecycle without bypass = %v, want nil", err)
	}
	svc.cfg.L4WakeDirectBypassEnabled = true
	err := svc.validateLifecycle(lifecycle)
	if err == nil || !strings.Contains(err.Error(), "direct-route bypass") {
		t.Fatalf("validateLifecycle with bypass = %v, want floor error", err)
	}
}

func TestCreateAndUpdateLifecycleRejectBypassSubFloor(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.NetstatsPollInterval = time.Minute
	svc.cfg.ReconcileInterval = time.Minute

	lifecycle := models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}
	_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:     "alpine:3.20",
		Lifecycle: &lifecycle,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid lifecycle") {
		t.Fatalf("CreateSandbox error = %v, want invalid lifecycle", err)
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-lifecycle-floor",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStopped,
		Runtime:      models.RuntimeDocker,
		CPU:          1,
		MemoryMB:     256,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	_, err = svc.UpdateLifecycle(ctx, "sb-lifecycle-floor", lifecycle)
	if err == nil || !strings.Contains(err.Error(), "invalid lifecycle") {
		t.Fatalf("UpdateLifecycle error = %v, want invalid lifecycle", err)
	}
	if _, err := st.Get(ctx, "sb-lifecycle-floor"); errors.Is(err, store.ErrNotFound) {
		t.Fatal("UpdateLifecycle should not delete the sandbox")
	}
}
