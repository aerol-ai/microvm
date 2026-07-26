package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFlagSandboxAutoImportPending(t *testing.T) {
	logger := testLogger()
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-ai", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	flagSandboxAutoImportPending(st, logger, "sb-ai")
	got, err := st.Get(context.Background(), "sb-ai")
	if err != nil {
		t.Fatal(err)
	}
	if !got.AutoImportPending {
		t.Fatal("expected AutoImportPending set")
	}

	_ = st.Close()
	flagSandboxAutoImportPending(st, logger, "sb-ai") // warn path
}

func TestTemplateRotationRunOnceErrorPath(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	runCtx, cancel := context.WithCancel(context.Background())
	startTemplateRotationReconciler(runCtx, testLogger(), config.Config{
		EnableFirecracker:                   true,
		FirecrackerTemplateRotationInterval: 5 * time.Millisecond,
		FirecrackerTemplateMaxAge:           time.Hour,
	}, st, svc)
	time.Sleep(20 * time.Millisecond)
	_ = st.Close() // force RunOnce store errors
	time.Sleep(40 * time.Millisecond)
	cancel()
}

func TestDrainContainerdWarmPoolNilLoggerWithSlots(t *testing.T) {
	drainContainerdWarmPool(poolWithLoadedSlot(t), nil)
}
