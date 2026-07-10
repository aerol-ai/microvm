package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The docker create path must attribute its persist tail (store writes +
// response re-read) as a Server-Timing stage so operators can separate
// container-boot time from bookkeeping time.
func TestCreateSandboxRecordsPersistStage(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})

	ctx, timing := createtiming.With(context.Background())
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 256,
		DiskGB:   5,
	})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if resp == nil || resp.Sandbox.ID == "" {
		t.Fatal("CreateSandbox returned nil or empty sandbox")
	}

	found := false
	for _, st := range timing.Stages() {
		if st.Name == "svc_persist" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stages = %+v, want svc_persist recorded", timing.Stages())
	}
}

// The pending-image-GC refresh is deferred off the response path but must
// still land: a create for an image with a pending GC row eventually pushes
// its deadline forward.
func TestCreateSandboxRefreshesPendingImageGCAsync(t *testing.T) {
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	svc.cfg.ImageBuildGCEnabled = true

	ctx := context.Background()
	staleAt := time.Now().Add(-24 * time.Hour).UTC()
	if err := st.SchedulePendingImageGC(ctx, "alpine:3.20", staleAt); err != nil {
		t.Fatalf("seed pending gc: %v", err)
	}

	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 256,
		DiskGB:   5,
	}); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		due, err := st.ListPendingImageGCDue(ctx, staleAt.Add(time.Minute), 10)
		if err != nil {
			t.Fatalf("list pending gc: %v", err)
		}
		// The stale row is refreshed once its scheduled_at moves past the
		// seeded timestamp — it stops showing up as due at the old cutoff.
		if len(due) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("pending image GC row was not refreshed by the deferred create-path update")
}
