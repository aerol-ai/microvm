package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// sizedRuntime is a container engine that reports each container's writable
// layer size.
type sizedRuntime struct {
	*recordingRuntime
	sizes map[string]int64
	err   error
}

func (r *sizedRuntime) WritableLayerBytes(_ context.Context, ref string) (int64, error) {
	if r.err != nil {
		return 0, r.err
	}
	return r.sizes[ref], nil
}

// TestDiskLimitWatchStopsSandboxesOverTheirDisk: a container sandbox that has
// written past its DiskGB is stopped, with a last error that says why and is
// never armed for wake; one within its size, a Firecracker sandbox and one
// whose size cannot be read are left alone.
func TestDiskLimitWatchStopsSandboxesOverTheirDisk(t *testing.T) {
	ctx := context.Background()
	rt := &sizedRuntime{recordingRuntime: &recordingRuntime{}, sizes: map[string]int64{
		"ctr-over":  3 << 30,       // 3 GiB in a 2 GiB sandbox
		"ctr-under": 2 << 30,       // exactly at its size: within the slack
		"ctr-fc":    50 << 30,      // a Firecracker disk is a fixed image
		"ctr-slack": 2*(1<<30) + 1, // a byte over, still inside the slack
	}}
	svc, st, _ := newServiceRuntimeHarness(t, rt.recordingRuntime)
	svc.docker = rt
	now := time.Now().UTC()
	seed := func(id, ctr, runtime string) {
		t.Helper()
		if err := st.Create(ctx, &models.Sandbox{
			ID: id, Image: "alpine", Status: models.SandboxStatusStarted, Runtime: runtime,
			CPU: 1, MemoryMB: 512, DiskGB: 2, ContainerID: ctr, ContainerIP: "10.0.0.9",
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed("sb-over", "ctr-over", models.RuntimeDocker)
	seed("sb-under", "ctr-under", models.RuntimeDocker)
	seed("sb-slack", "ctr-slack", models.RuntimeDocker)
	seed("sb-fc", "ctr-fc", models.RuntimeFirecracker)
	before := diskLimitStops.Value()
	svc.runDiskLimitWatch(ctx)
	got, _ := st.Get(ctx, "sb-over")
	if got.Status != models.SandboxStatusStopped || !strings.Contains(got.LastError, "over its 2 GiB") || got.WakeArmed {
		t.Fatalf("over its disk: status %q, error %q, wake %v", got.Status, got.LastError, got.WakeArmed)
	}
	for _, id := range []string{"sb-under", "sb-slack", "sb-fc"} {
		if s, _ := st.Get(ctx, id); s.Status != models.SandboxStatusStarted {
			t.Fatalf("%s was stopped: %q", id, s.LastError)
		}
	}
	if diskLimitStops.Value() != before+1 {
		t.Fatalf("stops counted %d, want 1", diskLimitStops.Value()-before)
	}
	// A stop that fails is retried on the next pass (nothing recorded now).
	seed("sb-stuck", "ctr-stuck", models.RuntimeDocker)
	rt.sizes["ctr-stuck"] = 9 << 30
	rt.stopErr = errors.New("engine busy")
	svc.runDiskLimitWatch(ctx)
	if s, _ := st.Get(ctx, "sb-stuck"); s.LastError != "" {
		t.Fatalf("a failed stop recorded %q", s.LastError)
	}
	rt.stopErr = nil
	// A size that cannot be read is skipped, not treated as over.
	seed("sb-unread", "ctr-unread", models.RuntimeDocker)
	rt.err = errors.New("inspect failed")
	svc.runDiskLimitWatch(ctx)
	if s, _ := st.Get(ctx, "sb-unread"); s.Status != models.SandboxStatusStarted {
		t.Fatal("an unreadable size stopped the sandbox")
	}
}

// TestDiskLimitWatchEdges: off at interval zero, an engine that cannot
// report sizes is skipped, and a store failure is logged.
func TestDiskLimitWatchEdges(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.cfg.DiskLimitCheckInterval = 0
	svc.StartDiskLimitWatch(ctx) // no-op
	var nilSvc *Service
	nilSvc.StartDiskLimitWatch(ctx)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-plain", Image: "alpine", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		CPU: 1, MemoryMB: 512, DiskGB: 1, ContainerID: "ctr", ContainerIP: "10.0.0.9", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	svc.runDiskLimitWatch(ctx) // recordingRuntime reports no sizes: skipped
	if s, _ := st.Get(ctx, "sb-plain"); s.Status != models.SandboxStatusStarted {
		t.Fatal("an engine without sizes stopped a sandbox")
	}
	svc.cfg.DiskLimitCheckInterval = time.Hour
	cctx, cancel := context.WithCancel(ctx)
	svc.StartDiskLimitWatch(cctx)
	cancel()
	_ = st.Close()
	svc.runDiskLimitWatch(ctx)
}
