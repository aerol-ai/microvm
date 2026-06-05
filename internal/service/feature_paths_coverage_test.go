package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func seedStartedSandbox(t *testing.T, st interface {
	Create(context.Context, *models.Sandbox) error
}, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:           id,
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerID:  "ctr-" + id,
		ContainerIP:  "10.0.0.77",
		CPU:          2,
		MemoryMB:     1024,
		DiskGB:       10,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

func TestNetworkUsageAndLimits(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	seedStartedSandbox(t, st, "sb-net")

	usage, err := svc.GetNetworkUsage(ctx, "sb-net")
	if err != nil {
		t.Fatalf("GetNetworkUsage: %v", err)
	}
	if usage == nil {
		t.Fatal("nil usage")
	}

	updated, err := svc.SetNetworkLimits(ctx, "sb-net", 1_000_000, 2_000_000)
	if err != nil {
		t.Fatalf("SetNetworkLimits: %v", err)
	}
	if updated.BytesInLimit != 1_000_000 || updated.BytesOutLimit != 2_000_000 {
		t.Fatalf("limits = %+v", updated)
	}

	// Not-found paths.
	if _, err := svc.GetNetworkUsage(ctx, "missing"); err == nil {
		t.Fatal("GetNetworkUsage(missing) should error")
	}
	if _, err := svc.SetNetworkLimits(ctx, "missing", 1, 1); err == nil {
		t.Fatal("SetNetworkLimits(missing) should error")
	}
}

func TestServiceUpdateTags(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	seedStartedSandbox(t, st, "sb-tags")

	if err := svc.UpdateTags(ctx, "sb-tags", map[string]string{"team": "blue"}); err != nil {
		t.Fatalf("UpdateTags: %v", err)
	}
	got, err := svc.GetSandbox(ctx, "sb-tags")
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if got.Tags["team"] != "blue" {
		t.Fatalf("tags = %+v", got.Tags)
	}
}

// resizeSnapRuntime supports Resize/CreateSnapshot (the bare recordingRuntime
// panics on both) so the service-level resize/snapshot paths can run.
type resizeSnapRuntime struct {
	*recordingRuntime
}

func (resizeSnapRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}

func (resizeSnapRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "img-snapshot", nil
}

func TestResizeAndLifecycle(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.docker = resizeSnapRuntime{rt}
	seedStartedSandbox(t, st, "sb-rz")

	resized, err := svc.ResizeSandbox(ctx, "sb-rz", models.ResizeSandboxRequest{CPU: 4, MemoryMB: 2048, DiskGB: 20})
	if err != nil {
		t.Fatalf("ResizeSandbox: %v", err)
	}
	if resized.CPU != 4 || resized.MemoryMB != 2048 {
		t.Fatalf("resized = cpu=%v mem=%d", resized.CPU, resized.MemoryMB)
	}

	updated, err := svc.UpdateLifecycle(ctx, "sb-rz", models.Lifecycle{StopIfIdleFor: 5 * time.Minute})
	if err != nil {
		t.Fatalf("UpdateLifecycle: %v", err)
	}
	if updated.Lifecycle.StopIfIdleFor != 5*time.Minute {
		t.Fatalf("lifecycle = %+v", updated.Lifecycle)
	}
}

func TestExposeUnexposeHTTPPort(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	seedStartedSandbox(t, st, "sb-port")

	// Caddy is disabled in the harness, so HTTP exposure is a store-only op.
	resp, err := svc.ExposePort(ctx, "sb-port", 8080, "")
	if err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if resp.Protocol != models.ExposedPortProtocolHTTP {
		t.Fatalf("expose resp = %+v", resp)
	}
	// Idempotent re-expose returns the same exposure.
	if _, err := svc.ExposePort(ctx, "sb-port", 8080, ""); err != nil {
		t.Fatalf("ExposePort (re-expose): %v", err)
	}

	if err := svc.UnexposePort(ctx, "sb-port", 8080); err != nil {
		t.Fatalf("UnexposePort: %v", err)
	}
}

func TestStopStartDestroyLifecycle(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	seedStartedSandbox(t, st, "sb-life")

	stopped, err := svc.StopSandbox(ctx, "sb-life")
	if err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	if stopped.Status != models.SandboxStatusStopped {
		t.Fatalf("status after stop = %q", stopped.Status)
	}

	started, err := svc.StartSandbox(ctx, "sb-life")
	if err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}
	if started.Status != models.SandboxStatusStarted {
		t.Fatalf("status after start = %q", started.Status)
	}

	// List with and without a tag filter.
	all, err := svc.ListSandboxes(ctx, nil)
	if err != nil || len(all) != 1 {
		t.Fatalf("ListSandboxes = %v, %v", all, err)
	}
	none, err := svc.ListSandboxes(ctx, map[string]string{"team": "nope"})
	if err != nil {
		t.Fatalf("ListSandboxes(filter): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no sandboxes for non-matching tag, got %d", len(none))
	}

	if err := svc.DestroySandbox(ctx, "sb-life"); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
	if _, err := svc.GetSandbox(ctx, "sb-life"); err == nil {
		t.Fatal("GetSandbox after destroy should error")
	}
}

func TestCreateSnapshotService(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.docker = resizeSnapRuntime{rt}
	seedStartedSandbox(t, st, "sb-snap")

	snap, err := svc.CreateSnapshot(ctx, "sb-snap", models.CreateSandboxSnapshotRequest{Name: "snap-svc"})
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if snap.Name != "snap-svc" {
		t.Fatalf("snapshot = %+v", snap)
	}
}
