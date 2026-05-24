package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// specWriteThroughCluster records UpsertSpec calls so a test can assert that
// the FSM-replicated spec saw a given mutation. Embeds cluster.Noop so any
// surface this test doesn't care about returns the standalone defaults.
type specWriteThroughCluster struct {
	*cluster.Noop

	mu       sync.Mutex
	spec     *models.CreateSandboxRequest
	upserted []models.CreateSandboxRequest
}

func (s *specWriteThroughCluster) SpecOf(string) *models.CreateSandboxRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.spec == nil {
		return nil
	}
	cp := *s.spec
	return &cp
}

func (s *specWriteThroughCluster) UpsertSpec(_ context.Context, _ string, spec *models.CreateSandboxRequest, _ cluster.PlacementSecrets) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *spec
	s.spec = &cp
	s.upserted = append(s.upserted, cp)
	return nil
}

func (s *specWriteThroughCluster) calls() []models.CreateSandboxRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]models.CreateSandboxRequest, len(s.upserted))
	copy(out, s.upserted)
	return out
}

// TestResizeSandboxWritesThroughToClusterSpec pins stage-4 issue I2: the
// FSM-replicated spec must be refreshed after a resize regardless of which
// HTTP wrapper made the call. Previously this lived in the v1 handler only,
// so Daytona/E2B resizes left the cluster spec stale — invisible today
// because failover=recreate is opt-in, but a latent bug the moment a user
// flips that policy on. The fix moves the write-through into the service
// layer; this test guards against a regression that re-introduces the
// per-handler duplication.
func TestResizeSandboxWritesThroughToClusterSpec(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	stub := &specWriteThroughCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512, DiskGB: 1},
	}
	svc.AttachCluster(stub)

	now := time.Now().UTC()
	const sandboxID = "sb-resize-replicate"
	if err := st.Create(ctx, &models.Sandbox{
		ID: sandboxID, Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-resize-replicate", ContainerIP: "10.0.0.30",
		CPU: 1, MemoryMB: 512, DiskGB: 1, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	if _, err := svc.ResizeSandbox(ctx, sandboxID, models.ResizeSandboxRequest{CPU: 4, MemoryMB: 2048}); err != nil {
		t.Fatalf("ResizeSandbox: %v", err)
	}

	calls := stub.calls()
	if len(calls) != 1 {
		t.Fatalf("UpsertSpec calls = %d, want 1 (one per resize, regardless of v1/Daytona/E2B caller)", len(calls))
	}
	got := calls[0]
	if got.CPU != 4 || got.MemoryMB != 2048 {
		t.Fatalf("replicated spec = {CPU:%v MemoryMB:%v}, want {CPU:4 MemoryMB:2048}", got.CPU, got.MemoryMB)
	}
	if got.DiskGB != 1 {
		t.Fatalf("replicated spec DiskGB = %d, want 1 (unchanged field must round-trip)", got.DiskGB)
	}
}

// TestUpdateLifecycleWritesThroughToClusterSpec is the symmetric guard for
// stage-4 I2 on lifecycle updates. Daytona's setAutoStopInterval and E2B's
// updateTimeout / pauseSandbox both go through Service.UpdateLifecycle, so
// asserting the service-level write-through is what proves both facades
// inherit the contract without per-handler duplication.
func TestUpdateLifecycleWritesThroughToClusterSpec(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	stub := &specWriteThroughCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		spec: &models.CreateSandboxRequest{Image: "alpine"},
	}
	svc.AttachCluster(stub)

	now := time.Now().UTC()
	const sandboxID = "sb-lifecycle-replicate"
	if err := st.Create(ctx, &models.Sandbox{
		ID: sandboxID, Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-lifecycle-replicate", ContainerIP: "10.0.0.31",
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	want := models.Lifecycle{StopIfIdleFor: 5 * time.Minute, DestroyIfIdleFor: time.Hour}
	if _, err := svc.UpdateLifecycle(ctx, sandboxID, want); err != nil {
		t.Fatalf("UpdateLifecycle: %v", err)
	}

	calls := stub.calls()
	if len(calls) != 1 {
		t.Fatalf("UpsertSpec calls = %d, want 1", len(calls))
	}
	got := calls[0].Lifecycle
	if got == nil {
		t.Fatal("replicated spec.Lifecycle = nil, want lifecycle to be carried into FSM")
	}
	if got.StopIfIdleFor != want.StopIfIdleFor || got.DestroyIfIdleFor != want.DestroyIfIdleFor {
		t.Fatalf("replicated lifecycle = %+v, want %+v", *got, want)
	}
}

// TestResizeSandboxSkipsWriteThroughWhenSpecNotRecorded covers the pre-cluster
// sandbox case: SpecOf returns nil for placements that predate cluster mode
// (or for sandboxes never written through the cluster path). The service must
// not crash and must not invent a spec to upsert — silent no-op is correct.
func TestResizeSandboxSkipsWriteThroughWhenSpecNotRecorded(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	stub := &specWriteThroughCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	svc.AttachCluster(stub)

	now := time.Now().UTC()
	const sandboxID = "sb-resize-no-spec"
	if err := st.Create(ctx, &models.Sandbox{
		ID: sandboxID, Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-resize-no-spec", ContainerIP: "10.0.0.32",
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	if _, err := svc.ResizeSandbox(ctx, sandboxID, models.ResizeSandboxRequest{CPU: 2}); err != nil {
		t.Fatalf("ResizeSandbox: %v", err)
	}
	if calls := stub.calls(); len(calls) != 0 {
		t.Fatalf("UpsertSpec was called %d times for a pre-cluster sandbox; want 0", len(calls))
	}
}
