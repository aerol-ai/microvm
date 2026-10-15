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

// TestUpdateTagsWritesThroughToClusterSpec pins B11: a tag edit after create
// must refresh the FSM-replicated spec, or a failover recreate replays the
// create-time tags and silently drops the edit.
func TestUpdateTagsWritesThroughToClusterSpec(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	stub := &specWriteThroughCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		spec: &models.CreateSandboxRequest{Image: "alpine", Tags: map[string]string{"team": "old"}},
	}
	svc.AttachCluster(stub)

	now := time.Now().UTC()
	const sandboxID = "sb-tags-replicate"
	if err := st.Create(ctx, &models.Sandbox{
		ID: sandboxID, Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-tags-replicate", ContainerIP: "10.0.0.32",
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	want := map[string]string{"team": "sdk", "env": "prod"}
	if err := svc.UpdateTags(ctx, sandboxID, want); err != nil {
		t.Fatalf("UpdateTags: %v", err)
	}

	calls := stub.calls()
	if len(calls) != 1 {
		t.Fatalf("UpsertSpec calls = %d, want 1", len(calls))
	}
	got := calls[0].Tags
	if got["team"] != "sdk" || got["env"] != "prod" || len(got) != 2 {
		t.Fatalf("replicated spec.Tags = %+v, want %+v", got, want)
	}
}

// A pre-cluster sandbox (SpecOf nil) does not get a spurious spec write.
func TestUpdateTagsSkipsWriteThroughWhenSpecNotRecorded(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	stub := &specWriteThroughCluster{Noop: cluster.NewNoop("self", "http://self", "")} // spec nil
	svc.AttachCluster(stub)

	now := time.Now().UTC()
	const sandboxID = "sb-tags-nospec"
	if err := st.Create(ctx, &models.Sandbox{
		ID: sandboxID, Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-tags-nospec", ContainerIP: "10.0.0.33",
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := svc.UpdateTags(ctx, sandboxID, map[string]string{"k": "v"}); err != nil {
		t.Fatalf("UpdateTags: %v", err)
	}
	if calls := stub.calls(); len(calls) != 0 {
		t.Fatalf("UpsertSpec called %d times for a pre-cluster sandbox; want 0", len(calls))
	}
}

// TestUpsertCompatStateWritesThroughToClusterSpec pins B11: facade compat state
// must ride the FSM-replicated spec so a failover recreate can restore it (the
// sandbox_compat_state rows are node-local).
func TestUpsertCompatStateWritesThroughToClusterSpec(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	stub := &specWriteThroughCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		spec: &models.CreateSandboxRequest{Image: "alpine"},
	}
	svc.AttachCluster(stub)

	now := time.Now().UTC()
	const sandboxID = "sb-compat-replicate"
	if err := st.Create(ctx, &models.Sandbox{
		ID: sandboxID, Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-compat-replicate", ContainerIP: "10.0.0.34",
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	if err := svc.UpsertCompatState(ctx, sandboxID, models.FacadeRunloop, `{"name":"box"}`); err != nil {
		t.Fatalf("UpsertCompatState runloop: %v", err)
	}
	if err := svc.UpsertCompatState(ctx, sandboxID, models.FacadeE2B, `{"t":1}`); err != nil {
		t.Fatalf("UpsertCompatState e2b: %v", err)
	}

	calls := stub.calls()
	if len(calls) != 2 {
		t.Fatalf("UpsertSpec calls = %d, want 2", len(calls))
	}
	// The last write-through carries both facades' state, merged.
	got := calls[len(calls)-1].CompatState
	if got[models.FacadeRunloop] != `{"name":"box"}` || got[models.FacadeE2B] != `{"t":1}` {
		t.Fatalf("replicated spec.CompatState = %+v, want both facades", got)
	}
}

// restoreCompatStateAfterRecreate re-materializes the facade compat-state rows a
// failover recreate inherited from the replicated spec (B11).
func TestRestoreCompatStateAfterRecreate(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	now := time.Now().UTC()
	const sandboxID = "sb-compat-restore"
	if err := st.Create(ctx, &models.Sandbox{
		ID: sandboxID, Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-compat-restore", ContainerIP: "10.0.0.35",
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	svc.restoreCompatStateAfterRecreate(ctx, sandboxID, map[string]string{
		models.FacadeRunloop: `{"name":"restored"}`,
		models.FacadeE2B:     `{"t":9}`,
	})

	got, err := st.GetCompatState(ctx, sandboxID, models.FacadeRunloop)
	if err != nil || got.StateJSON != `{"name":"restored"}` {
		t.Fatalf("runloop compat not restored: %+v err=%v", got, err)
	}
	e2b, err := st.GetCompatState(ctx, sandboxID, models.FacadeE2B)
	if err != nil || e2b.StateJSON != `{"t":9}` {
		t.Fatalf("e2b compat not restored: %+v err=%v", e2b, err)
	}
}

// normalizeCreateRequest strips any client-supplied CompatState so only the
// service's own write-through populates it (B11).
func TestNormalizeCreateRequestStripsCompatState(t *testing.T) {
	req := models.CreateSandboxRequest{
		Image:       "alpine",
		CompatState: map[string]string{models.FacadeRunloop: `{"injected":true}`},
	}
	if got := normalizeCreateRequest(req); got.CompatState != nil {
		t.Fatalf("normalizeCreateRequest kept CompatState = %+v, want nil", got.CompatState)
	}
}
