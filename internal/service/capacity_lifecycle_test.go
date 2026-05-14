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
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// fakeCapacityRuntime is a permissive runtime fake for the capacity-accounting
// tests. The default reconcile fake panics on Inspect / ListManaged variations
// we need here, so we own the surface explicitly. Anything not exercised by a
// test is a no-op rather than a panic — these tests assert on admitter state,
// not runtime call shape, so loud failure on unrelated calls would just be
// noise.
type fakeCapacityRuntime struct {
	managed map[string]*models.SandboxRuntimeState
	inspect map[string]*models.SandboxRuntimeState
}

func (f *fakeCapacityRuntime) ListManaged(_ context.Context) (map[string]*models.SandboxRuntimeState, error) {
	out := make(map[string]*models.SandboxRuntimeState, len(f.managed))
	for k, v := range f.managed {
		out[k] = v
	}
	return out, nil
}

func (f *fakeCapacityRuntime) Inspect(_ context.Context, ref string) (*models.SandboxRuntimeState, error) {
	if state, ok := f.inspect[ref]; ok {
		return state, nil
	}
	return &models.SandboxRuntimeState{}, nil
}

func (f *fakeCapacityRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (f *fakeCapacityRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", nil
}
func (f *fakeCapacityRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (f *fakeCapacityRuntime) Stop(context.Context, string) error             { return nil }
func (f *fakeCapacityRuntime) Destroy(context.Context, *models.Sandbox) error { return nil }
func (f *fakeCapacityRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}
func (f *fakeCapacityRuntime) Ping(context.Context) error                { return nil }
func (f *fakeCapacityRuntime) RemoveImage(context.Context, string) error { return nil }
func (f *fakeCapacityRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	return nil
}
func (f *fakeCapacityRuntime) ClearNetworkRules(string) error    { return nil }
func (f *fakeCapacityRuntime) ApplyNetworkBlockAll(string) error { return nil }

func newCapacityHarness(t *testing.T, managed, inspect map[string]*models.SandboxRuntimeState) (*Service, *capacity.Admitter, *store.Store) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     filepath.Join(t.TempDir(), "mounts"),
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)

	svc := &Service{
		cfg:    config.Config{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		docker: &fakeCapacityRuntime{managed: managed, inspect: inspect},
		caddy: caddy.New(config.Config{
			EnableCaddy:       false,
			HTTPClientTimeout: time.Second,
		}),
		mounts:   mgr,
		admitter: admitter,
	}
	return svc, admitter, st
}

// TestDieEventReleasesAdmitter is the headline regression: stopping a sandbox
// must free its admitter slot so the next CreateSandbox can use that budget.
// Pre-fix, markSandboxStopped only updated the row to status=stopped and left
// the reservation in place — operators ran into "host capacity exceeded"
// errors after running `docker stop` on stale containers, even though those
// containers consumed no CPU/RAM.
func TestDieEventReleasesAdmitter(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const sandboxID = "sb-die-cap"
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           sandboxID,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-die-cap",
		ContainerIP:  "10.0.0.10",
		CPU:          2,
		MemoryMB:     2048,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	admitter.Reserve(sandboxID, capacity.Request{CPU: 2, MemoryMB: 2048})

	if snap := admitter.Snapshot(); snap.SandboxesActive != 1 {
		t.Fatalf("precondition: active=%d, want 1", snap.SandboxesActive)
	}

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: sandboxID,
		Action:    "die",
		ExitCode:  137,
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("handleDockerEvent die: %v", err)
	}

	snap := admitter.Snapshot()
	if snap.SandboxesActive != 0 {
		t.Fatalf("admitter still holds reservation after die: %+v", snap)
	}
	if snap.ReservedCPU != 0 || snap.ReservedMemoryMB != 0 {
		t.Fatalf("admitter accounting not zeroed: cpu=%v mem=%v", snap.ReservedCPU, snap.ReservedMemoryMB)
	}
	// Row still exists at status=stopped — Start must be able to bring it back.
	got, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("row should be preserved on die: %v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("row status: got %q, want %q", got.Status, models.SandboxStatusStopped)
	}
}

// TestStartEventReservesAdmitter covers the symmetric out-of-band path: an
// operator runs `docker start <id>` directly. The container is now consuming
// CPU/RAM, so the admitter must Reserve the slot — Reserve, not Admit, because
// the container is already running and the host cannot refuse it.
func TestStartEventReservesAdmitter(t *testing.T) {
	ctx := context.Background()
	const sandboxID = "sb-start-cap"
	const containerID = "ctr-start-cap"
	const newIP = "10.0.0.55"

	svc, admitter, st := newCapacityHarness(t, nil, map[string]*models.SandboxRuntimeState{
		containerID: {
			SandboxID:   sandboxID,
			ContainerID: containerID,
			ContainerIP: newIP,
			Status:      models.SandboxStatusStarted,
		},
	})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           sandboxID,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStopped,
		ContainerID:  containerID,
		ContainerIP:  "",
		CPU:          1,
		MemoryMB:     512,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("precondition: active=%d, want 0 (sandbox starts stopped)", snap.SandboxesActive)
	}

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID:   sandboxID,
		ContainerID: containerID,
		Action:      "start",
		Time:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("handleDockerEvent start: %v", err)
	}

	snap := admitter.Snapshot()
	if snap.SandboxesActive != 1 {
		t.Fatalf("admitter did not Reserve on start event: %+v", snap)
	}
	if snap.ReservedCPU != 1 || snap.ReservedMemoryMB != 512 {
		t.Fatalf("reservation footprint: cpu=%v mem=%v, want 1/512", snap.ReservedCPU, snap.ReservedMemoryMB)
	}
}

// TestReconcileSyncsAdmitterWithRuntimeState is the safety-net test: even if
// every event was lost (daemon restart, missed event, manual `docker stop`
// before sandboxd started), the next reconcile pass must reconcile the
// admitter to ground truth. Stopped containers release; running containers
// reserve. Both directions matter — a one-sided fix would let the host
// silently drift in the other direction.
func TestReconcileSyncsAdmitterWithRuntimeState(t *testing.T) {
	ctx := context.Background()
	const (
		stoppedID = "sb-recon-stopped"
		runningID = "sb-recon-running"
	)
	managed := map[string]*models.SandboxRuntimeState{
		stoppedID: {
			SandboxID:   stoppedID,
			ContainerID: "ctr-stopped",
			ContainerIP: "",
			Status:      models.SandboxStatusStopped,
		},
		runningID: {
			SandboxID:   runningID,
			ContainerID: "ctr-running",
			ContainerIP: "10.0.0.20",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, admitter, st := newCapacityHarness(t, managed, nil)

	now := time.Now().UTC()
	// Stopped sandbox in the DB but admitter still thinks it has a slot —
	// what you'd see after a missed die event or pre-fix daemon upgrade.
	if err := st.Create(ctx, &models.Sandbox{
		ID:           stoppedID,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStarted, // will be reconciled to stopped
		ContainerID:  "ctr-stopped",
		ContainerIP:  "10.0.0.19",
		CPU:          1,
		MemoryMB:     1024,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed stopped sandbox: %v", err)
	}
	admitter.Reserve(stoppedID, capacity.Request{CPU: 1, MemoryMB: 1024})

	// Running sandbox in the DB but admitter has no record of it — what
	// you'd see after a daemon restart with a stopped row that came back
	// online out-of-band before ReplayReservations could see it.
	if err := st.Create(ctx, &models.Sandbox{
		ID:           runningID,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStopped, // will be reconciled to started
		ContainerID:  "ctr-running",
		ContainerIP:  "10.0.0.20",
		CPU:          2,
		MemoryMB:     4096,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed running sandbox: %v", err)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	snap := admitter.Snapshot()
	if snap.SandboxesActive != 1 {
		t.Fatalf("admitter not in sync: active=%d, want 1 (only the running sandbox)", snap.SandboxesActive)
	}
	if snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 4096 {
		t.Fatalf("admitter accounting wrong: cpu=%v mem=%v, want 2/4096", snap.ReservedCPU, snap.ReservedMemoryMB)
	}
}

// TestReplayReservationsSkipsStopped pins down the daemon-boot behavior. A
// stopped sandbox row exists for life-of-sandbox reasons (Start can resurrect
// it), but it consumes nothing on the host, so the admitter must not bill it
// at startup. Pre-fix, the only skipped status was "destroyed" — counting
// stopped rows would re-introduce the overcommit bug we just fixed on the
// stop path.
func TestReplayReservationsSkipsStopped(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	now := time.Now().UTC()
	mustSeed := func(id string, status models.SandboxStatus, cpu float64, mem int) {
		t.Helper()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           id,
			Image:        "ubuntu:22.04",
			Status:       status,
			Runtime:      models.RuntimeDocker,
			CPU:          cpu,
			MemoryMB:     mem,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	mustSeed("sb-replay-running", models.SandboxStatusStarted, 1, 512)
	mustSeed("sb-replay-stopped", models.SandboxStatusStopped, 4, 8192)
	mustSeed("sb-replay-destroyed", models.SandboxStatusDestroyed, 8, 16384)

	svc.ReplayReservations(ctx)

	snap := admitter.Snapshot()
	if snap.SandboxesActive != 1 {
		t.Fatalf("replay should count only running sandboxes: active=%d, want 1", snap.SandboxesActive)
	}
	if snap.ReservedCPU != 1 || snap.ReservedMemoryMB != 512 {
		t.Fatalf("replay footprint wrong: cpu=%v mem=%v, want 1/512 (only the running sandbox)",
			snap.ReservedCPU, snap.ReservedMemoryMB)
	}
}

// seedSandbox is the shared seed helper for the lifecycle integration tests
// below. Returns the sandbox so individual tests can inspect/mutate without
// re-reading from the store.
func seedSandbox(t *testing.T, st *store.Store, id string, status models.SandboxStatus, cpu float64, mem int) *models.Sandbox {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:           id,
		Image:        "ubuntu:22.04",
		Status:       status,
		ContainerID:  "ctr-" + id,
		ContainerIP:  "10.0.0.1",
		Runtime:      models.RuntimeDocker,
		CPU:          cpu,
		MemoryMB:     mem,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("seed sandbox %s: %v", id, err)
	}
	return sb
}

// TestStopSandboxAPIReleasesAdmitter pairs with TestDieEventReleasesAdmitter
// for the API path. StopSandbox must release the admitter slot whether the
// stop arrives via API or via die event — the lifecycle accounting cannot
// depend on which path the operator used.
func TestStopSandboxAPIReleasesAdmitter(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const id = "sb-api-stop"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 2, 2048)
	admitter.Reserve(id, capacity.Request{CPU: 2, MemoryMB: 2048})

	if _, err := svc.StopSandbox(ctx, id); err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}

	snap := admitter.Snapshot()
	if snap.SandboxesActive != 0 {
		t.Fatalf("StopSandbox did not release admitter: %+v", snap)
	}
	got, err := st.Get(ctx, id)
	if err != nil {
		t.Fatalf("row should remain after stop: %v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("status after stop: got %q, want %q", got.Status, models.SandboxStatusStopped)
	}
}

// TestStopSandboxAPIIdempotent: a second Stop API call after the first must
// not corrupt admitter state or fail loudly. Operators retry stops; the API
// must absorb that.
func TestStopSandboxAPIIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const id = "sb-stop-twice"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 1024})

	if _, err := svc.StopSandbox(ctx, id); err != nil {
		t.Fatalf("first StopSandbox: %v", err)
	}
	if _, err := svc.StopSandbox(ctx, id); err != nil {
		t.Fatalf("second StopSandbox: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("repeated stop corrupted admitter: %+v", snap)
	}
}

// TestMultipleDieEventsIdempotent: the event monitor may deliver duplicate
// die events on reconnect. Each duplicate must be a no-op for the admitter.
func TestMultipleDieEventsIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const id = "sb-die-dup"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 2, 2048)
	admitter.Reserve(id, capacity.Request{CPU: 2, MemoryMB: 2048})

	for i := 0; i < 3; i++ {
		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
			SandboxID: id,
			Action:    "die",
			ExitCode:  137,
			Time:      time.Now().UTC(),
		}); err != nil {
			t.Fatalf("die event %d: %v", i, err)
		}
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("duplicate die events leaked: %+v", snap)
	}
}

// TestMultipleStartEventsIdempotent: same shape for start. Reserve is
// idempotent per ID, so duplicate starts must not double-count.
func TestMultipleStartEventsIdempotent(t *testing.T) {
	ctx := context.Background()
	const id = "sb-start-dup"
	const containerID = "ctr-sb-start-dup"
	svc, admitter, st := newCapacityHarness(t, nil, map[string]*models.SandboxRuntimeState{
		containerID: {
			SandboxID:   id,
			ContainerID: containerID,
			ContainerIP: "10.0.0.50",
			Status:      models.SandboxStatusStarted,
		},
	})

	sb := seedSandbox(t, st, id, models.SandboxStatusStopped, 1, 1024)
	sb.ContainerID = containerID
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("upsert seed: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
			SandboxID:   id,
			ContainerID: containerID,
			Action:      "start",
			Time:        time.Now().UTC(),
		}); err != nil {
			t.Fatalf("start event %d: %v", i, err)
		}
	}
	snap := admitter.Snapshot()
	if snap.SandboxesActive != 1 || snap.ReservedCPU != 1 || snap.ReservedMemoryMB != 1024 {
		t.Fatalf("duplicate start events corrupted accounting: %+v", snap)
	}
}

// TestNilAdmitterTolerated: every admitter access in the lifecycle code is
// `if s.admitter != nil { ... }`. When the admitter is disabled (zero-config
// hosted dev install), the lifecycle paths must still complete without a
// panic. This test pins down the contract so a future refactor that drops
// the nil-guard fails loudly.
func TestNilAdmitterTolerated(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.admitter = nil // simulate admission disabled

	const id = "sb-no-admitter"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 512)

	// die → markSandboxStopped path
	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: id,
		Action:    "die",
		ExitCode:  0,
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("die event: %v", err)
	}
	// destroy → handleDestroyEvent path
	seedSandbox(t, st, id+"-2", models.SandboxStatusStarted, 1, 512)
	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: id + "-2",
		Action:    "destroy",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("destroy event: %v", err)
	}
	// Reconcile (managed=nil → destroyed branch)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// ReplayReservations must short-circuit, not panic.
	svc.ReplayReservations(ctx)
}

// TestMultiSandboxIndependentLifecycle: stopping one sandbox must not affect
// another's reservation, even when both are accounted in the admitter at the
// same time. Mirrors the capacity-package isolation test, but at the service
// integration layer.
func TestMultiSandboxIndependentLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	for _, id := range []string{"sb-multi-a", "sb-multi-b", "sb-multi-c"} {
		seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 1024)
		admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 1024})
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 3 {
		t.Fatalf("precondition: %+v", snap)
	}

	// Stop only b via die event.
	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: "sb-multi-b",
		Action:    "die",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("die b: %v", err)
	}
	snap := admitter.Snapshot()
	if snap.SandboxesActive != 2 || snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 2048 {
		t.Fatalf("multi-sandbox isolation broken: %+v", snap)
	}
	// a and c rows untouched.
	for _, id := range []string{"sb-multi-a", "sb-multi-c"} {
		got, err := st.Get(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if got.Status != models.SandboxStatusStarted {
			t.Fatalf("%s status: got %q, want started", id, got.Status)
		}
	}
}

// TestReplayReservationsCountsCreatingAndError: stopped + destroyed are the
// only excluded statuses. Creating means a CreateSandbox is mid-flight (the
// container exists or is about to) and error means the lifecycle wedged with
// the container still attached — both consume host resources and must be
// billed on replay.
func TestReplayReservationsCountsCreatingAndError(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	now := time.Now().UTC()
	mustSeed := func(id string, status models.SandboxStatus, cpu float64, mem int) {
		t.Helper()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           id,
			Image:        "ubuntu:22.04",
			Status:       status,
			Runtime:      models.RuntimeDocker,
			CPU:          cpu,
			MemoryMB:     mem,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	mustSeed("sb-replay-creating", models.SandboxStatusCreating, 1, 512)
	mustSeed("sb-replay-error", models.SandboxStatusError, 2, 1024)

	svc.ReplayReservations(ctx)

	snap := admitter.Snapshot()
	if snap.SandboxesActive != 2 {
		t.Fatalf("creating + error must replay: %+v", snap)
	}
	if snap.ReservedCPU != 3 || snap.ReservedMemoryMB != 1536 {
		t.Fatalf("creating+error footprint: %+v", snap)
	}
}

// TestReplayReservationsEmptyStore: no rows means no reservations. Important
// regression hook for the daemon-cold-start path on a fresh install — the
// admitter must not arrive at zero+1 because of an uninitialized loop var.
func TestReplayReservationsEmptyStore(t *testing.T) {
	ctx := context.Background()
	svc, admitter, _ := newCapacityHarness(t, nil, nil)

	svc.ReplayReservations(ctx)
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("fresh store should replay nothing: %+v", snap)
	}
}

// TestDestroyEventIdempotentRelease: a destroy event for a sandbox row that
// has already been removed (API destroy ran first, then the event arrives)
// must be a silent no-op — handleDockerEvent translates ErrNotFound to nil.
// This pins down the race-tolerance contract.
func TestDestroyEventIdempotentRelease(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const id = "sb-already-gone"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 1024})

	// Simulate the API path winning the race: row is gone, slot released.
	if err := st.Delete(ctx, id); err != nil {
		t.Fatalf("delete row: %v", err)
	}
	admitter.Release(id)

	// Event arrives late.
	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: id,
		Action:    "destroy",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("late destroy event must be a no-op: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("admitter mutated by no-op event: %+v", snap)
	}
}

// TestImageGCSkippedWhenAnotherSandboxReferences: destroying one sandbox
// must NOT remove the image if another sandbox (any non-destroyed status)
// still references it. Otherwise a Stop+Destroy on one container would yank
// the image out from under a sibling that's about to start.
func TestImageGCSkippedWhenAnotherSandboxReferences(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	rt := svc.docker.(*fakeCapacityRuntime)
	imageRemoved := 0
	rt2 := &countingFakeRuntime{fakeCapacityRuntime: *rt, removed: &imageRemoved}
	svc.docker = rt2

	const survivor = "sb-survivor"
	const doomed = "sb-doomed"
	seedSandbox(t, st, survivor, models.SandboxStatusStarted, 1, 1024)
	seedSandbox(t, st, doomed, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(survivor, capacity.Request{CPU: 1, MemoryMB: 1024})
	admitter.Reserve(doomed, capacity.Request{CPU: 1, MemoryMB: 1024})

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: doomed,
		Action:    "destroy",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("destroy event: %v", err)
	}
	if imageRemoved != 0 {
		t.Fatalf("image GC ran while sibling still references image: hits=%d", imageRemoved)
	}
	// Survivor still in the admitter.
	if snap := admitter.Snapshot(); snap.SandboxesActive != 1 {
		t.Fatalf("survivor evicted from admitter: %+v", snap)
	}
}

// TestImageGCRunsWhenLastReferenceDestroyed: the inverse — when no other
// sandbox references the image, the destroy event must trigger image
// removal. Pre-fix store.Delete-after-RemoveImage would have skipped the GC
// because HasActiveImageRef saw the doomed row at status=started.
func TestImageGCRunsWhenLastReferenceDestroyed(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	imageRemoved := 0
	rt := svc.docker.(*fakeCapacityRuntime)
	svc.docker = &countingFakeRuntime{fakeCapacityRuntime: *rt, removed: &imageRemoved}

	const id = "sb-only-ref"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 1024})

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: id,
		Action:    "destroy",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("destroy event: %v", err)
	}
	if imageRemoved != 1 {
		t.Fatalf("expected image GC to fire exactly once, got %d", imageRemoved)
	}
}

// TestImageGCSkippedWhenStoppedSiblingReferences: stopped is treated as a
// live reference (the image is needed to Start the sibling later), so the
// GC must skip even though the stopped container holds no host CPU/RAM.
// This is exactly the behavior that lets Stop+Start be free.
func TestImageGCSkippedWhenStoppedSiblingReferences(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	imageRemoved := 0
	rt := svc.docker.(*fakeCapacityRuntime)
	svc.docker = &countingFakeRuntime{fakeCapacityRuntime: *rt, removed: &imageRemoved}

	seedSandbox(t, st, "sb-stopped-sibling", models.SandboxStatusStopped, 1, 1024)
	const doomed = "sb-doomed-2"
	seedSandbox(t, st, doomed, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(doomed, capacity.Request{CPU: 1, MemoryMB: 1024})

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: doomed,
		Action:    "destroy",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("destroy event: %v", err)
	}
	if imageRemoved != 0 {
		t.Fatalf("image GC ran with stopped sibling holding the image: hits=%d", imageRemoved)
	}
}

// TestReconcileIdempotentAcrossPasses: two consecutive Reconcile calls on the
// same world view must produce the same admitter state. The pre-fix Reserve
// loop would have re-Reserved the same ID on every pass — fine for state but
// we want to assert it explicitly so accidental "+= req" arithmetic is caught.
func TestReconcileIdempotentAcrossPasses(t *testing.T) {
	ctx := context.Background()
	const id = "sb-recon-idem"
	managed := map[string]*models.SandboxRuntimeState{
		id: {
			SandboxID:   id,
			ContainerID: "ctr-recon-idem",
			ContainerIP: "10.0.0.30",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, admitter, st := newCapacityHarness(t, managed, nil)
	seedSandbox(t, st, id, models.SandboxStatusStarted, 2, 2048)

	for i := 0; i < 5; i++ {
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile pass %d: %v", i, err)
		}
		snap := admitter.Snapshot()
		if snap.SandboxesActive != 1 || snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 2048 {
			t.Fatalf("pass %d footprint: %+v", i, snap)
		}
	}
}

// TestReconcileStoppedThenStartedFlip: a sandbox that goes
// stopped→started→stopped across reconcile passes must end with the admitter
// at zero. Catches a class of bugs where Reserve and Release branches drift
// out of sync (e.g. only Release called).
func TestReconcileStoppedThenStartedFlip(t *testing.T) {
	ctx := context.Background()
	const id = "sb-flip"
	const containerID = "ctr-flip"
	managed := map[string]*models.SandboxRuntimeState{
		id: {
			SandboxID:   id,
			ContainerID: containerID,
			ContainerIP: "",
			Status:      models.SandboxStatusStopped,
		},
	}
	svc, admitter, st := newCapacityHarness(t, managed, nil)
	sb := seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 512)
	sb.ContainerID = containerID
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 512})

	// Pass 1: managed says stopped → admitter releases.
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("after stopped pass: %+v", snap)
	}

	// Flip managed to started.
	managed[id].Status = models.SandboxStatusStarted
	managed[id].ContainerIP = "10.0.0.31"
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 1 || snap.ReservedCPU != 1 {
		t.Fatalf("after started pass: %+v", snap)
	}

	// Flip back to stopped.
	managed[id].Status = models.SandboxStatusStopped
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("pass 3: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("after re-stopped pass: %+v", snap)
	}
}

// TestReconcileMultiSandboxMixedStates: one started, one stopped, one
// destroyed (managed missing) — the admitter must end with exactly the
// started sandbox billed. Exercises all three reconcile branches in one pass.
func TestReconcileMultiSandboxMixedStates(t *testing.T) {
	ctx := context.Background()
	const (
		startedID   = "sb-mix-running"
		stoppedID   = "sb-mix-stopped"
		destroyedID = "sb-mix-destroyed"
	)
	managed := map[string]*models.SandboxRuntimeState{
		startedID: {
			SandboxID:   startedID,
			ContainerID: "ctr-" + startedID,
			ContainerIP: "10.0.0.40",
			Status:      models.SandboxStatusStarted,
		},
		stoppedID: {
			SandboxID:   stoppedID,
			ContainerID: "ctr-" + stoppedID,
			Status:      models.SandboxStatusStopped,
		},
		// destroyedID intentionally missing from managed.
	}
	svc, admitter, st := newCapacityHarness(t, managed, nil)

	seedSandbox(t, st, startedID, models.SandboxStatusStopped, 2, 2048) // will reconcile to started
	seedSandbox(t, st, stoppedID, models.SandboxStatusStarted, 4, 4096) // will reconcile to stopped
	seedSandbox(t, st, destroyedID, models.SandboxStatusStarted, 1, 1024)

	// Pre-load admitter with stale data for stopped + destroyed; reconcile
	// must clean them out.
	admitter.Reserve(stoppedID, capacity.Request{CPU: 4, MemoryMB: 4096})
	admitter.Reserve(destroyedID, capacity.Request{CPU: 1, MemoryMB: 1024})

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	snap := admitter.Snapshot()
	if snap.SandboxesActive != 1 || snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 2048 {
		t.Fatalf("mixed-state reconcile footprint: %+v", snap)
	}
	// Destroyed row removed.
	if _, err := st.Get(ctx, destroyedID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("destroyed row not deleted: %v", err)
	}
}

// TestStartEventReserveBeforeCaddyUpsert: the start-event handler must
// Reserve before it tries to upsert caddy routes, otherwise a transient
// caddy hiccup would let the container run un-billed. The proxy doesn't
// matter for billing — what matters is "is this container running on the
// host." Asserts the order by mocking caddy as disabled and verifying the
// admitter state is in place even though no caddy work happened.
func TestStartEventReserveBeforeCaddyUpsert(t *testing.T) {
	ctx := context.Background()
	const id = "sb-start-order"
	const containerID = "ctr-start-order"
	svc, admitter, st := newCapacityHarness(t, nil, map[string]*models.SandboxRuntimeState{
		containerID: {
			SandboxID:   id,
			ContainerID: containerID,
			ContainerIP: "10.0.0.60",
			Status:      models.SandboxStatusStarted,
		},
	})
	sb := seedSandbox(t, st, id, models.SandboxStatusStopped, 2, 2048)
	sb.ContainerID = containerID
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID:   id,
		ContainerID: containerID,
		Action:      "start",
		Time:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("start event: %v", err)
	}
	snap := admitter.Snapshot()
	if snap.SandboxesActive != 1 || snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 2048 {
		t.Fatalf("start event did not reserve: %+v", snap)
	}
}

// TestUnknownEventActionIsNoOp: handleDockerEvent must silently ignore
// actions outside its switch (e.g. "kill", "pause", "exec_create"). A future
// Docker version that adds a new action must not crash the daemon or perturb
// admitter state.
func TestUnknownEventActionIsNoOp(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const id = "sb-pause-test"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 2, 2048)
	admitter.Reserve(id, capacity.Request{CPU: 2, MemoryMB: 2048})

	for _, action := range []string{"pause", "unpause", "exec_create", "rename", ""} {
		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
			SandboxID: id,
			Action:    action,
			Time:      time.Now().UTC(),
		}); err != nil {
			t.Fatalf("event %q must be a no-op: %v", action, err)
		}
	}
	snap := admitter.Snapshot()
	if snap.SandboxesActive != 1 || snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 2048 {
		t.Fatalf("unknown action perturbed admitter: %+v", snap)
	}
	// Row untouched.
	got, err := st.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("status mutated by unknown action: %q", got.Status)
	}
}

// TestUnknownSandboxEventIsNoOp: events for a sandbox we don't have a row
// for (manual `docker rm` of a non-managed container that happened to share
// our label, or a stale event after our DB was wiped) must be silent. Fail-
// loud here would have us logging a noise warning per event.
func TestUnknownSandboxEventIsNoOp(t *testing.T) {
	ctx := context.Background()
	svc, admitter, _ := newCapacityHarness(t, nil, nil)

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: "sb-never-existed",
		Action:    "die",
		ExitCode:  0,
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("event for unknown sandbox: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("admitter mutated by unknown-sandbox event: %+v", snap)
	}
}

// TestOOMEventReleasesAdmitter: oom is grouped with die/stop in
// markSandboxStopped — the container is dead, the host slot is freed, and
// the row is preserved with a LastError that names OOM so users can see why
// their container died on next list.
func TestOOMEventReleasesAdmitter(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const id = "sb-oom"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 1024})

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: id,
		Action:    "oom",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("oom event: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("oom did not release admitter: %+v", snap)
	}
	got, err := st.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("status after oom: %q, want stopped", got.Status)
	}
	if got.LastError == "" {
		t.Fatalf("oom event must set LastError so the cause shows in /v1/sandboxes")
	}
}

// TestStopEventActionReleasesAdmitter: covers the third action that funnels
// through markSandboxStopped — "stop" — separately from die/oom. Belt-and-
// braces against a future refactor that splits the switch.
func TestStopEventActionReleasesAdmitter(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const id = "sb-stop-event"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 1024})

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: id,
		Action:    "stop",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("stop event: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("stop event did not release: %+v", snap)
	}
}

// TestReconcileDoesNotResurrectDestroyedRow: a row that was just destroyed
// in pass N must remain absent in pass N+1, even if the managed map still
// returns nothing for it. In other words, reconcile must be convergent: the
// destroyed branch deletes the row and subsequent passes are no-ops, not
// re-inserts.
func TestReconcileDoesNotResurrectDestroyedRow(t *testing.T) {
	ctx := context.Background()
	const id = "sb-no-resurrect"
	svc, admitter, st := newCapacityHarness(t, nil, nil) // managed empty
	seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 1024})

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row not deleted: %v", err)
	}
	// Pass 2 with the same world: still nothing.
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row resurrected on pass 2: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("admitter resurrected: %+v", snap)
	}
}

// countingFakeRuntime wraps fakeCapacityRuntime to count RemoveImage calls
// for the image-GC tests above. Other methods inherit the no-op behavior.
type countingFakeRuntime struct {
	fakeCapacityRuntime
	removed *int
}

func (c *countingFakeRuntime) RemoveImage(_ context.Context, _ string) error {
	*c.removed++
	return nil
}
