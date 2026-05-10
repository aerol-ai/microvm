package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync/atomic"
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

// fakeReconcileRuntime is the minimum runtime.Runtime stub that exercises the
// reconcile destroyed-row branch: a controllable ListManaged plus a counted
// RemoveImage. All other methods are unused on this code path and panic loudly
// if reached, so a future refactor that starts calling them in reconcile fails
// the test instead of silently passing.
type fakeReconcileRuntime struct {
	managed         map[string]*models.SandboxRuntimeState
	removeImageHits atomic.Int32
}

func (f *fakeReconcileRuntime) ListManaged(_ context.Context) (map[string]*models.SandboxRuntimeState, error) {
	out := make(map[string]*models.SandboxRuntimeState, len(f.managed))
	for k, v := range f.managed {
		out[k] = v
	}
	return out, nil
}

func (f *fakeReconcileRuntime) RemoveImage(_ context.Context, _ string) error {
	f.removeImageHits.Add(1)
	return nil
}

func (f *fakeReconcileRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	panic("unexpected Create on reconcile destroyed path")
}
func (f *fakeReconcileRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Start on reconcile destroyed path")
}
func (f *fakeReconcileRuntime) Stop(context.Context, string) error {
	panic("unexpected Stop on reconcile destroyed path")
}
func (f *fakeReconcileRuntime) Destroy(context.Context, *models.Sandbox) error {
	panic("unexpected Destroy on reconcile destroyed path: container is already gone")
}
func (f *fakeReconcileRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	panic("unexpected Resize on reconcile destroyed path")
}
func (f *fakeReconcileRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Inspect on reconcile destroyed path")
}
func (f *fakeReconcileRuntime) Ping(context.Context) error {
	panic("unexpected Ping on reconcile destroyed path")
}
func (f *fakeReconcileRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	panic("unexpected PushAllowedPorts on reconcile destroyed path")
}
func (f *fakeReconcileRuntime) ClearNetworkRules(string) error {
	return nil
}
func (f *fakeReconcileRuntime) ApplyNetworkBlockAll(string) error {
	return nil
}

// TestReconcileDestroyedRowFreesHostPort is the regression test required by
// pr-review.md §5: a destroyed sandbox must free its TCP host_port reservation
// on the very next Reconcile pass, not after some retention TTL. Pre-fix, the
// reconcile branch only Upserted status=destroyed and left exposed_ports rows
// behind; the partial unique index on host_port doesn't filter by sandbox
// status, so the slot was held forever and the [22000, 23000] pool drained
// over historical, not concurrent, usage.
func TestReconcileDestroyedRowFreesHostPort(t *testing.T) {
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mountsRoot := filepath.Join(t.TempDir(), "mounts")
	credDir := filepath.Join(t.TempDir(), "cred")
	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     mountsRoot,
		CredDir:     credDir,
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	// EnableCaddy=false makes every caddy call a no-op — sufficient because
	// gcZombieCaddyEntries already has dedicated coverage. The destroyed
	// branch's caddy calls are best-effort and tested against a fake there.
	caddyClient := caddy.New(config.Config{
		EnableCaddy:       false,
		HTTPClientTimeout: time.Second,
	})

	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)

	rt := &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{}}

	svc := &Service{
		cfg:      config.Config{},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:    st,
		docker:   rt,
		caddy:    caddyClient,
		mounts:   mgr,
		admitter: admitter,
	}

	const (
		sandboxID = "sb-doomed"
		image     = "ubuntu:22.04"
		hostPort  = 22500 // inside the default L4 pool [22000, 23000]
		container = 5432
	)

	// Seed: a started sandbox with one TCP exposure holding host_port=22500.
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           sandboxID,
		Image:        image,
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-doomed",
		ContainerIP:  "10.0.0.42",
		CPU:          1,
		MemoryMB:     512,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	res, err := st.TryReserveHostPort(ctx, sandboxID, container, hostPort, models.ExposedPortProtocolTCP, "", now)
	if err != nil {
		t.Fatalf("seed exposed port: %v", err)
	}
	if !res.Reserved {
		t.Fatalf("seed: host_port %d not reserved (existing=%+v)", hostPort, res.Existing)
	}
	admitter.Reserve(sandboxID, capacity.Request{CPU: 1, MemoryMB: 512})

	// rt.managed is empty — to Reconcile, the container is gone.
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Sandbox row must be gone. Pre-fix, this would have remained with
	// status=destroyed and held its host_port reservation indefinitely.
	if _, err := st.Get(ctx, sandboxID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sandbox row should be deleted, got err=%v", err)
	}

	// exposed_ports cascaded: a fresh sandbox can claim the same host_port.
	// Pre-fix this would land on the partial unique index and come back with
	// Reserved=false (or, if cascade ran but the sandboxes row stuck around,
	// would never be tried because the original sandbox still owned it).
	const successorID = "sb-successor"
	if err := st.Create(ctx, &models.Sandbox{
		ID:           successorID,
		Image:        image,
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		LastActiveAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create successor sandbox: %v", err)
	}
	probe, err := st.TryReserveHostPort(ctx, successorID, container, hostPort, models.ExposedPortProtocolTCP, "", time.Now().UTC())
	if err != nil {
		t.Fatalf("re-reserve host_port: %v", err)
	}
	if !probe.Reserved {
		t.Fatalf("host_port %d still held by stale row (existing=%+v) — destroyed-branch cascade did not run",
			hostPort, probe.Existing)
	}

	// Capacity admitter must have been released — the next sandbox should not
	// be billed for the doomed sandbox's reservation.
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("admitter not released: snapshot=%+v", snap)
	}

	// Image GC was attempted exactly once — no other sandbox referenced it.
	if got := rt.removeImageHits.Load(); got != 1 {
		t.Fatalf("RemoveImage hits = %d, want 1", got)
	}
}

// TestDestroyEventFreesHostPort covers the second cleanup path — the Docker
// /events stream's "destroy" action. Pre-fix, the event handler called
// markSandboxStopped which Upserted status=destroyed and left exposed_ports
// rows behind; the host_port reservation would then sit in the unique-index
// pool until the next reconcile tick (or forever, if SB_AUTO_RECONCILE=false
// or reconcile was failing). Post-fix, handleDestroyEvent deletes the row in
// the same handler call, matching DestroySandbox and the reconcile branch.
func TestDestroyEventFreesHostPort(t *testing.T) {
	ctx := context.Background()

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

	caddyClient := caddy.New(config.Config{
		EnableCaddy:       false,
		HTTPClientTimeout: time.Second,
	})
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)
	rt := &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{}}

	svc := &Service{
		cfg:      config.Config{},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:    st,
		docker:   rt,
		caddy:    caddyClient,
		mounts:   mgr,
		admitter: admitter,
	}

	const (
		sandboxID = "sb-event-doomed"
		image     = "ubuntu:22.04"
		hostPort  = 22501
		container = 6379
	)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           sandboxID,
		Image:        image,
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-event-doomed",
		ContainerIP:  "10.0.0.99",
		CPU:          1,
		MemoryMB:     512,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if res, err := st.TryReserveHostPort(ctx, sandboxID, container, hostPort, models.ExposedPortProtocolTCP, "", now); err != nil || !res.Reserved {
		t.Fatalf("seed exposed port: reserved=%v err=%v", res.Reserved, err)
	}
	admitter.Reserve(sandboxID, capacity.Request{CPU: 1, MemoryMB: 512})

	// Simulate `docker rm -f <container>` — the daemon emits a destroy event
	// for our managed container, which the event monitor would route to
	// handleDockerEvent. Bypass the stream and invoke the handler directly so
	// the test is hermetic.
	event := docker.DockerEvent{
		ContainerID: "ctr-event-doomed",
		SandboxID:   sandboxID,
		Action:      "destroy",
		Time:        time.Now().UTC(),
	}
	if err := svc.handleDockerEvent(ctx, event); err != nil {
		t.Fatalf("handleDockerEvent destroy: %v", err)
	}

	// Sandbox row deleted in the same handler call — no waiting for reconcile.
	if _, err := st.Get(ctx, sandboxID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sandbox row should be deleted by destroy event, got err=%v", err)
	}

	// host_port reusable. Pre-fix this would have failed: the row sat at
	// status=destroyed and the unique index doesn't filter on status.
	const successorID = "sb-event-successor"
	if err := st.Create(ctx, &models.Sandbox{
		ID:           successorID,
		Image:        image,
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		LastActiveAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create successor: %v", err)
	}
	probe, err := st.TryReserveHostPort(ctx, successorID, container, hostPort, models.ExposedPortProtocolTCP, "", time.Now().UTC())
	if err != nil {
		t.Fatalf("re-reserve host_port: %v", err)
	}
	if !probe.Reserved {
		t.Fatalf("host_port %d still held after destroy event (existing=%+v)", hostPort, probe.Existing)
	}

	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("admitter not released: %+v", snap)
	}
	if got := rt.removeImageHits.Load(); got != 1 {
		t.Fatalf("RemoveImage hits = %d, want 1", got)
	}
}

// TestDieEventDoesNotDeleteRow verifies the symmetry: die/stop/oom must
// preserve the sandbox row so a future Start can resurrect it. Only destroy
// is allowed to delete. A regression that funnelled die through the new
// delete path would silently lose all stopped sandboxes — this test exists
// to make that failure loud.
func TestDieEventDoesNotDeleteRow(t *testing.T) {
	ctx := context.Background()

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

	rt := &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	svc := &Service{
		cfg:    config.Config{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		docker: rt,
		caddy: caddy.New(config.Config{
			EnableCaddy:       false,
			HTTPClientTimeout: time.Second,
		}),
		mounts: mgr,
		admitter: capacity.New(
			capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
			capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
			nil,
		),
	}

	const sandboxID = "sb-stoppable"
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           sandboxID,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-stoppable",
		ContainerIP:  "10.0.0.7",
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: sandboxID,
		Action:    "die",
		ExitCode:  137,
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("handleDockerEvent die: %v", err)
	}

	got, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("die must preserve the row, got err=%v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("status after die: got %q, want %q", got.Status, models.SandboxStatusStopped)
	}
	if rt.removeImageHits.Load() != 0 {
		t.Fatalf("die must not GC image, got %d hits", rt.removeImageHits.Load())
	}
}
