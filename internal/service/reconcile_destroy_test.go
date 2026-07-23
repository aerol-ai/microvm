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
	managed map[string]*models.SandboxRuntimeState
	// inspect backs the reconcile guard's targeted re-Inspect (a container the
	// bulk ListManaged snapshot missed). Keyed by runtime ref; a ref absent
	// here returns a not-found error, i.e. "container is durably gone".
	inspect               map[string]*models.SandboxRuntimeState
	removeImageHits       atomic.Int32
	networkBlockAllCalls  []string
	allowPushAllowedPorts bool
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
func (f *fakeReconcileRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	panic("unexpected CreateSnapshot on reconcile destroyed path")
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
func (f *fakeReconcileRuntime) Inspect(_ context.Context, ref string) (*models.SandboxRuntimeState, error) {
	if st, ok := f.inspect[ref]; ok {
		return st, nil
	}
	return nil, errors.New("container not found")
}
func (f *fakeReconcileRuntime) Ping(context.Context) error {
	panic("unexpected Ping on reconcile destroyed path")
}
func (f *fakeReconcileRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	if !f.allowPushAllowedPorts {
		panic("unexpected PushAllowedPorts on reconcile destroyed path")
	}
	return nil
}
func (f *fakeReconcileRuntime) ClearNetworkRules(string) error {
	return nil
}
func (f *fakeReconcileRuntime) ApplyEgressPolicy(string, []string, []string) error { return nil }
func (f *fakeReconcileRuntime) ClearEgressPolicy(string, []string, []string) error { return nil }
func (f *fakeReconcileRuntime) ApplyNetworkBlockAll(containerIP string) error {
	f.networkBlockAllCalls = append(f.networkBlockAllCalls, containerIP)
	return nil
}
func (f *fakeReconcileRuntime) ApplyNetworkBlockIngress(string) error {
	return nil
}
func (f *fakeReconcileRuntime) ClearNetworkBlockIngress(string) error {
	return nil
}
func (f *fakeReconcileRuntime) ClearNetworkBlockEgress(string) error {
	return nil
}

func TestReconcileReappliesNetworkBlockAllWithCurrentContainerIP(t *testing.T) {
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
	rt := &fakeReconcileRuntime{
		allowPushAllowedPorts: true,
		managed: map[string]*models.SandboxRuntimeState{
			"sb-blocked": {
				SandboxID:   "sb-blocked",
				ContainerID: "ctr-current",
				ContainerIP: "10.0.0.42",
				Status:      models.SandboxStatusStarted,
			},
		},
	}
	svc := &Service{
		// schedulePendingImageGC checks ImageBuildGCEnabled — leave it on
		// so the destroy branches produce the expected ledger rows.
		cfg:    config.Config{ImageBuildGCEnabled: true},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		docker: rt,
		caddy:  caddyClient,
		mounts: mgr,
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:              "sb-blocked",
		Image:           "ubuntu:22.04",
		Status:          models.SandboxStatusStarted,
		ContainerID:     "ctr-stale",
		ContainerIP:     "10.0.0.7",
		CPU:             1,
		MemoryMB:        512,
		Runtime:         models.RuntimeDocker,
		NetworkBlockAll: true,
		CreatedAt:       now,
		UpdatedAt:       now,
		LastActiveAt:    now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if got, want := rt.networkBlockAllCalls, []string{"10.0.0.42"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("ApplyNetworkBlockAll calls = %v, want %v", got, want)
	}
	refreshed, err := st.Get(ctx, "sb-blocked")
	if err != nil {
		t.Fatalf("Get refreshed sandbox: %v", err)
	}
	if refreshed.ContainerID != "ctr-current" || refreshed.ContainerIP != "10.0.0.42" {
		t.Fatalf("reconcile did not persist current runtime identity: id=%q ip=%q", refreshed.ContainerID, refreshed.ContainerIP)
	}
	if !refreshed.NetworkBlockAll {
		t.Fatal("NetworkBlockAll flag was lost during reconcile")
	}
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
		// Reconcile's destroyed-branch goes through schedulePendingImageGC,
		// which checks ImageBuildGCEnabled before writing the ledger row.
		cfg:      config.Config{ImageBuildGCEnabled: true},
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
	// rt.managed is empty and rt.inspect has no entry, so the reconcile guard's
	// re-Inspect returns "container not found" → durably gone → reaped.
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

	// Image GC was scheduled, not executed inline: the destroy path now
	// records the image in pending_image_gc for the janitor to sweep
	// after ImageBuildGCTTL. The successor created above with the same
	// image is exactly the case the deferral protects — yanking the
	// image inline would have forced a re-pull on every destroy/recreate
	// cycle.
	if got := rt.removeImageHits.Load(); got != 0 {
		t.Fatalf("RemoveImage must NOT be called inline, hits = %d", got)
	}
	due, err := st.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue: %v", err)
	}
	if len(due) != 1 || due[0].Image != image {
		t.Fatalf("expected pending_image_gc to contain %q, got %v", image, due)
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
		// Reconcile's destroyed-branch goes through schedulePendingImageGC,
		// which checks ImageBuildGCEnabled before writing the ledger row.
		cfg:      config.Config{ImageBuildGCEnabled: true},
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
	// Image scheduled for deferred GC, not removed inline (see the
	// reconcile-branch test above for the rationale).
	if got := rt.removeImageHits.Load(); got != 0 {
		t.Fatalf("RemoveImage must NOT be called inline, hits = %d", got)
	}
	due, err := st.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue: %v", err)
	}
	if len(due) != 1 || due[0].Image != image {
		t.Fatalf("expected pending_image_gc to contain %q, got %v", image, due)
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
		// schedulePendingImageGC checks ImageBuildGCEnabled — leave it on
		// so the destroy branches produce the expected ledger rows.
		cfg:    config.Config{ImageBuildGCEnabled: true},
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

// TestReconcileReInspectsBeforeReap is the UC-20 regression. The reconcile
// "container gone" branch reaps a row (and, in cluster mode, its FSM placement)
// when the sandbox ID is absent from the bulk ListManaged snapshot. That
// snapshot is one racy read per tick whose per-container Inspect silently skips
// a container it can't read at that instant (mid-adopt/mid-start). Pre-fix the
// reap fired on that single miss, deleting a healthy sandbox's row and surfacing
// as an intermittent cross-node snapshot 404. Post-fix a targeted re-Inspect
// that still resolves the container spares the row; a genuinely-gone container
// (Inspect error / empty identity) is still reaped.
func TestReconcileReInspectsBeforeReap(t *testing.T) {
	newSvc := func(rt *fakeReconcileRuntime) (*Service, *store.Store) {
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
		svc := &Service{
			cfg:    config.Config{ImageBuildGCEnabled: true},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			store:  st,
			docker: rt,
			caddy: caddy.New(config.Config{
				EnableCaddy:       false,
				HTTPClientTimeout: time.Second,
			}),
			mounts: mgr,
		}
		return svc, st
	}

	seed := func(st *store.Store, id string) {
		now := time.Now().UTC()
		if err := st.Create(context.Background(), &models.Sandbox{
			ID:           id,
			Image:        "ubuntu:22.04",
			Status:       models.SandboxStatusStarted,
			ContainerID:  "ctr-" + id,
			ContainerIP:  "10.0.0.5",
			Runtime:      models.RuntimeDocker,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	ctx := context.Background()

	// Bulk snapshot missed it, but a targeted re-Inspect resolves the container
	// (non-empty runtime identity) — the exact UC-20 race. Must NOT be reaped.
	t.Run("re-inspect resolves container -> spared", func(t *testing.T) {
		rt := &fakeReconcileRuntime{
			managed: map[string]*models.SandboxRuntimeState{},
			inspect: map[string]*models.SandboxRuntimeState{
				"ctr-sb-settling": {SandboxID: "sb-settling", ContainerID: "ctr-sb-settling", Status: models.SandboxStatusStarted},
			},
		}
		svc, st := newSvc(rt)
		seed(st, "sb-settling")
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if _, err := st.Get(ctx, "sb-settling"); err != nil {
			t.Fatalf("sandbox with a re-inspectable container was reaped on a stale bulk snapshot: %v", err)
		}
	})

	// Absent from ListManaged AND re-Inspect returns not-found: durably gone,
	// cleanup must still run so orphan rows don't accumulate.
	t.Run("re-inspect not-found -> reaped", func(t *testing.T) {
		rt := &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{}}
		svc, st := newSvc(rt)
		seed(st, "sb-dead")
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if _, err := st.Get(ctx, "sb-dead"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("durably-gone sandbox should be reaped, got err=%v", err)
		}
	})
}
