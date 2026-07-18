package isolate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	rt "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The load-bearing property of the whole tier (plans/isolate-runtime.md §1):
// the driver is a Runtime, and deliberately NOT a ContainerRuntime — isolates
// never get an IP, so there is nothing for iptables to pin. If someone adds a
// network-rule method to the driver this test breaks the build conversation.
func TestDriverIsRuntimeButNotContainerRuntime(t *testing.T) {
	var r rt.Runtime = New(Config{}, nil)
	if _, ok := rt.AsContainerRuntime(r); ok {
		t.Fatal("isolate driver must not satisfy ContainerRuntime (host-mediated networking, §4)")
	}
}

// Phase-1 skeleton: every lifecycle method rejects with
// ErrRuntimeNotImplemented so a stray dispatch is an actionable 4xx, never a
// panic or a generic 500.
// The operations isolates genuinely do not support (V8 exposes no serialize-a-
// running-isolate API, so no snapshots; no image GC surface, no live resize)
// stay ErrRuntimeNotImplemented. Create/Start/Stop/Destroy became real in
// Phase 2 and are covered separately.
func TestUnsupportedMethodsReturnNotImplemented(t *testing.T) {
	d := New(Config{}, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{name: "create_snapshot", call: func() error {
			_, err := d.CreateSnapshot(ctx, "sb-1", "img")
			return err
		}},
		{name: "resize", call: func() error {
			return d.Resize(ctx, "sb-1", models.ResizeSandboxRequest{})
		}},
		{name: "remove_image", call: func() error { return d.RemoveImage(ctx, "img") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if !errors.Is(err, models.ErrRuntimeNotImplemented) {
				t.Fatalf("%s = %v, want ErrRuntimeNotImplemented", tc.name, err)
			}
		})
	}
}

// Create without a resolver wired is a configuration error, not a panic.
func TestCreateWithoutResolverErrors(t *testing.T) {
	d := New(Config{}, nil)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{ModuleRef: "x.js"}, "sb-1", "", nil)
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("Create w/o resolver = %v, want ErrRuntimeNotImplemented", err)
	}
}

func TestDestroyNilIsNoOp(t *testing.T) {
	d := New(Config{}, nil)
	if err := d.Destroy(context.Background(), nil); err != nil {
		t.Fatalf("Destroy(nil) = %v, want nil (Runtime contract)", err)
	}
}

func TestInspectUnknownReturnsNil(t *testing.T) {
	d := New(Config{}, nil)
	state, err := d.Inspect(context.Background(), "sb-missing")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if state != nil {
		t.Fatalf("Inspect unknown = %+v, want nil", state)
	}
}

// Reconcile calls ListManaged on every registered runtime; an empty (not
// nil-error) result is what lets restart reconcile terminal-ize stray isolate
// rows instead of wedging the sweep.
func TestListManagedEmpty(t *testing.T) {
	d := New(Config{}, nil)
	managed, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(managed) != 0 {
		t.Fatalf("ListManaged = %d entries, want 0", len(managed))
	}
}

func TestInspectAndListManagedSeeRegisteredState(t *testing.T) {
	d := New(Config{}, nil)
	want := &models.SandboxRuntimeState{SandboxID: "sb-1", Status: models.SandboxStatusStarted}
	d.mu.Lock()
	d.byID["sb-1"] = &sandboxRecord{state: want, groupKey: "acme"}
	d.mu.Unlock()

	state, err := d.Inspect(context.Background(), "sb-1")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if state != want {
		t.Fatalf("Inspect = %+v, want the registered state", state)
	}
	managed, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(managed) != 1 || managed["sb-1"] != want {
		t.Fatalf("ListManaged = %+v, want the registered state under sb-1", managed)
	}
}

func TestPing(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing_binary_errors", func(t *testing.T) {
		d := New(Config{WorkerdPath: filepath.Join(dir, "missing-workerd")}, nil)
		if err := d.Ping(context.Background()); err == nil {
			t.Fatal("expected error for missing workerd binary")
		}
	})

	t.Run("directory_errors", func(t *testing.T) {
		d := New(Config{WorkerdPath: dir}, nil)
		if err := d.Ping(context.Background()); err == nil {
			t.Fatal("expected error for directory workerd path")
		}
	})

	t.Run("existing_binary_ok", func(t *testing.T) {
		bin := filepath.Join(dir, "workerd")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		d := New(Config{WorkerdPath: bin}, nil)
		if err := d.Ping(context.Background()); err != nil {
			t.Fatalf("Ping = %v, want nil", err)
		}
	})
}

type stubResolver struct{}

func (stubResolver) Resolve(ctx context.Context, tenant, ref string) (*jsbundle.Bundle, error) {
	return jsbundle.BuildFromSource("m.js", "export default { async fetch(){ return new Response('x'); } };", "")
}

type stubPool struct{}

func (stubPool) Acquire(ctx context.Context) (GroupHost, bool) { return nil, false }

func TestSetters(t *testing.T) {
	d := New(Config{}, nil)
	d.SetBundleResolver(stubResolver{})
	if d.resolver == nil {
		t.Fatal("SetBundleResolver did not wire the resolver")
	}
	d.SetWarmPool(stubPool{})
	if d.warmPool == nil {
		t.Fatal("SetWarmPool did not wire the pool")
	}
	d.SetHostSupervisor(&fakeSupervisor{})
	if d.supervisor == nil {
		t.Fatal("SetHostSupervisor did not wire the supervisor")
	}
}

// --- Phase-2 group-router + create fakes ---------------------------------

// fakeGroupHost records loads/unloads without a real workerd process.
type fakeGroupHost struct {
	mu      sync.Mutex
	loaded  map[string]bool
	stopped bool
	loadErr error
}

func newFakeGroupHost() *fakeGroupHost { return &fakeGroupHost{loaded: map[string]bool{}} }

func (h *fakeGroupHost) Load(id string, b *jsbundle.Bundle) error {
	if h.loadErr != nil {
		return h.loadErr
	}
	h.mu.Lock()
	h.loaded[id] = true
	h.mu.Unlock()
	return nil
}
func (h *fakeGroupHost) Unload(id string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.loaded, id)
	return len(h.loaded)
}
func (h *fakeGroupHost) LoadedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.loaded)
}
func (h *fakeGroupHost) Invoke(ctx context.Context, id string, r *http.Request) (*http.Response, error) {
	return nil, errors.New("fake: no invoke")
}
func (h *fakeGroupHost) Stop() error {
	h.mu.Lock()
	h.stopped = true
	h.mu.Unlock()
	return nil
}

// fakeSupervisor hands out fakeGroupHosts and counts spawns so the group
// router's single-flight and last-member teardown are observable.
type fakeSupervisor struct {
	mu       sync.Mutex
	spawns   int
	hosts    []*fakeGroupHost
	spawnErr error
	block    chan struct{} // if non-nil, SpawnGroup waits on it (single-flight test)
}

func (s *fakeSupervisor) SpawnGroup(ctx context.Context, spec JailSpec) (GroupHost, error) {
	if s.block != nil {
		<-s.block
	}
	if s.spawnErr != nil {
		return nil, s.spawnErr
	}
	h := newFakeGroupHost()
	s.mu.Lock()
	s.spawns++
	s.hosts = append(s.hosts, h)
	s.mu.Unlock()
	return h, nil
}

func (s *fakeSupervisor) spawnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spawns
}

func newCreateDriver(t *testing.T, granularity string, sup *fakeSupervisor) *Driver {
	t.Helper()
	d := New(Config{GroupGranularity: granularity, JailUID: 1000, JailGID: 1000, JailChrootBase: "/srv/jail"}, nil)
	d.SetBundleResolver(stubResolver{})
	d.SetHostSupervisor(sup)
	return d
}

func TestCreateRoutesToGroupAndLoads(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()

	// Two sandboxes for the same tenant share ONE group process.
	for _, id := range []string{"sb-1", "sb-2"} {
		st, err := d.Create(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "a.js", TenantID: "acme"}, id, "", nil)
		if err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
		if st.Status != models.SandboxStatusStarted || st.SandboxID != id {
			t.Fatalf("state = %+v", st)
		}
		if st.ModuleDigest == "" {
			t.Fatal("state missing bundle digest")
		}
	}
	if sup.spawnCount() != 1 {
		t.Fatalf("spawned %d group processes for one tenant, want 1", sup.spawnCount())
	}
	if got := sup.hosts[0].LoadedCount(); got != 2 {
		t.Fatalf("group has %d loaded, want 2", got)
	}

	// A different tenant gets its OWN process (isolation boundary).
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "a.js", TenantID: "other"}, "sb-3", "", nil); err != nil {
		t.Fatal(err)
	}
	if sup.spawnCount() != 2 {
		t.Fatalf("spawned %d, want 2 (per-tenant isolation)", sup.spawnCount())
	}
}

func TestCreatePerSandboxGranularity(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerSandbox, sup)
	ctx := context.Background()
	for _, id := range []string{"sb-1", "sb-2"} {
		if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, id, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	// Per-sandbox: each sandbox is its own process even within one tenant.
	if sup.spawnCount() != 2 {
		t.Fatalf("per-sandbox spawned %d, want 2", sup.spawnCount())
	}
}

func TestCreateSingleFlightsGroupSpawn(t *testing.T) {
	sup := &fakeSupervisor{block: make(chan struct{})}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()

	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			_, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, fmt.Sprintf("sb-%d", i), "", nil)
			errs <- err
		}(i)
	}
	// Let all goroutines reach the single-flight barrier, then release the spawn.
	time.Sleep(50 * time.Millisecond)
	close(sup.block)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent create: %v", err)
		}
	}
	if sup.spawnCount() != 1 {
		t.Fatalf("concurrent first-creates spawned %d processes, want 1 (single-flight)", sup.spawnCount())
	}
	if got := sup.hosts[0].LoadedCount(); got != n {
		t.Fatalf("group loaded %d, want %d", got, n)
	}
}

func TestDestroyLastMemberTearsGroupDown(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	for _, id := range []string{"sb-1", "sb-2"} {
		if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, id, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	host := sup.hosts[0]

	// Destroy the first: group stays up (sb-2 still resident).
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	if host.stopped {
		t.Fatal("group stopped while sb-2 still resident")
	}
	// Destroy the last: group process is torn down.
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-2"}); err != nil {
		t.Fatal(err)
	}
	if !host.stopped {
		t.Fatal("group not stopped after last member left")
	}
	// A fresh create for the tenant spawns a NEW process (old group removed).
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-3", "", nil); err != nil {
		t.Fatal(err)
	}
	if sup.spawnCount() != 2 {
		t.Fatalf("post-teardown spawns = %d, want 2", sup.spawnCount())
	}
}

// A load failure on a freshly-spawned group must reap that group's process —
// otherwise a failed first-create leaks an empty workerd (§11 empty-group rule).
func TestCreateLoadFailureReapsSpawnedGroup(t *testing.T) {
	lfs := &loadFailSupervisor{}
	d := New(Config{GroupGranularity: GroupPerTenant, JailUID: 1000, JailGID: 1000, JailChrootBase: "/srv/jail"}, nil)
	d.SetBundleResolver(stubResolver{})
	d.SetHostSupervisor(lfs)

	_, err := d.Create(context.Background(), models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil)
	if err == nil {
		t.Fatal("Create should fail when Load fails")
	}
	if !lfs.host.stopped {
		t.Fatal("spawned group not reaped after load failure (empty-group leak)")
	}
	// The router must not retain the failed group.
	d.groupsMu.Lock()
	n := len(d.groups)
	d.groupsMu.Unlock()
	if n != 0 {
		t.Fatalf("router retains %d groups after load failure, want 0", n)
	}
}

type loadFailSupervisor struct{ host *fakeGroupHost }

func (s *loadFailSupervisor) SpawnGroup(ctx context.Context, spec JailSpec) (GroupHost, error) {
	s.host = newFakeGroupHost()
	s.host.loadErr = errors.New("fake load failure")
	return s.host, nil
}

func TestStartStopTransitions(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Stop(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	st, _ := d.Inspect(ctx, "sb-1")
	if st.Status != models.SandboxStatusStopped {
		t.Fatalf("after Stop status = %s, want stopped", st.Status)
	}
	st2, err := d.Start(ctx, "sb-1")
	if err != nil || st2.Status != models.SandboxStatusStarted {
		t.Fatalf("after Start = %+v err=%v", st2, err)
	}
	// Unknown ids: Start → nil,nil; Stop → nil.
	if got, err := d.Start(ctx, "sb-missing"); got != nil || err != nil {
		t.Fatalf("Start(missing) = %+v, %v", got, err)
	}
	if err := d.Stop(ctx, "sb-missing"); err != nil {
		t.Fatalf("Stop(missing) = %v", err)
	}
}

// TestBundleResolverAdapter covers the jsbundle→seam adapter end to end.
func TestBundleResolverAdapter(t *testing.T) {
	store, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := jsbundle.BuildFromSource("m.js", "export default { async fetch(){ return new Response('y'); } };", "")
	digest, _ := store.Put("acme", "hook", b)

	r := NewBundleResolver(jsbundle.NewResolver(store))
	got, err := r.Resolve(context.Background(), "acme", "hook")
	if err != nil || got.Digest != digest {
		t.Fatalf("adapter Resolve = %+v err=%v", got, err)
	}
}

// TestHostSupervisorSpawnError covers the production supervisor's construction
// and its failure path (a missing workerd binary fails the host Start). The
// success path needs a real workerd and is integration-covered.
func TestHostSupervisorSpawnError(t *testing.T) {
	sup := NewHostSupervisor(Config{WorkerdPath: filepath.Join(t.TempDir(), "no-workerd"), RunDir: shortRunDirDriver(t)})
	spec, err := BuildJailSpec(Config{JailChrootBase: "/srv/jail", JailUID: 1000, JailGID: 1000}, "acme", 1, 128)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sup.SpawnGroup(context.Background(), spec); err == nil {
		t.Fatal("SpawnGroup with missing workerd should fail")
	}
}

// shortRunDirDriver mirrors pkg/isolate's short-path helper for the unix-socket
// sun_path limit on macOS.
func shortRunDirDriver(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "isod")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestFromDaemonConfig(t *testing.T) {
	cfg := config.Config{
		IsolateWorkerdPath:      "/opt/workerd",
		IsolateRunDir:           "/run/iso",
		IsolateGroupGranularity: config.IsolateGroupPerSandbox,
		IsolateUseJail:          true,
		IsolateJailChrootBase:   "/srv/jail",
		IsolateJailUID:          1234,
		IsolateJailGID:          1235,
		IsolateJitless:          true,
	}
	got := FromDaemonConfig(cfg)
	want := Config{
		WorkerdPath:      "/opt/workerd",
		RunDir:           "/run/iso",
		GroupGranularity: GroupPerSandbox,
		UseJail:          true,
		JailChrootBase:   "/srv/jail",
		JailUID:          1234,
		JailGID:          1235,
		Jitless:          true,
	}
	if got != want {
		t.Fatalf("FromDaemonConfig = %+v, want %+v", got, want)
	}
}
