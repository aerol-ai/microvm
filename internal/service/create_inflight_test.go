package service

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// gatedCreateRuntime holds a create inside the runtime, with its instance
// already listed and no row written yet, until released: the window in which
// reconcile's orphan sweep destroyed it (live UC-37 on cluster-3-mixed: "start
// task: OCI runtime start failed: cannot start a container that has
// stopped").
type gatedCreateRuntime struct {
	*recordingRuntime
	mu        sync.Mutex
	live      map[string]*models.SandboxRuntimeState
	destroyed []string
	entered   chan string
	release   chan struct{}
	// listHook runs inside ListManaged, after reconcile has read its rows.
	listHook func()
}

func newGatedCreateRuntime() *gatedCreateRuntime {
	return &gatedCreateRuntime{
		recordingRuntime: &recordingRuntime{},
		live:             map[string]*models.SandboxRuntimeState{},
		entered:          make(chan string, 1),
		release:          make(chan struct{}),
	}
}

func (g *gatedCreateRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	state := &models.SandboxRuntimeState{SandboxID: id, ContainerID: "ctr-" + id, ContainerIP: "10.0.0.2", Status: models.SandboxStatusStarted}
	g.mu.Lock()
	g.live[id] = state
	g.mu.Unlock()
	g.entered <- id
	<-g.release
	return state, nil
}

func (g *gatedCreateRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	if g.listHook != nil {
		g.listHook()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]*models.SandboxRuntimeState, len(g.live))
	for id, st := range g.live {
		c := *st
		out[id] = &c
	}
	return out, nil
}

func (g *gatedCreateRuntime) Inspect(_ context.Context, ref string) (*models.SandboxRuntimeState, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, st := range g.live {
		if st.ContainerID == ref || st.SandboxID == ref {
			c := *st
			return &c, nil
		}
	}
	return &models.SandboxRuntimeState{}, nil
}

func (g *gatedCreateRuntime) Destroy(_ context.Context, sb *models.Sandbox) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if sb != nil {
		g.destroyed = append(g.destroyed, sb.ID)
		delete(g.live, sb.ID)
	}
	return nil
}

func (g *gatedCreateRuntime) destroyedIDs() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.destroyed)
}

// TestReconcileDoesNotDestroyACreateInFlight: reconcile runs while a create's
// container is up and its row isn't written yet. The sweep leaves it, the
// create completes, and the next sweep still leaves it (its row is there).
func TestReconcileDoesNotDestroyACreateInFlight(t *testing.T) {
	rt := newGatedCreateRuntime()
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	ctx := context.Background()

	type result struct {
		resp *models.CreateSandboxResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine"})
		done <- result{resp, err}
	}()
	var id string
	select {
	case id = <-rt.entered:
	case r := <-done:
		t.Fatalf("create returned before reaching the runtime: %v", r.err)
	case <-time.After(10 * time.Second):
		t.Fatal("create never reached the runtime")
	}
	if !svc.createsInFlight.running(id) {
		t.Fatal("a create inside the runtime must be registered")
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rt.destroyedIDs(); slices.Contains(got, id) {
		t.Fatalf("reconcile destroyed a create in flight: %v", got)
	}

	close(rt.release)
	r := <-done
	if r.err != nil {
		t.Fatalf("the create must complete: %v", r.err)
	}
	if svc.createsInFlight.running(id) {
		t.Fatal("a returned create must release its registration")
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rt.destroyedIDs(); slices.Contains(got, id) {
		t.Fatalf("reconcile destroyed a created sandbox: %v", got)
	}
}

// TestReconcileRechecksTheRowBeforeRemovingAnOrphan: a create that wrote its
// row after reconcile's row snapshot (here, while reconcile lists the
// runtime) is not an orphan; a runtime instance with no row and no create
// still is.
func TestReconcileRechecksTheRowBeforeRemovingAnOrphan(t *testing.T) {
	rt := newGatedCreateRuntime()
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	ctx := context.Background()
	now := time.Now().UTC()
	late := &models.Sandbox{ID: "sb-late", Image: "alpine", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-sb-late", ContainerIP: "10.0.0.3", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	rt.live["sb-late"] = &models.SandboxRuntimeState{SandboxID: "sb-late", ContainerID: "ctr-sb-late", ContainerIP: "10.0.0.3", Status: models.SandboxStatusStarted}
	rt.live["sb-leak"] = &models.SandboxRuntimeState{SandboxID: "sb-leak", ContainerID: "ctr-sb-leak", ContainerIP: "10.0.0.4", Status: models.SandboxStatusStarted}
	rt.listHook = func() {
		rt.listHook = nil
		if err := st.Create(ctx, late); err != nil {
			t.Error(err)
		}
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	got := rt.destroyedIDs()
	if slices.Contains(got, "sb-late") {
		t.Fatalf("a sandbox whose row came after the snapshot was destroyed: %v", got)
	}
	if !slices.Contains(got, "sb-leak") {
		t.Fatalf("a runtime instance with no row and no create must still go: %v", got)
	}
}

// TestOrphanRecheckFailureKeepsTheInstance: a row lookup that fails is not
// evidence of an orphan.
func TestOrphanRecheckFailureKeepsTheInstance(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if !svc.confirmedOrphan(context.Background(), "sb-none") {
		t.Fatal("no row and no create is an orphan")
	}
	_ = st.Close()
	if svc.confirmedOrphan(context.Background(), "sb-none") {
		t.Fatal("a failed lookup must not confirm an orphan")
	}
}

func TestCreatesInFlightCountsAndMatchesRoutes(t *testing.T) {
	var c createsInFlight
	if c.running("a") || c.ownsRoute("sandbox-a") {
		t.Fatal("nothing is running yet")
	}
	r1, r2 := c.begin("a"), c.begin("a")
	r1()
	r1() // a second release of the same registration is a no-op
	if !c.running("a") {
		t.Fatal("a second create of the same id still holds it")
	}
	for route, want := range map[string]bool{
		"sandbox-a": true, "sandbox-a-port-80": true, "sandbox-a-port-80-wake": true,
		"sandbox-ab": false, "sandbox-ab-port-80": false, "sandbox-": false, "a": false, "tcp-port-80": false,
	} {
		if got := c.ownsRoute(route); got != want {
			t.Errorf("ownsRoute(%q) = %v, want %v", route, got, want)
		}
	}
	r2()
	if c.running("a") || c.ownsRoute("sandbox-a") {
		t.Fatal("released once both creates returned")
	}
}

// TestZombieRouteSweepKeepsNewRoutes: the route sweep keeps a route whose
// sandbox's row was written after the caller read its rows, and one a create
// in flight installed before its row; a real zombie still goes.
func TestZombieRouteSweepKeepsNewRoutes(t *testing.T) {
	fake := newGCCaddyFake()
	fake.httpRouteIDs["sandbox-late"] = struct{}{}
	fake.httpRouteIDs["sandbox-late-port-3000"] = struct{}{}
	fake.httpRouteIDs["sandbox-creating"] = struct{}{}
	fake.l4TLSRouteIDs["sandbox-creating-port-6379-tls"] = struct{}{}
	fake.httpRouteIDs["sandbox-ghost"] = struct{}{}
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.caddy = caddy.New(config.Config{CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true, HTTPClientTimeout: 5 * time.Second})
	now := time.Now().UTC()
	public := true
	if err := st.Create(context.Background(), &models.Sandbox{ID: "late", Image: "alpine", Status: models.SandboxStatusStarted,
		AllowPublicTraffic: &public, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(context.Background(), models.ExposedPort{SandboxID: "late", Port: 3000, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	release := svc.createsInFlight.begin("creating")
	defer release()

	// The caller's rows predate both "late" and "creating".
	svc.gcZombieCaddyEntries(context.Background(), nil)
	if got := fake.keys(fake.httpRouteIDs); !equalSorted(got, []string{"sandbox-creating", "sandbox-late", "sandbox-late-port-3000"}) {
		t.Fatalf("http routes after gc = %v", got)
	}
	if got := fake.keys(fake.l4TLSRouteIDs); !equalSorted(got, []string{"sandbox-creating-port-6379-tls"}) {
		t.Fatalf("tls routes after gc = %v", got)
	}
}
