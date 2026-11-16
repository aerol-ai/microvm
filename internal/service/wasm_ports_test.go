package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWasmExposePortHTTPUsesHostMediator(t *testing.T) {
	ctx := context.Background()
	driver := wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(driver)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-wasm-port",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeWasm,
		ContainerIP:  "127.0.0.1",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}

	resp1, err := svc.ExposePort(ctx, "sb-wasm-port", 8080, "http")
	if err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	resp2, err := svc.ExposePort(ctx, "sb-wasm-port", 8080, "http")
	if err != nil {
		t.Fatalf("ExposePort idempotent: %v", err)
	}
	if resp1.PublicURL != resp2.PublicURL {
		t.Fatalf("public URL changed on retry: %q vs %q", resp1.PublicURL, resp2.PublicURL)
	}

	url, err := svc.wasmHTTPUpstreamURL(ctx, "sb-wasm-port", 8080)
	if err != nil {
		t.Fatalf("wasmHTTPUpstreamURL: %v", err)
	}
	ep, err := svc.WakeAwarePortTarget(ctx, "sb-wasm-port", 8080)
	if err != nil {
		t.Fatalf("WakeAwarePortTarget: %v", err)
	}
	if ep.URL != url {
		t.Fatalf("upstream = %q want %q", ep.URL, url)
	}
}

// A WASM sandbox's ContainerIP is the host's loopback: a port probe there
// would dial whatever listens on that port on the host. expose_port must
// skip it.
func TestWasmExposePortDoesNotProbeTheHostPort(t *testing.T) {
	ctx := context.Background()
	driver := wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(driver)
	var probed []string
	svc.probeContainerPortFn = func(_ context.Context, ip string, port int) error {
		probed = append(probed, fmt.Sprintf("%s:%d", ip, port))
		return nil
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-noprobe", Status: models.SandboxStatusStarted, Runtime: models.RuntimeWasm,
		ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.ExposePort(ctx, "sb-wasm-noprobe", 2019, "http"); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if len(probed) != 0 {
		t.Fatalf("expose_port probed %v on a WASM sandbox, want no probe", probed)
	}
}

// portsRecordingWasmRuntime records the port sets the service pushes to a
// WASM sandbox's gateway and guest listeners.
type portsRecordingWasmRuntime struct {
	wasmModuleAPINoopRuntime
	noopWasmPortGateway
	mu      sync.Mutex
	allowed map[string][]int
	listen  map[string][]int
	syncing atomic.Int32
	overlap atomic.Bool
}

func newPortsRecordingWasmRuntime() *portsRecordingWasmRuntime {
	return &portsRecordingWasmRuntime{allowed: map[string][]int{}, listen: map[string][]int{}}
}

func (r *portsRecordingWasmRuntime) SyncAllowedPorts(id string, ports []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowed[id] = append([]int(nil), ports...)
}

func (r *portsRecordingWasmRuntime) SyncGuestListenPorts(_ context.Context, id string, ports []int) error {
	if r.syncing.Add(1) > 1 {
		r.overlap.Store(true)
	}
	defer r.syncing.Add(-1)
	// A listener sync re-instantiates the guest: give a racing one time
	// to overlap.
	time.Sleep(5 * time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listen[id] = append([]int(nil), ports...)
	return nil
}

func (r *portsRecordingWasmRuntime) last(id string) (allowed, listen []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	allowed = append([]int(nil), r.allowed[id]...)
	listen = append([]int(nil), r.listen[id]...)
	sort.Ints(allowed)
	sort.Ints(listen)
	return allowed, listen
}

// A sync from a row read before another expose stored its port must not
// shrink the set: the ports come from the store, read under the lock.
func TestSyncWasmAllowedPortsReadsTheStore(t *testing.T) {
	ctx := context.Background()
	rt := newPortsRecordingWasmRuntime()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-stale", Status: models.SandboxStatusStarted, Runtime: models.RuntimeWasm,
		ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, port := range []int{8080, 9090} {
		if _, err := svc.ExposePort(ctx, "sb-wasm-stale", port, "http"); err != nil {
			t.Fatalf("ExposePort %d: %v", port, err)
		}
	}
	stale := &models.Sandbox{ID: "sb-wasm-stale", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		ContainerIP: "127.0.0.1", ExposedPorts: []models.ExposedPort{{Port: 8080}}}
	svc.syncWasmAllowedPorts(ctx, stale)
	if allowed, listen := rt.last("sb-wasm-stale"); fmt.Sprint(allowed) != "[8080 9090]" || fmt.Sprint(listen) != "[8080 9090]" {
		t.Fatalf("after a stale sync: allowed %v, listen %v", allowed, listen)
	}
	// WASM exposes route through the gateway and never take a host port
	// from the TCP pool.
	rows, err := st.ListPorts(ctx, "sb-wasm-stale")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.HostPort != 0 {
			t.Fatalf("port %d took host port %d", row.Port, row.HostPort)
		}
	}
}

// Two exposes at once end with both ports allowed and listened on, and the
// guest's listeners are synced by one of them at a time.
func TestWasmConcurrentExposesRouteBothPorts(t *testing.T) {
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		rt := newPortsRecordingWasmRuntime()
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(rt)
		svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }
		id := fmt.Sprintf("sb-wasm-race-%d", round)
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID: id, Status: models.SandboxStatusStarted, Runtime: models.RuntimeWasm,
			ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatalf("create: %v", err)
		}
		var wg sync.WaitGroup
		urls := make([]string, 2)
		errs := make([]error, 2)
		for i, port := range []int{8080, 9090} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := svc.ExposePort(ctx, id, port, "http")
				urls[i], errs[i] = resp.PublicURL, err
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d expose %d: %v", round, i, err)
			}
		}
		if allowed, listen := rt.last(id); fmt.Sprint(allowed) != "[8080 9090]" || fmt.Sprint(listen) != "[8080 9090]" {
			t.Fatalf("round %d: allowed %v, listen %v", round, allowed, listen)
		}
		if rt.overlap.Load() {
			t.Fatalf("round %d: two listener syncs ran at once", round)
		}
		// Re-expose is idempotent: the same URL.
		again, err := svc.ExposePort(ctx, id, 9090, "http")
		if err != nil || again.PublicURL != urls[1] {
			t.Fatalf("round %d: re-expose = %q, %v; first %q", round, again.PublicURL, err, urls[1])
		}
	}
}

// A store read that fails pushes nothing rather than a stale set.
func TestSyncWasmAllowedPortsStoreError(t *testing.T) {
	rt := newPortsRecordingWasmRuntime()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.SetWasmRuntime(rt)
	_ = st.Close()
	svc.syncWasmAllowedPorts(context.Background(), &models.Sandbox{ID: "sb-closed", Runtime: models.RuntimeWasm,
		ExposedPorts: []models.ExposedPort{{Port: 8080}}})
	if allowed, listen := rt.last("sb-closed"); len(allowed) != 0 || len(listen) != 0 {
		t.Fatalf("pushed allowed %v, listen %v after a failed read", allowed, listen)
	}
}

func TestWasmExposePortRejectsTCP(t *testing.T) {
	ctx := context.Background()
	driver := wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(driver)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-tcp", Status: models.SandboxStatusStarted, Runtime: models.RuntimeWasm,
		ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err := svc.ExposePort(ctx, "sb-wasm-tcp", 5432, "tcp")
	if err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("expected tcp rejection, got %v", err)
	}
}

func TestInstallWasmHTTPPortRoute(t *testing.T) {
	ctx := context.Background()
	driver := wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(driver)

	now := time.Now().UTC()
	sb1 := &models.Sandbox{
		ID:         "sb-wasm-route-1",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityEphemeral,
		CreatedAt:  now, UpdatedAt: now,
	}
	_ = st.Create(ctx, sb1)

	// Test RouteShapeDirect
	err := svc.installWasmHTTPPortRoute(ctx, sb1, 8080)
	if err != nil {
		t.Fatalf("installWasmHTTPPortRoute Direct failed: %v", err)
	}

	// Test RouteShapeWake
	sb2 := &models.Sandbox{
		ID:         "sb-wasm-route-2",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityPassivatable,
		CreatedAt:  now, UpdatedAt: now,
	}
	_ = st.Create(ctx, sb2)
	err = svc.installWasmHTTPPortRoute(ctx, sb2, 8081)
	if err != nil {
		t.Fatalf("installWasmHTTPPortRoute Wake failed: %v", err)
	}

	// Test RouteShapeNone
	sb3 := &models.Sandbox{
		ID:         "sb-wasm-route-3",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStopped,
		Durability: models.DurabilityEphemeral,
		CreatedAt:  now, UpdatedAt: now,
	}
	_ = st.Create(ctx, sb3)
	err = svc.installWasmHTTPPortRoute(ctx, sb3, 8082)
	if err != nil {
		t.Fatalf("installWasmHTTPPortRoute None failed: %v", err)
	}
}

func TestWasmHTTPPortRouteCleanup(t *testing.T) {
	ctx := context.Background()
	driver := wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(driver)

	// Since we mock caddy, we just verify it doesn't panic and returns without error
	svc.wasmHTTPPortRouteCleanup(ctx, "sb-clean", 8080)
}

func TestWasmHTTPDialErrorBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-wasm-dial",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeWasm,
		ContainerIP:  "127.0.0.1",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}

	if _, err := svc.wasmHTTPDial(ctx, "sb-wasm-dial", 8080); err == nil {
		t.Fatal("wasmHTTPDial should fail when the runtime driver is missing")
	}
	if _, err := svc.wasmHTTPUpstreamURL(ctx, "sb-wasm-dial", 8080); err == nil {
		t.Fatal("wasmHTTPUpstreamURL should fail when the runtime driver is missing")
	}
	if err := svc.installWasmHTTPPortRoute(ctx, &models.Sandbox{ID: "sb-wasm-dial", Runtime: models.RuntimeWasm}, 8080); err == nil {
		t.Fatal("installWasmHTTPPortRoute should fail when the runtime driver is missing")
	}

	svc.syncWasmAllowedPorts(ctx, nil)
	svc.syncWasmAllowedPorts(ctx, &models.Sandbox{
		ID:           "sb-wasm-dial",
		Runtime:      models.RuntimeWasm,
		ContainerIP:  "127.0.0.1",
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
	})
}

type wasmPortsSyncErrRuntime struct {
	wasmModuleAPINoopRuntime
	noopWasmPortGateway
	syncErr error
}

func (r wasmPortsSyncErrRuntime) SyncGuestListenPorts(context.Context, string, []int) error {
	return r.syncErr
}

func TestInstallWasmHTTPPortRouteEdgeBranches(t *testing.T) {
	ctx := context.Background()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			http.NotFound(w, r)
			return
		case http.MethodPut:
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	t.Run("direct route error", func(t *testing.T) {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.EnableServerless = true
		svc.cfg.HTTPWakeDirectBypassEnabled = true
		svc.cfg.Domain = "sandbox.example.com"
		svc.cfg.InternalIngressAddr = "127.0.0.1:1234"
		svc.caddy = caddy.New(config.Config{
			EnableCaddy:       true,
			Domain:            "sandbox.example.com",
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			HTTPClientTimeout: time.Second,
		})
		svc.SetWasmRuntime(wasmPortsSyncErrRuntime{})
		sandbox := &models.Sandbox{
			ID:          "sb-wasm-direct",
			Runtime:     models.RuntimeWasm,
			Status:      models.SandboxStatusStarted,
			ContainerIP: "127.0.0.1",
			Lifecycle:   models.Lifecycle{Serverless: true},
		}
		if err := svc.installWasmHTTPPortRoute(ctx, sandbox, 8080); err == nil {
			t.Fatal("expected direct route error")
		}
	})

	t.Run("wake route error", func(t *testing.T) {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.EnableServerless = true
		svc.cfg.HTTPWakeDirectBypassEnabled = false
		svc.cfg.Domain = "sandbox.example.com"
		svc.cfg.InternalIngressAddr = "127.0.0.1:1234"
		svc.caddy = caddy.New(config.Config{
			EnableCaddy:       true,
			Domain:            "sandbox.example.com",
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			HTTPClientTimeout: time.Second,
		})
		svc.SetWasmRuntime(wasmPortsSyncErrRuntime{})
		sandbox := &models.Sandbox{
			ID:        "sb-wasm-wake",
			Runtime:   models.RuntimeWasm,
			Status:    models.SandboxStatusStopped,
			WakeArmed: true,
			Lifecycle: models.Lifecycle{Serverless: true},
		}
		if err := svc.installWasmHTTPPortRoute(ctx, sandbox, 8081); err == nil {
			t.Fatal("expected wake route error")
		}
	})

	t.Run("none route cleanup", func(t *testing.T) {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.EnableServerless = true
		svc.cfg.HTTPWakeDirectBypassEnabled = true
		svc.cfg.Domain = "sandbox.example.com"
		svc.caddy = caddy.New(config.Config{
			EnableCaddy:       true,
			Domain:            "sandbox.example.com",
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			HTTPClientTimeout: time.Second,
		})
		svc.SetWasmRuntime(wasmPortsSyncErrRuntime{})
		sandbox := &models.Sandbox{
			ID:        "sb-wasm-none",
			Runtime:   models.RuntimeWasm,
			Status:    models.SandboxStatusStarted,
			Lifecycle: models.Lifecycle{Serverless: true},
		}
		if err := svc.installWasmHTTPPortRoute(ctx, sandbox, 8082); err != nil {
			t.Fatalf("installWasmHTTPPortRoute none = %v", err)
		}
	})

	t.Run("guest port sync warning", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(wasmPortsSyncErrRuntime{syncErr: errors.New("sync failed")})
		svc.syncWasmAllowedPorts(ctx, &models.Sandbox{
			ID:           "sb-sync",
			Runtime:      models.RuntimeWasm,
			ContainerIP:  "127.0.0.1",
			ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		})
	})
}
