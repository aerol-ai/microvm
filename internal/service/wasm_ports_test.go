package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
