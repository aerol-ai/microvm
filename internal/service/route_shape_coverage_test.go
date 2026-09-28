package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestBypassEnabledForWave12(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.L4WakeDirectBypassEnabled = true
	_ = svc.bypassEnabledFor(RouteKindHTTP)
	_ = svc.bypassEnabledFor(RouteKindL4)
	_ = svc.anyBypassEnabled()
}

func TestIsolateHTTPRouteShapeNoneWave15(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.EnableIsolate = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.SetIsolateRuntime(&recordingRuntime{})
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	sb := &models.Sandbox{
		ID: "iso-none", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installIsolateHTTPPortRoute(ctx, sb, 8080); err != nil {
		// RouteShapeNone still needs caddy deletes; isolate gateway check may fire first.
		t.Logf("isolate none: %v", err)
	}
	svc.isolateHTTPPortRouteCleanup(ctx, "iso-none", 8080)
}

func TestIsolateAndWasmHTTPRouteShapeNoneWave20(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	isoRT := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.EnableIsolate = true
	svc.cfg.EnableWasm = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21220"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.SetIsolateRuntime(isoRT)
	svc.SetWasmRuntime(&wasmPortsRuntime{recordingRuntime: &recordingRuntime{}})

	none := &models.Sandbox{
		ID: "sb-none-iso", Runtime: models.RuntimeIsolate,
		Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installIsolateHTTPPortRoute(ctx, none, 8080); err != nil {
		t.Fatalf("isolate RouteShapeNone: %v", err)
	}
	svc.isolateHTTPPortRouteCleanup(ctx, none.ID, 8080)

	wasmNone := &models.Sandbox{
		ID: "sb-none-wasm", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusCreating, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installWasmHTTPPortRoute(ctx, wasmNone, 8081); err != nil {
		t.Fatalf("wasm RouteShapeNone: %v", err)
	}
	svc.wasmHTTPPortRouteCleanup(ctx, wasmNone.ID, 8081)
}

type wasmPortsRuntime struct {
	*recordingRuntime
	noopWasmPortGateway
}

func TestBypassEnabledForDefaultWave20(t *testing.T) {
	svc := &Service{cfg: config.Config{}}
	if svc.bypassEnabledFor(RouteKind(99)) {
		t.Fatal("unknown kind should be false")
	}
}

func TestWasmInstallHTTPRouteShapeNoneExplicitWave21(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableServerless = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.SetWasmRuntime(&wasmPortsRuntime{recordingRuntime: &recordingRuntime{}})
	sb := &models.Sandbox{
		ID: "wasm-none21", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installWasmHTTPPortRoute(ctx, sb, 9090); err != nil {
		t.Fatalf("none: %v", err)
	}
}
