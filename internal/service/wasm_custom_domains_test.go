package service

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func newWasmCustomDomainsHarness(t *testing.T) (*Service, *routeAdminCaddyFake, func()) {
	t.Helper()
	driver := wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "aerol.cloud"
	svc.cfg.CustomDomainVerifyPrefix = "_aerol-verify"
	svc.cfg.CustomDomainVerifyValuePrefix = "aerol-verify="
	svc.cfg.ToolboxPort = 4321
	svc.SetWasmRuntime(driver)
	svc.dnsResolver = &mockDNSResolver{
		records: map[string][]string{
			"_aerol-verify.api.acme.com": {"aerol-verify=api.acme.com"},
		},
	}

	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.HTTPClientTimeout = time.Second
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:           "sb-wasm-cd",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeWasm,
		ContainerIP:  "127.0.0.1",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	return svc, fake, server.Close
}

func TestWasmAddCustomDomainTargetsExposedHTTPPort(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := newWasmCustomDomainsHarness(t)
	defer cleanup()

	if _, err := svc.ExposePort(ctx, "sb-wasm-cd", 8080, "http"); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	mediatorDial, err := svc.wasmHTTPDial(ctx, "sb-wasm-cd", 8080)
	if err != nil {
		t.Fatalf("wasmHTTPDial: %v", err)
	}

	if err := svc.AddCustomDomain(ctx, "sb-wasm-cd", "api.acme.com", 8080); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	sandbox, err := svc.store.Get(ctx, "sb-wasm-cd")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	dial, err := svc.wasmCustomDomainDial(ctx, sandbox, 8080)
	if err != nil {
		t.Fatalf("wasmCustomDomainDial: %v", err)
	}
	if dial != mediatorDial {
		t.Fatalf("dial = %q want mediator %q", dial, mediatorDial)
	}
}

func TestWasmAddCustomDomainToolboxPort(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := newWasmCustomDomainsHarness(t)
	defer cleanup()

	if err := svc.AddCustomDomain(ctx, "sb-wasm-cd", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	sandbox, err := svc.store.Get(ctx, "sb-wasm-cd")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	dial, err := svc.wasmCustomDomainDial(ctx, sandbox, 0)
	if err != nil {
		t.Fatalf("wasmCustomDomainDial: %v", err)
	}
	if dial != "127.0.0.1:4321" {
		t.Fatalf("toolbox dial = %q", dial)
	}
}

func TestWasmCustomDomainReconcileOnExpose(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := newWasmCustomDomainsHarness(t)
	defer cleanup()

	if err := svc.AddCustomDomain(ctx, "sb-wasm-cd", "api.acme.com", 8080); err != nil {
		t.Fatalf("AddCustomDomain before expose: %v", err)
	}
	if _, err := svc.ExposePort(ctx, "sb-wasm-cd", 8080, "http"); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	sandbox, err := svc.store.Get(ctx, "sb-wasm-cd")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	dial, err := svc.wasmCustomDomainDial(ctx, sandbox, 8080)
	if err != nil {
		t.Fatalf("wasmCustomDomainDial after expose: %v", err)
	}
	if dial == "" || !strings.HasPrefix(dial, "127.0.0.1:") {
		t.Fatalf("expected loopback mediator dial, got %q", dial)
	}
}

func TestWasmCustomDomainRejectsUnexposedPort(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := newWasmCustomDomainsHarness(t)
	defer cleanup()

	if _, err := svc.ExposePort(ctx, "sb-wasm-cd", 8080, "http"); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	err := svc.AddCustomDomain(ctx, "sb-wasm-cd", "api.acme.com", 9999)
	if err == nil || !errors.Is(err, ErrWasmCustomDomainPortNotExposed) {
		t.Fatalf("AddCustomDomain(9999) = %v, want ErrWasmCustomDomainPortNotExposed", err)
	}
}

func TestWasmCustomDomainHelperBranches(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ToolboxPort = 4321

	if ports := wasmExposedHTTPPorts(nil); ports != nil {
		t.Fatalf("wasmExposedHTTPPorts(nil) = %v, want nil", ports)
	}
	sb := &models.Sandbox{
		ExposedPorts: []models.ExposedPort{
			{Port: 8080, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 8443, Protocol: models.ExposedPortProtocolTLS},
			{Port: 9090, Protocol: ""},
		},
	}
	if ports := wasmExposedHTTPPorts(sb); len(ports) != 2 {
		t.Fatalf("wasmExposedHTTPPorts = %v, want 2 HTTP ports", ports)
	}

	if dial, err := svc.wasmCustomDomainDial(ctx, &models.Sandbox{ContainerIP: "10.0.0.2"}, 0); err != nil || dial != "10.0.0.2:4321" {
		t.Fatalf("wasmCustomDomainDial(toolbox) = (%q, %v), want toolbox dial", dial, err)
	}

	svc.SetWasmRuntime(&recordingRuntime{})
	wasmRow := &models.Sandbox{
		ID:          "sb-wasm-cd-helper",
		Runtime:     models.RuntimeWasm,
		ContainerIP: "10.0.0.2",
		ExposedPorts: []models.ExposedPort{
			{Port: 8080, Protocol: models.ExposedPortProtocolHTTP},
		},
	}
	if _, err := svc.wasmCustomDomainDial(ctx, wasmRow, 8080); err == nil {
		t.Fatal("wasmCustomDomainDial should fail when the runtime lacks a port gateway")
	}

	if err := svc.syncWasmCustomDomainRoutes(ctx, nil); err != nil {
		t.Fatalf("syncWasmCustomDomainRoutes(nil) = %v, want nil", err)
	}
	if err := svc.syncWasmCustomDomainRoutes(ctx, &models.Sandbox{Runtime: models.RuntimeDocker}); err != nil {
		t.Fatalf("syncWasmCustomDomainRoutes(non-wasm) = %v, want nil", err)
	}
}
