package service

import (
	"context"
	"errors"
	"testing"
	"time"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
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
