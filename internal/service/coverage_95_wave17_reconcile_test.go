package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestReconcileOfflineWasmAndFCWave17(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableWasm = true
	svc.cfg.EnableFirecracker = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})
	svc.SetWasmRuntime(&recordingRuntime{}) // ListManaged empty → offline
	svc.SetFirecrackerRuntime(&recordingRuntime{})

	// Wasm passivated → continue early
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-pas", Image: "m", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusPassivated, Durability: models.DurabilityPassivatable,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	// Wasm awaiting runtime
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-await", Image: "m", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusAwaitingRuntime, Durability: models.DurabilityDurable,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	// Wasm stopped + armed
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-arm", Image: "m", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusStopped, WakeArmed: true, Durability: models.DurabilityPassivatable,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	// Wasm stopped + unarmed with exposed ports
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-unarm", Image: "m", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusStopped, WakeArmed: false, Durability: models.DurabilityPassivatable,
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-wasm-unarm", Port: 80, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x",
	})

	// Firecracker stopped + armed / unarmed
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-fc-arm", Image: "a", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-fc-unarm", Image: "a", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 22, Protocol: models.ExposedPortProtocolTCP, HostPort: 42001}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-fc-unarm", Port: 22, Protocol: models.ExposedPortProtocolTCP, HostPort: 42001, PublicURL: "tcp://x:42001",
	})

	// Containerd-owned without containerd driver → skip warn
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-ctrd", Image: "a", Engine: models.ContainerEngineContainerd,
		Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func TestReconcileGoneDockerRowWave17(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	// recordingRuntime ListManaged empty + Inspect empty identity → confirmed gone
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, t.TempDir()+"/rec17.db", rt)
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-gone", Image: "alpine:3.20", Status: models.SandboxStatusStarted, ContainerID: "missing",
		ExposedPorts: []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-gone", Port: 80, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x",
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile gone: %v", err)
	}
}

func TestReconcileGoneWasmDestroyWave17(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	wasmRT := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(wasmRT)
	svc.cfg.EnableCaddy = true
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-gone", Image: "m", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusStarted, Durability: models.DurabilityEphemeral,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile wasm gone: %v", err)
	}
}
