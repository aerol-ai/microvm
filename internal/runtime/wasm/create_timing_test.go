package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func wasmStageMap(timing *createtiming.CreateTiming) map[string]createtiming.Stage {
	out := map[string]createtiming.Stage{}
	for _, st := range timing.Stages() {
		out[st.Name] = st
	}
	return out
}

func TestCreate_WarmHit_RecordsStages(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	runDir := filepath.Join(dir, "run")
	warmSock := filepath.Join(dir, "warm.sock")

	sup := &fakeSupervisor{}
	client := &recordingWorkerClient{}
	d := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 256}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(sup)
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	d.SetWarmPool(&fakeWarmPool{slot: &wasmpool.Slot{
		ID:           "pool-1",
		ModuleDigest: "deadbeef",
		ModulePath:   modPath,
		SocketPath:   warmSock,
		WorkerKey:    "pool-1",
		MemoryMB:     256,
	}})

	ctx, timing := createtiming.With(context.Background())
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-timing-warm", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	stages := wasmStageMap(timing)
	for _, name := range []string{"wasm_resolve", "wasm_warm", "wasm_instantiate", "wasm_driver"} {
		if _, ok := stages[name]; !ok {
			t.Fatalf("stage %q not recorded (have %v)", name, stages)
		}
	}
	if stages["wasm_warm"].Desc != "hit" {
		t.Fatalf("wasm_warm desc = %q, want hit", stages["wasm_warm"].Desc)
	}
	for _, name := range []string{"wasm_spawn", "wasm_load"} {
		if _, ok := stages[name]; ok {
			t.Fatalf("stage %q must be absent on warm hit", name)
		}
	}
}

func TestCreate_ColdPath_RecordsAllStages(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	runDir := filepath.Join(dir, "run")

	d := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 256}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })

	ctx, timing := createtiming.With(context.Background())
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-timing-cold", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	stages := wasmStageMap(timing)
	for _, name := range []string{"wasm_resolve", "wasm_warm", "wasm_spawn", "wasm_load", "wasm_instantiate", "wasm_driver"} {
		if _, ok := stages[name]; !ok {
			t.Fatalf("stage %q not recorded (have %v)", name, stages)
		}
	}
	if stages["wasm_warm"].Desc != "miss" {
		t.Fatalf("wasm_warm desc = %q, want miss", stages["wasm_warm"].Desc)
	}
}

func TestCreate_FailureStillRecordsDriverStage(t *testing.T) {
	d := New(Config{RunDir: t.TempDir(), ModulesDir: t.TempDir()}, nil)
	d.SetModuleResolver(fakeResolver{path: "/missing/module.wasm", digest: "x"})
	d.SetWorkerSupervisor(&fakeSupervisor{})

	ctx, timing := createtiming.With(context.Background())
	_, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-fail", "tok", nil)
	if err == nil {
		t.Fatal("expected create error")
	}
	stages := wasmStageMap(timing)
	if _, ok := stages["wasm_driver"]; !ok {
		t.Fatalf("wasm_driver not recorded on failure (have %v)", stages)
	}
}

// Ensure timing tests exercise a real modules dir for Ping-related paths.
func TestCreateTiming_ResolverRequired(t *testing.T) {
	d := New(Config{RunDir: filepath.Join(t.TempDir(), "run")}, nil)
	ctx, timing := createtiming.With(context.Background())
	_, err := d.Create(ctx, models.CreateSandboxRequest{Image: "x"}, "sb", "tok", nil)
	if err == nil {
		t.Fatal("expected error without resolver")
	}
	if timing == nil {
		t.Fatal("expected timing recorder")
	}
	_ = os.MkdirAll(d.cfg.RunDir, 0o700)
}
