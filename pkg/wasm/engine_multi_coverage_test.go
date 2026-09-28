package wasm

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestCoverage95EngineReinitializationAndPreopen(t *testing.T) {
	ctx := context.Background()
	module := wasmmod.WriteMinimalWasm(t, t.TempDir(), "minimal.wasm")
	engine, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close(ctx) })
	if err := engine.LoadModule(ctx, module, LoadOptions{MemoryMB: 1}); err != nil {
		t.Fatal(err)
	}
	caps := Capabilities{
		Env:      map[string]string{"COVERAGE_KEY": "value"},
		MemoryMB: 2,
		Preopens: []Preopen{{HostPath: t.TempDir()}},
	}
	if err := engine.Instantiate(ctx, caps); err != nil {
		t.Fatalf("Instantiate with a changed memory limit and preopen: %v", err)
	}
	if err := engine.StopInstance(ctx); err != nil {
		t.Fatal(err)
	}

	multi, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = multi.Close(ctx) })
	if err := multi.LoadModule(ctx, module); err != nil {
		t.Fatal(err)
	}
	if err := multi.Instantiate(ctx, "preopen", caps); err != nil {
		t.Fatalf("multi Instantiate with preopen: %v", err)
	}
	if _, err := multi.Run(ctx, "preopen", caps, ""); err != nil {
		t.Fatalf("multi Run with default export: %v", err)
	}
}
