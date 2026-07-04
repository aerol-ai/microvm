package wasm

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/tetratelabs/wazero"
)

func TestLoadThenInstantiate_CompilesOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)

	var compileCalls atomic.Int32
	old := compileModule
	compileModule = func(r wazero.Runtime, c context.Context, b []byte) (wazero.CompiledModule, error) {
		compileCalls.Add(1)
		return old(r, c, b)
	}
	t.Cleanup(func() { compileModule = old })

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close(ctx)

	memMB := 256
	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: memMB}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: memMB}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if got := compileCalls.Load(); got != 1 {
		t.Fatalf("compile calls = %d, want 1", got)
	}
}

func TestInstantiate_DifferentLimitStillRebuilds(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)

	var compileCalls atomic.Int32
	old := compileModule
	compileModule = func(r wazero.Runtime, c context.Context, b []byte) (wazero.CompiledModule, error) {
		compileCalls.Add(1)
		return old(r, c, b)
	}
	t.Cleanup(func() { compileModule = old })

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close(ctx)

	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 128}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: 256}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if got := compileCalls.Load(); got < 2 {
		t.Fatalf("compile calls = %d, want >= 2 for mismatched memory limit", got)
	}
}
