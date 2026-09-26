package wasm

import (
	"context"
	"os"
	"path/filepath"
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

func TestCloseOnContextDoneIsHashedIntoCompileCacheKey(t *testing.T) {
	// wazero.AssignModuleID hashes WithCloseOnContextDone into the module
	// ID. The engine keeps the flag on (safe Stop); this test pins that a
	// cache populated without it does not satisfy a runtime with it on —
	// that is the 2–3s cold compile on upgrade, once per module per node.
	ctx := context.Background()
	wasmPath := writeDummyWasm(t, t.TempDir())
	bin, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ccOff, err := wazero.NewCompilationCacheWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rOff := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(ccOff).WithCloseOnContextDone(false))
	if _, err := rOff.CompileModule(ctx, bin); err != nil {
		t.Fatal(err)
	}
	if err := rOff.Close(ctx); err != nil {
		t.Fatal(err)
	}
	before := countRegularFiles(t, dir)

	ccOn, err := wazero.NewCompilationCacheWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rOn := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(ccOn).WithCloseOnContextDone(true))
	if _, err := rOn.CompileModule(ctx, bin); err != nil {
		t.Fatal(err)
	}
	if err := rOn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	after := countRegularFiles(t, dir)
	if after <= before {
		t.Fatalf("CloseOnContextDone reused the old cache key (files before=%d after=%d)", before, after)
	}
}

func countRegularFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
