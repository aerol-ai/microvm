package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestMultiInstanceEngine_CompileOnceInstantiateManyIsolated is the Phase 1
// regression guard for the resident-module host: one compiled module must serve
// many isolated instances (compile-once, instantiate-many), stopping one must
// leave co-tenants running, and duplicate sandbox IDs must be rejected. This is
// the primitive that turns a cold create's 2.8s CompileModule into a ~9ms
// Instantiate (plans/wasm-resident-module-host.md).
func TestMultiInstanceEngine_CompileOnceInstantiateManyIsolated(t *testing.T) {
	dir := t.TempDir()
	// A module with exported linear memory, so we can prove instance isolation.
	modPath := wasmmod.WriteCheckpointWasm(t, dir, "mem.wasm")
	ctx := context.Background()

	eng, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })

	if err := eng.LoadModule(ctx, modPath); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	// Compile-once: capture the resident compiled module; it must not change as
	// we instantiate many times below.
	compiledAfterLoad := eng.compiled
	if compiledAfterLoad == nil {
		t.Fatal("LoadModule left no compiled module")
	}

	caps := Capabilities{Args: []string{"wasm"}}
	if err := eng.Instantiate(ctx, "a", caps); err != nil {
		t.Fatalf("Instantiate a: %v", err)
	}
	if err := eng.Instantiate(ctx, "b", caps); err != nil {
		t.Fatalf("Instantiate b: %v", err)
	}
	if got := eng.InstanceCount(); got != 2 {
		t.Fatalf("InstanceCount=%d, want 2", got)
	}
	if eng.compiled != compiledAfterLoad {
		t.Fatal("compiled module changed across Instantiate — expected compile-once, instantiate-many")
	}

	// Isolation: each instance has its own linear memory. A write to A must not
	// be visible in B.
	memA := eng.instanceModule("a").Memory()
	memB := eng.instanceModule("b").Memory()
	if memA == nil || memB == nil {
		t.Fatal("instances missing linear memory")
	}
	if !memA.WriteByte(0, 0x42) {
		t.Fatal("write to instance A memory failed")
	}
	if got, ok := memB.ReadByte(0); !ok || got != 0 {
		t.Fatalf("instance B memory saw A's write: got %#x (ok=%v), want 0 — instances not isolated", got, ok)
	}
	if got, _ := memA.ReadByte(0); got != 0x42 {
		t.Fatalf("instance A memory readback = %#x, want 0x42", got)
	}

	// Duplicate sandboxID must be rejected (idempotency is the caller's job via
	// HasInstance; the engine refuses to silently replace a live instance).
	if err := eng.Instantiate(ctx, "b", caps); err == nil {
		t.Fatal("expected error instantiating a duplicate sandboxID")
	}

	// Stop-one: closing A leaves B alive and uncorrupted.
	if err := eng.StopInstance(ctx, "a"); err != nil {
		t.Fatalf("StopInstance a: %v", err)
	}
	if eng.HasInstance("a") {
		t.Fatal("instance a still present after StopInstance")
	}
	if !eng.HasInstance("b") {
		t.Fatal("stopping a removed instance b")
	}
	if got := eng.InstanceCount(); got != 1 {
		t.Fatalf("InstanceCount=%d after stopping a, want 1", got)
	}
	if got, ok := memB.ReadByte(0); !ok || got != 0 {
		t.Fatalf("instance B memory corrupted after stopping A: got %#x (ok=%v)", got, ok)
	}

	// Stopping an unknown instance is a no-op, not an error.
	if err := eng.StopInstance(ctx, "does-not-exist"); err != nil {
		t.Fatalf("StopInstance unknown: %v", err)
	}
}

// TestMultiInstanceEngine_InstantiateBeforeLoad guards the ordering contract:
// Instantiate before LoadModule must fail cleanly rather than panic.
func TestMultiInstanceEngine_InstantiateBeforeLoad(t *testing.T) {
	ctx := context.Background()
	eng, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })

	if err := eng.Instantiate(ctx, "a", Capabilities{}); err == nil {
		t.Fatal("expected error instantiating before LoadModule")
	}
	if err := eng.Instantiate(ctx, "", Capabilities{}); err == nil {
		t.Fatal("expected error for empty sandboxID")
	}
}

// TestMultiInstanceEngine_RunPerInstance confirms the one-shot Exec path works
// per sandbox on the resident compiled module and returns a clean exit for the
// empty _start module — without a second compile.
func TestMultiInstanceEngine_RunPerInstance(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	ctx := context.Background()
	eng, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, modPath); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	compiledAfterLoad := eng.compiled

	caps := Capabilities{Args: []string{"wasm"}}
	for _, id := range []string{"run-a", "run-b"} {
		res, err := eng.Run(ctx, id, caps, "_start")
		if err != nil {
			t.Fatalf("Run %s: %v", id, err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("Run %s exit=%d stderr=%q", id, res.ExitCode, res.Stderr)
		}
	}
	if eng.compiled != compiledAfterLoad {
		t.Fatal("Run recompiled the module — expected reuse of the resident compiled module")
	}
	if got := eng.InstanceCount(); got != 2 {
		t.Fatalf("InstanceCount=%d after two Runs, want 2", got)
	}

	// Run before load must fail cleanly, and empty sandboxID is rejected.
	fresh, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = fresh.Close(ctx) })
	if _, err := fresh.Run(ctx, "x", caps, "_start"); err == nil {
		t.Fatal("expected error running before LoadModule")
	}
	if _, err := eng.Run(ctx, "", caps, "_start"); err == nil {
		t.Fatal("expected error for empty sandboxID")
	}
}

// TestMultiInstanceEngine_ReportsLoadTimings confirms the engine satisfies
// LoadTimingReporter so the resident-host path keeps emitting the wasm_load
// breakdown once wired into the worker (Phase 2).
func TestMultiInstanceEngine_ReportsLoadTimings(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	ctx := context.Background()
	eng, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })

	var _ LoadTimingReporter = eng // compile-time: implements the reporter

	if err := eng.LoadModule(ctx, modPath); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if got := eng.LastLoadTimings().Compile; got <= 0 {
		t.Fatalf("Compile timing not reported: %v", got)
	}
}

func TestMultiInstanceEngineHelpersAndHooks(t *testing.T) {
	ctx := context.Background()
	eng, err := NewMultiInstanceEngine(ctx, 64)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })

	if got := eng.MemoryMB(); got != 64 {
		t.Fatalf("MemoryMB=%d, want 64", got)
	}
	if eng.Loaded() {
		t.Fatal("Loaded=true before LoadModule")
	}

	eng.SetNetworkHook("", nil)
	eng.SetNetworkHook("sb", nil)
	if eng.netHost == nil {
		t.Fatal("SetNetworkHook did not initialize netHost")
	}
	eng.ClearNetworkHook("sb")
	eng.ClearNetworkHook("missing")
}

func TestMultiInstanceEngineErrorAndReplacementPaths(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	module := wasmmod.WriteMinimalWasm(t, dir, "valid.wasm")
	invalid := filepath.Join(dir, "invalid.wasm")
	if err := os.WriteFile(invalid, []byte("not wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, filepath.Join(dir, "missing.wasm")); err == nil {
		t.Fatal("missing module unexpectedly loaded")
	}
	if err := eng.LoadModule(ctx, invalid); err == nil {
		t.Fatal("invalid module unexpectedly loaded")
	}
	if err := eng.LoadModule(ctx, module); err != nil {
		t.Fatal(err)
	}
	if err := eng.LoadModule(ctx, module); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Run(ctx, "missing-export", Capabilities{}, "does-not-exist"); err == nil {
		t.Fatal("missing export unexpectedly ran")
	}
	if err := eng.InvokeExport(ctx, "missing", "_start"); err == nil {
		t.Fatal("missing instance unexpectedly invoked")
	}
	if err := eng.Instantiate(ctx, "instance", Capabilities{}); err != nil {
		t.Fatal(err)
	}
	if err := eng.InvokeExport(ctx, "instance", "does-not-exist"); err == nil {
		t.Fatal("missing export unexpectedly invoked")
	}
	if eng.instanceModule("missing") != nil {
		t.Fatal("missing instance returned a module")
	}
}
