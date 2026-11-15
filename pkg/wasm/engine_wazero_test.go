package wasm

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func writeDummyWasm(t *testing.T, dir string) string {
	path := filepath.Join(dir, "test.wasm")
	// CheckpointWasmHex is a minimal module with exported linear memory for snapshot tests.
	const CheckpointWasmHex = "0061736d01000000010401600000030201000503010001071302066d656d6f72790200065f737461727400000a040102000b"
	b, err := hex.DecodeString(CheckpointWasmHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWazeroEngine_Lifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)

	// Test LoadModule
	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}

	// Test Instantiate
	caps := Capabilities{
		MemoryMB: 10,
		Preopens: []Preopen{{HostPath: "/tmp", GuestPath: "/tmp"}},
	}
	if err := eng.Instantiate(ctx, caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}

	// Test InvokeExport
	if err := eng.InvokeExport(ctx, "_start"); err != nil {
		t.Fatalf("InvokeExport: %v", err)
	}

	// Test CaptureSnapshot
	snap, err := eng.CaptureSnapshot(ctx)
	if err != nil {
		t.Fatalf("CaptureSnapshot: %v", err)
	}

	snapDir := filepath.Join(dir, "snapshot")
	if err := WriteSnapshotDir(snapDir, snap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}

	// Test StopInstance
	if err := eng.StopInstance(ctx); err != nil {
		t.Fatalf("StopInstance: %v", err)
	}

	// Test RestoreSnapshot
	restoredSnap, err := ReadSnapshotDir(snapDir, EngineNameWazero())
	if err != nil {
		t.Fatalf("ReadSnapshotDir: %v", err)
	}
	if err := eng.RestoreSnapshot(ctx, restoredSnap, caps); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}

	// Ensure memory limits and helpers
	if err := eng.ensureMemoryLimit(ctx, caps.MemoryMB); err != nil {
		t.Fatalf("ensureMemoryLimit: %v", err)
	}
	if eng.SupportsListen() {
		eng.ResolvedListenPort()
		eng.ClearNetworkHook()
	}

	// Test Run
	res, err := eng.Run(ctx, caps, "_start")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected 0 exit code, got %d", res.ExitCode)
	}
}

func TestExitCodeFromInvoke(t *testing.T) {
	// Not an error
	if exitCodeFromInvoke(nil) != 0 {
		t.Fatal("expected 0")
	}

	// A regular error
	if exitCodeFromInvoke(context.Canceled) != 1 {
		t.Fatal("expected 1")
	}
}

func TestWazeroEngine_CompileCacheDirEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", dir)

	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
}

func TestWazeroEngine_EnsureMemoryLimitRebuildsRuntime(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)

	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.ensureMemoryLimit(ctx, 20); err != nil {
		t.Fatalf("ensureMemoryLimit: %v", err)
	}
	if eng.memoryPages == 0 {
		t.Fatal("expected memoryPages to be set")
	}
}

func TestWazeroEngine_InvokeExportNotFound(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)

	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: 10}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := eng.InvokeExport(ctx, "missing"); err == nil {
		t.Fatal("expected error for missing export")
	}
}

func TestWazeroEngine_RunExportNotFound(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)

	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	res, err := eng.Run(ctx, Capabilities{MemoryMB: 10}, "missing")
	if err == nil {
		t.Fatal("expected error for missing export")
	}
	if res.ExitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", res.ExitCode)
	}
}

func TestWazeroEngine_FsConfigForPreopens(t *testing.T) {
	caps := Capabilities{Preopens: []Preopen{{HostPath: "/tmp", GuestPath: "/work"}}}
	cfg, mounts, err := fsConfigFor(caps)
	if err != nil || cfg == nil || len(mounts) != 1 {
		t.Fatalf("expected one confined mount, got %v, %d, %v", cfg, len(mounts), err)
	}
	release := releaseMounts(mounts)
	release()
	release() // idempotent: the close notifier and a failed instantiate may both call it
	if _, errno := mounts[0].Stat("."); errno == 0 {
		t.Fatal("a released mount still serves paths")
	}

	cfg, mounts, err = fsConfigFor(Capabilities{})
	if err != nil || cfg != nil || mounts != nil {
		t.Fatalf("no preopens: cfg=%v mounts=%v err=%v; want nothing", cfg, mounts, err)
	}
	releaseMounts(mounts)()
}

func TestWazeroEngine_ListenerFD(t *testing.T) {
	caps := Capabilities{Preopens: []Preopen{{HostPath: "/tmp", GuestPath: "/work"}}}
	if ListenerFD(caps) != 3+len(caps.Preopens) {
		t.Fatalf("unexpected ListenerFD")
	}
}

func TestWazeroEngine_LoadModuleMissingFile(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
	if err := eng.LoadModule(ctx, "/tmp/does-not-exist.wasm", LoadOptions{MemoryMB: 10}); err == nil {
		t.Fatal("expected error for missing module file")
	}
}

func TestWazeroEngine_ResolvedListenPort_NoModule(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
	if got, ok := eng.ResolvedListenPort(); got != 0 || ok {
		t.Fatalf("ResolvedListenPort = (%d,%v), want (0,false)", got, ok)
	}
}

// Once wazero closes the module on its own (the guest exited, a deadline
// fired), the listener is closed and its port free for any other bind on the
// host, so the engine must stop naming it.
func TestWazeroEngine_ResolvedListenPort_ClosedModule(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
	if err := eng.LoadModule(ctx, writeDummyWasm(t, t.TempDir()), LoadOptions{}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.Instantiate(ctx, Capabilities{WASIListenPort: 0, WASIListenHost: "127.0.0.1"}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if port, ok := eng.ResolvedListenPort(); !ok || port <= 0 {
		t.Fatalf("ResolvedListenPort = (%d,%v), want a bound port", port, ok)
	}
	if err := eng.module.Close(ctx); err != nil {
		t.Fatalf("module Close: %v", err)
	}
	if port, ok := eng.ResolvedListenPort(); ok {
		t.Fatalf("ResolvedListenPort = (%d,%v) after the module closed, want none", port, ok)
	}
}

func TestWazeroEngine_CloseNilModule(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	if err := eng.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestWazeroEngine_InstantiateWithoutLoadFails(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
	if err := eng.Instantiate(ctx, Capabilities{MemoryMB: 10}); err == nil {
		t.Fatal("expected error when instantiate without loaded module")
	}
}

func TestWazeroEngine_StopInstanceWithoutModuleNoop(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
	if err := eng.StopInstance(ctx); err != nil {
		t.Fatalf("StopInstance: %v", err)
	}
}

func TestWazeroEngine_CallExportNoActiveInstance(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
	if _, err := eng.callExport(ctx, "_start"); err == nil {
		t.Fatal("expected error for no active instance")
	}
}

func TestWazeroEngine_CaptureSnapshotNoModule(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
	if _, err := eng.CaptureSnapshot(ctx); err == nil {
		t.Fatal("expected error for no active instance")
	}
}

func TestWazeroEngine_RestoreSnapshotWithoutMemory(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasmPath := writeDummyWasm(t, dir)

	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer eng.Close(ctx)
	if err := eng.LoadModule(ctx, wasmPath, LoadOptions{MemoryMB: 10}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.RestoreSnapshot(ctx, SnapshotRestoreInput{}, Capabilities{MemoryMB: 10}); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
}

func TestWazeroEngine_EnsureWasiCompatHostsNoRuntime(t *testing.T) {
	eng := &wazeroEngine{}
	if err := eng.ensureWasiCompatHosts(context.Background()); err != nil {
		t.Fatalf("ensureWasiCompatHosts: %v", err)
	}
}

func TestWazeroEngine_StringsTrimJoinEmpty(t *testing.T) {
	if got := stringsTrimJoin("", ""); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestSnapshotCodecHelpers(t *testing.T) {
	if len(SnapshotMediaTypes()) == 0 {
		t.Fatal("expected media types")
	}

	if DirExists("/invalid/path/that/does/not/exist") {
		t.Fatal("expected false")
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0644)
	if !DirExists(dir) {
		t.Fatal("expected true")
	}

	if err := FenceCloneGeneration("1", "2"); err == nil {
		t.Fatal("expected error")
	}
	if err := FenceCloneGeneration("1", "1"); err != nil {
		t.Fatal("expected nil")
	}

	err := snapshotCorruptf("test %s", "msg")
	if err == nil {
		t.Fatal("expected err")
	}
}

func TestStringsTrimJoin(t *testing.T) {
	res := stringsTrimJoin(" a \n", "  b  \n")
	if res != "a\nb" {
		t.Fatalf("expected 'a\\nb', got %q", res)
	}

	res2 := stringsTrimJoin("  ", "b")
	if res2 != "b" {
		t.Fatalf("expected 'b', got %q", res2)
	}

	res3 := stringsTrimJoin("a", "  ")
	if res3 != "a" {
		t.Fatalf("expected 'a', got %q", res3)
	}
}
