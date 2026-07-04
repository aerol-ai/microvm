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
