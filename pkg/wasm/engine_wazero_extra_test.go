package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEngine_ErrorPaths(t *testing.T) {
	ctx := context.Background()
	eng, err := NewEngine(ctx)
	if err != nil {
		t.Fatalf("expected engine: %v", err)
	}
	defer eng.Close(ctx)
	testEngineErrorPaths(t, eng)
}

func TestWazeroEngine_ErrorPaths(t *testing.T) {
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("expected engine: %v", err)
	}
	defer eng.Close(ctx)
	testEngineErrorPaths(t, eng)
}

func testEngineErrorPaths(t *testing.T, eng Engine) {
	ctx := context.Background()

	// Error on LoadModule (bad path)
	if err := eng.LoadModule(ctx, "/does/not/exist.wasm"); err == nil {
		t.Fatalf("expected error on LoadModule")
	}

	// Error on LoadModule (invalid wasm)
	badWasm := filepath.Join(t.TempDir(), "bad.wasm")
	os.WriteFile(badWasm, []byte("not a wasm file"), 0644)
	if err := eng.LoadModule(ctx, badWasm); err == nil {
		t.Fatalf("expected error on LoadModule bad wasm")
	}

	// Error on Instantiate without load
	if err := eng.Instantiate(ctx, Capabilities{}); err == nil {
		t.Fatalf("expected error on Instantiate")
	}

	// Error on InvokeExport without instantiate
	if err := eng.InvokeExport(ctx, "_start"); err == nil {
		t.Fatalf("expected error on InvokeExport")
	}

	// Error on StopInstance without instantiate
	// Depending on implementation, this might just return nil, but we can call it.
	_ = eng.StopInstance(ctx)

	// Error on Run without instantiate
	if _, err := eng.Run(ctx, Capabilities{}, "_start"); err == nil {
		t.Fatalf("expected error on Run")
	}

	// CaptureSnapshot without instantiate
	if _, err := eng.CaptureSnapshot(ctx); err == nil {
		t.Fatalf("expected error on CaptureSnapshot")
	}

	// RestoreSnapshot bad path
	if err := eng.RestoreSnapshot(ctx, SnapshotRestoreInput{Config: SnapshotConfig{}}, Capabilities{}); err == nil {
		t.Fatalf("expected error on RestoreSnapshot")
	}

	// Create a dummy wasm to test Instantiate error paths
	goodWasm := filepath.Join(t.TempDir(), "good.wasm")
	// Valid wasm module with 1 page memory exported:
	os.WriteFile(goodWasm, []byte("\x00\x61\x73\x6d\x01\x00\x00\x00\x05\x03\x01\x00\x01\x07\x0a\x01\x06\x6d\x65\x6d\x6f\x72\x79\x02\x00"), 0644)
	if err := eng.LoadModule(ctx, goodWasm); err != nil {
		t.Fatalf("failed to load good wasm: %v", err)
	}

	if err := eng.Instantiate(ctx, Capabilities{}); err != nil {
		t.Fatalf("failed to instantiate: %v", err)
	}

	// Test RestoreSnapshot empty memory
	if err := eng.RestoreSnapshot(ctx, SnapshotRestoreInput{Memory: nil}, Capabilities{}); err != nil {
		t.Fatalf("expected nil on empty memory: %v", err)
	}

	// Test RestoreSnapshot mem write fail (1 page is 64KB, we write 64KB + 1 byte)
	hugeMem := make([]byte, 65537)
	if err := eng.RestoreSnapshot(ctx, SnapshotRestoreInput{Memory: hugeMem}, Capabilities{}); err == nil {
		t.Fatalf("expected error on huge memory write")
	}

	// Test CaptureSnapshot on module with no memory (goodWasm has no memory now)
	engNoMem, _ := newWazeroEngine(ctx)
	noMemWasm := filepath.Join(t.TempDir(), "nomem.wasm")
	os.WriteFile(noMemWasm, []byte("\x00\x61\x73\x6d\x01\x00\x00\x00"), 0644)
	_ = engNoMem.LoadModule(ctx, noMemWasm)
	_ = engNoMem.Instantiate(ctx, Capabilities{})
	if _, err := engNoMem.CaptureSnapshot(ctx); err == nil {
		t.Fatalf("expected error on CaptureSnapshot without memory")
	}

	// Test double LoadModule to cover Close()
	if err := eng.LoadModule(ctx, goodWasm); err != nil {
		t.Fatalf("failed double LoadModule: %v", err)
	}

	// Test double Instantiate to cover module Close()
	if err := eng.Instantiate(ctx, Capabilities{}); err != nil {
		t.Fatalf("failed double Instantiate: %v", err)
	}

	// Test double Run
	_, _ = eng.Run(ctx, Capabilities{}, "")
	_, _ = eng.Run(ctx, Capabilities{}, "")
}
func TestRunBadExport(t *testing.T) {
	ctx := context.Background()
	eng, _ := newWazeroEngine(ctx)
	defer eng.Close(ctx)

	goodWasm := filepath.Join(t.TempDir(), "good.wasm")
	os.WriteFile(goodWasm, []byte("\x00\x61\x73\x6d\x01\x00\x00\x00\x05\x03\x01\x00\x01\x07\x0a\x01\x06\x6d\x65\x6d\x6f\x72\x79\x02\x00"), 0644)
	eng.LoadModule(ctx, goodWasm)
	eng.Instantiate(ctx, Capabilities{})

	if _, err := eng.Run(ctx, Capabilities{}, "does_not_exist"); err == nil {
		t.Fatalf("expected error on Run with bad export")
	}
}
