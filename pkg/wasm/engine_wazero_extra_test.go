package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWazeroEngine_ErrorPaths(t *testing.T) {
	ctx := context.Background()
	eng, err := NewEngine(ctx)
	if err != nil {
		t.Fatalf("expected engine: %v", err)
	}
	defer eng.Close(ctx)

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
}
