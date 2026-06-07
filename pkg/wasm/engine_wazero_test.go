package wasm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestWazeroEngineLoadAndInvokeStart(t *testing.T) {
	dir := t.TempDir()
	path := wasmmod.WriteMinimalWasm(t, dir, "empty.wasm")

	ctx := context.Background()
	eng, err := NewEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close(ctx)

	if err := eng.LoadModule(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err := eng.Instantiate(ctx, Capabilities{Args: []string{"test"}}); err != nil {
		t.Fatal(err)
	}
	if err := eng.InvokeExport(ctx, "_start"); err != nil {
		t.Fatal(err)
	}
	if err := eng.StopInstance(ctx); err != nil {
		t.Fatal(err)
	}
	// Re-instantiate after stop.
	if err := eng.Instantiate(ctx, Capabilities{Args: []string{filepath.Base(path)}}); err != nil {
		t.Fatal(err)
	}
}
