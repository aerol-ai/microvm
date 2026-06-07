//go:build wasmtime

package wasm_test

import (
	"context"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestNewEngineForWasmtimeWithTag(t *testing.T) {
	eng, err := wasmengine.NewEngineFor(context.Background(), wasmengine.EngineNameWasmtime())
	if err != nil {
		t.Fatalf("NewEngineFor wasmtime: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(context.Background()) })
}
