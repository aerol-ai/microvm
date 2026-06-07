//go:build !wasmtime

package wasm_test

import (
	"context"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestNewEngineForWasmtimeUnavailableWithoutTag(t *testing.T) {
	_, err := wasmengine.NewEngineFor(context.Background(), wasmengine.EngineNameWasmtime())
	if err == nil {
		t.Fatal("expected wasmtime engine to be unavailable without build tag")
	}
}
