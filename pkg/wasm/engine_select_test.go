package wasm_test

import (
	"context"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestNewEngineForWazeroDefault(t *testing.T) {
	eng, err := wasmengine.NewEngineFor(context.Background(), "")
	if err != nil {
		t.Fatalf("NewEngineFor: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(context.Background()) })
}

func TestNewEngineForWasmtimeUnavailableWithoutTag(t *testing.T) {
	_, err := wasmengine.NewEngineFor(context.Background(), wasmengine.EngineNameWasmtime())
	if err == nil {
		t.Fatal("expected wasmtime engine to be unavailable without build tag")
	}
}
