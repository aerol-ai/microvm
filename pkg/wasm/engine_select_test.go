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

func TestNewEngineForUnknown(t *testing.T) {
	_, err := wasmengine.NewEngineFor(context.Background(), "unknown-engine")
	if err == nil {
		t.Fatal("expected error for unknown engine")
	}
}
