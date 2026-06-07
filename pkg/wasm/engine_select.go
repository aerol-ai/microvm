package wasm

import (
	"context"
	"fmt"
)

const engineWasmtime = "wasmtime"

// EngineNameWasmtime returns the §4.8.1 engine identifier for the optional wasmtime backend (UC-42b).
func EngineNameWasmtime() string { return engineWasmtime }

// NewEngineFor constructs an engine by name. Empty name selects wazero.
func NewEngineFor(ctx context.Context, name string) (Engine, error) {
	switch name {
	case "", engineWazero:
		return newWazeroEngine(ctx)
	case engineWasmtime:
		return newWasmtimeEngine(ctx)
	default:
		return nil, fmt.Errorf("unknown wasm engine %q", name)
	}
}
