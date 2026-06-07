//go:build !wasmtime

package wasm

import (
	"context"
	"fmt"
)

func newWasmtimeEngine(_ context.Context) (Engine, error) {
	return nil, fmt.Errorf("wasmtime engine unavailable (rebuild sandboxd with -tags wasmtime)")
}
