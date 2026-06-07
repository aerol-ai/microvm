package wasm

import (
	"context"
)

// Engine compiles and runs a single WASM module with WASI.
type Engine interface {
	// LoadModule compiles bytes from path. Idempotent per path within one engine.
	LoadModule(ctx context.Context, path string) error
	// Instantiate creates a runnable instance with the given capabilities.
	Instantiate(ctx context.Context, caps Capabilities) error
	// InvokeExport calls an exported function by name.
	InvokeExport(ctx context.Context, name string) error
	// Run re-instantiates with caps, invokes export, and captures stdout/stderr.
	Run(ctx context.Context, caps Capabilities, export string) (RunResult, error)
	// StopInstance tears down the active instance but keeps the compiled module.
	StopInstance(ctx context.Context) error
	// Close releases compiled module and any active instance.
	Close(ctx context.Context) error
}

// NewEngine constructs the default wazero-backed engine.
func NewEngine(ctx context.Context) (Engine, error) {
	return newWazeroEngine(ctx)
}
