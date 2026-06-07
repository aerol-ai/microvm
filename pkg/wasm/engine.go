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
	// CaptureSnapshot exports linear memory from the active instance.
	CaptureSnapshot(ctx context.Context) (SnapshotCapture, error)
	// RestoreSnapshot re-instantiates and loads memory from a capture.
	RestoreSnapshot(ctx context.Context, snap SnapshotRestoreInput, caps Capabilities) error
	// Close releases compiled module and any active instance.
	Close(ctx context.Context) error
	// ResolvedListenPort returns the host port for an ephemeral wasip1 listener (0 in caps).
	ResolvedListenPort() (int, bool)
	// SupportsListen reports whether the engine can host a wasip1 TCP listener
	// (the HTTP ingress / expose_port path). wazero can; the wasmtime backend
	// cannot yet (see plans/wasm-runtime.md "Still open"). Callers must reject
	// listen requests up front rather than silently failing to resolve a port.
	SupportsListen() bool
}

// NewEngine constructs the default wazero-backed engine.
func NewEngine(ctx context.Context) (Engine, error) {
	return newWazeroEngine(ctx)
}

// EngineNameWazero returns the §4.8.1 engine identifier for the default backend.
func EngineNameWazero() string { return engineWazero }
