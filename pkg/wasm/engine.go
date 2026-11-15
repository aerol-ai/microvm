package wasm

import (
	"context"
)

// LoadOptions carries per-load engine configuration. MemoryMB sets the wazero
// runtime memory-limit pages before compilation so a later Instantiate with the
// same cap does not rebuild the runtime (plans/wasm-create-latency.md Phase 1).
type LoadOptions struct {
	MemoryMB int
}

// Engine compiles and runs a single WASM module with WASI.
type Engine interface {
	// LoadModule compiles bytes from path. Idempotent per path within one engine.
	LoadModule(ctx context.Context, path string, opts LoadOptions) error
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
	// (the HTTP ingress / expose_port path) for the loaded module. wazero
	// can. The wasmtime backend can on Linux and macOS for a module that
	// exports its memory: wasmtime cannot pre-open a listener, so the
	// engine serves the guest's sockets itself (wasmtime_sockets.go). For
	// an engine that cannot, the worker moves the sandbox to wazero or,
	// with that fallback off, rejects the request up front rather than
	// silently failing to resolve a port (worker/listen_engine.go).
	SupportsListen() bool
}

// MultiListenEngine is an Engine that pre-opens one wasip1 listener per
// exposed port (Capabilities.WASIListeners, #177) and can tell which of
// them its guest serves. Optional, so test fakes stay plain Engines;
// wazero and wasmtime implement it.
type MultiListenEngine interface {
	Engine
	// ResolvedListeners returns the running instance's live listeners with
	// the host ports they are bound to, ascending by guest port (a single
	// WASIListenPort listener has guest port 0). nil when it has none.
	ResolvedListeners() []WASIListener
	// ListenerAccepted reports whether the running guest has called
	// sock_accept on the listener for guestPort: a guest written for one
	// listener only ever accepts on the first.
	ListenerAccepted(guestPort int) bool
}

// NewEngine constructs the default wazero-backed engine.
func NewEngine(ctx context.Context) (Engine, error) {
	return newWazeroEngine(ctx)
}

// EngineNameWazero returns the §4.8.1 engine identifier for the default backend.
func EngineNameWazero() string { return engineWazero }
