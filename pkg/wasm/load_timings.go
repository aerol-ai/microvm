package wasm

import "time"

// LoadTimings breaks the cold-create wasm_load stage into its sub-costs. It
// exists because a single wasm_load timer told us the stage was ~2.8s p50 for
// CPython on t3.medium but not WHICH step owned it — and the firecracker
// create-latency episode proved that guessing the dominant sub-cost before
// measuring it burns effort on the wrong lever. Splitting the timer lets the
// create path emit per-step Server-Timing entries so the resident-module work
// (plans/wasm-resident-module-host.md) targets the real bottleneck.
//
// The fields mirror the cold LoadModule sequence in the worker:
//
//	NewEngine   — worker: NewEngineFor builds the first wazero runtime + WASI.
//	RuntimeInit — engine: LoadModule rebuilds the runtime at the target memory
//	              limit (+ WASI + compile-cache open). This is a second runtime
//	              build today; see the plan's "redundant double init" note.
//	Read        — engine: os.ReadFile of the module bytes (25MB for CPython).
//	Compile     — engine: wazero CompileModule (compile-cache assisted; a full
//	              cold compile is ~10s, a cache hit ~seconds of deserialize).
//
// Durations marshal to JSON as their nanosecond integer (time.Duration is
// int64), so they cross the worker IPC boundary losslessly.
type LoadTimings struct {
	NewEngine   time.Duration `json:"new_engine_ns,omitempty"`
	RuntimeInit time.Duration `json:"runtime_init_ns,omitempty"`
	Read        time.Duration `json:"read_ns,omitempty"`
	Compile     time.Duration `json:"compile_ns,omitempty"`
}

// LoadTimingReporter is an optional engine capability: an engine that
// implements it exposes the sub-stage breakdown of its most recent LoadModule.
// It is type-asserted by the worker (like NetworkAwareEngine) so the base
// Engine interface — and the wasmtime backend and the test mocks that
// implement it — stay untouched.
type LoadTimingReporter interface {
	LastLoadTimings() LoadTimings
}
