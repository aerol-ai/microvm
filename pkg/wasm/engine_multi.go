package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/sys"
)

// MultiInstanceEngine holds one resident wazero runtime + one compiled module
// and instantiates many isolated instances from it — compile-once,
// instantiate-many. It is the Phase 1 primitive for the resident-module host
// (plans/wasm-resident-module-host.md).
//
// Why it exists: the v0.7.9 cluster-3-mixed-wasm bench measured a cold create's
// `wasm_load` at 2843ms p50, of which `wasm_load_compile` was 2768ms (~97%) —
// and that is WITH the on-disk compile cache populated, so it is the per-process
// deserialize of a 25MB CPython image, not a from-scratch compile. Reusing a
// resident in-process CompiledModule skips that entirely: an Instantiate against
// it measured 9ms. This type turns a "cold" create into an Instantiate.
//
// Bucketing constraint: wazero sets the memory limit at the runtime level and a
// CompiledModule is bound to its runtime, so one MultiInstanceEngine serves a
// single (module, memoryMB) bucket. MemoryMB is fixed at construction; the pool
// (Phase 3) routes a create to an engine whose MemoryMB matches, else cold path.
//
// Isolation: wazero gives every InstantiateModule its own linear memory, so
// co-tenant instances cannot read each other's memory (proven in
// engine_multi_test.go). Per-instance networking, snapshot/restore, IO-capturing
// Run, and wasip1 listeners are deliberately NOT here yet — they are Phase 2,
// wired when this engine is embedded in the worker (the worker's NetMediator is
// already keyed by sandboxID). Phase 1 is the isolated-instance primitive only.
type MultiInstanceEngine struct {
	mu        sync.Mutex
	runtime   wazero.Runtime
	compiled  wazero.CompiledModule
	memoryMB  int
	pages     uint32
	instances map[string]api.Module
	lastLoad  LoadTimings
}

// NewMultiInstanceEngine builds the resident runtime (memory-limited to memoryMB,
// sharing the on-disk compile cache + base wasip1 host) with no module compiled
// yet. Call LoadModule once, then Instantiate per sandbox.
func NewMultiInstanceEngine(ctx context.Context, memoryMB int) (*MultiInstanceEngine, error) {
	pages := MemoryLimitPages(memoryMB)
	r, err := newBaseRuntime(ctx, pages)
	if err != nil {
		return nil, err
	}
	return &MultiInstanceEngine{
		runtime:   r,
		memoryMB:  memoryMB,
		pages:     pages,
		instances: make(map[string]api.Module),
	}, nil
}

// MemoryMB is the fixed memory limit (MB) this engine's runtime + compiled
// module are built for. The pool routes only matching-memory creates here.
func (m *MultiInstanceEngine) MemoryMB() int { return m.memoryMB }

// Loaded reports whether a module has been compiled into the resident runtime.
func (m *MultiInstanceEngine) Loaded() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.compiled != nil
}

// LoadModule compiles the module at path once; every later Instantiate reuses
// the resident CompiledModule. A repeat call recompiles (e.g. module upgrade)
// and closes the previous compiled module — existing live instances keep
// running on their own already-instantiated code.
func (m *MultiInstanceEngine) LoadModule(ctx context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLoad = LoadTimings{}
	readStart := time.Now()
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m.lastLoad.Read = time.Since(readStart)
	compileStart := time.Now()
	compiled, err := compileModule(m.runtime, ctx, b)
	if err != nil {
		return fmt.Errorf("compile module: %w", err)
	}
	m.lastLoad.Compile = time.Since(compileStart)
	if m.compiled != nil {
		_ = m.compiled.Close(ctx)
	}
	m.compiled = compiled
	return nil
}

// LastLoadTimings satisfies LoadTimingReporter. NewEngine/RuntimeInit are left
// zero — this engine builds its runtime once at construction, not per load.
func (m *MultiInstanceEngine) LastLoadTimings() LoadTimings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastLoad
}

// Instantiate creates an isolated instance keyed by sandboxID from the resident
// compiled module. This is the fast path the whole design exists for: it costs
// an Instantiate (~9ms), not a CompileModule (~2.8s). _start is NOT run here
// (deferred, matching the single-instance engine); callers invoke it explicitly.
func (m *MultiInstanceEngine) Instantiate(ctx context.Context, sandboxID string, caps Capabilities) error {
	if sandboxID == "" {
		return fmt.Errorf("sandboxID required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.compiled == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	if _, ok := m.instances[sandboxID]; ok {
		return fmt.Errorf("instance %q already exists", sandboxID)
	}
	// wazero rejects two instances sharing a module name on one runtime, so key
	// the instance name by sandboxID to keep co-tenants distinct.
	cfg := moduleConfigFor(caps).WithName(sandboxID)
	if fsCfg := fsConfigFor(caps); fsCfg != nil {
		cfg = cfg.WithFSConfig(fsCfg)
	}
	mod, err := m.runtime.InstantiateModule(ctx, m.compiled, cfg)
	if err != nil {
		return fmt.Errorf("instantiate module: %w", err)
	}
	m.instances[sandboxID] = mod
	return nil
}

// Run (re-)instantiates the sandbox's instance with stdout/stderr capture and
// invokes export (default _start), returning the captured output — the one-shot
// Exec path for a resident-hosted sandbox. It mirrors the single-instance
// engine's Run (re-instantiate per call so a fresh Exec starts clean), but
// keyed by sandboxID and reusing the resident compiled module, so it costs an
// Instantiate (~9ms), not a compile. A non-zero guest exit is returned in the
// RunResult (not as a Go error), matching the single-instance engine.
func (m *MultiInstanceEngine) Run(ctx context.Context, sandboxID string, caps Capabilities, export string) (RunResult, error) {
	if sandboxID == "" {
		return RunResult{}, fmt.Errorf("sandboxID required")
	}
	if export == "" {
		export = "_start"
	}
	m.mu.Lock()
	if m.compiled == nil {
		m.mu.Unlock()
		return RunResult{}, fmt.Errorf("no compiled module loaded")
	}
	// Re-instantiate semantics: drop any prior instance for this sandbox first.
	if old, ok := m.instances[sandboxID]; ok {
		_ = old.Close(ctx)
		delete(m.instances, sandboxID)
	}
	compiled := m.compiled
	runtime := m.runtime
	m.mu.Unlock()

	invokeCtx, cancel := WithInvocationDeadline(ctx, caps)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cfg := moduleConfigFor(caps).WithName(sandboxID).WithStdout(&stdout).WithStderr(&stderr)
	if fsCfg := fsConfigFor(caps); fsCfg != nil {
		cfg = cfg.WithFSConfig(fsCfg)
	}
	start := time.Now()
	mod, err := runtime.InstantiateModule(invokeCtx, compiled, cfg)
	if err != nil {
		return RunResult{}, fmt.Errorf("instantiate module: %w", err)
	}
	m.mu.Lock()
	m.instances[sandboxID] = mod
	m.mu.Unlock()

	result := RunResult{}
	fn := mod.ExportedFunction(export)
	if fn == nil {
		result.ExitCode = 1
		result.Stdout = stdout.String()
		result.Stderr = stderr.String()
		return result, fmt.Errorf("export %q not found", export)
	}
	_, callErr := fn.Call(invokeCtx)
	result.ExitCode = exitCodeFromInvoke(callErr)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.Usage = UsageStats{WallDurationMs: time.Since(start).Milliseconds()}
	if callErr != nil {
		var exitErr *sys.ExitError
		if errors.As(callErr, &exitErr) {
			// A guest exit(code) is a normal result, not a host error.
			return result, nil
		}
		result.Stderr = stringsTrimJoin(result.Stderr, callErr.Error())
		return result, callErr
	}
	return result, nil
}

// InvokeExport calls an exported function on one instance. The lock is released
// before the call so a long-running export does not serialize co-tenants.
func (m *MultiInstanceEngine) InvokeExport(ctx context.Context, sandboxID, name string) error {
	m.mu.Lock()
	mod, ok := m.instances[sandboxID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no instance %q", sandboxID)
	}
	fn := mod.ExportedFunction(name)
	if fn == nil {
		return fmt.Errorf("export %q not found", name)
	}
	_, err := fn.Call(ctx)
	return err
}

// StopInstance closes one instance and leaves every co-tenant running.
// Idempotent: stopping an unknown sandboxID is a no-op.
func (m *MultiInstanceEngine) StopInstance(ctx context.Context, sandboxID string) error {
	m.mu.Lock()
	mod, ok := m.instances[sandboxID]
	if ok {
		delete(m.instances, sandboxID)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	return mod.Close(ctx)
}

// HasInstance reports whether sandboxID has a live instance.
func (m *MultiInstanceEngine) HasInstance(sandboxID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.instances[sandboxID]
	return ok
}

// InstanceCount is the number of live instances (for pool accounting + tests).
func (m *MultiInstanceEngine) InstanceCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.instances)
}

// instanceModule returns the raw wazero module for one sandbox (nil if absent).
// Package-internal: used by tests and by future per-instance snapshot/network
// wiring in Phase 2.
func (m *MultiInstanceEngine) instanceModule(sandboxID string) api.Module {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.instances[sandboxID]
}

// Close tears down every instance, the compiled module, and the runtime.
func (m *MultiInstanceEngine) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, mod := range m.instances {
		_ = mod.Close(ctx)
		delete(m.instances, id)
	}
	if m.compiled != nil {
		_ = m.compiled.Close(ctx)
		m.compiled = nil
	}
	if m.runtime != nil {
		return m.runtime.Close(ctx)
	}
	return nil
}
