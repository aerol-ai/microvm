package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// compileModule is the wazero compile seam for latency regression tests.
var compileModule = func(r wazero.Runtime, ctx context.Context, b []byte) (wazero.CompiledModule, error) {
	return r.CompileModule(ctx, b)
}

type wazeroEngine struct {
	// lifecycleMu serializes operations that replace or release runtime state.
	// callMu/callWG form a publication barrier between InvokeExport and
	// StopInstance/Close: once stopping is set, no new call can enter, and the
	// runtime is not released until every admitted call has unwound.
	lifecycleMu sync.Mutex
	callMu      sync.Mutex
	callWG      sync.WaitGroup
	stopping    bool
	closed      bool
	instanceCtx context.Context
	instanceEnd context.CancelFunc

	runtime     wazero.Runtime
	compiled    wazero.CompiledModule
	module      api.Module
	moduleBytes []byte
	memoryPages uint32
	netHook     *NetworkHook
	netHost     *wazeroNetHost
	wasiCompat  bool
	// lastLoad is the sub-stage breakdown of the most recent LoadModule, read
	// back by the worker via LastLoadTimings() (LoadTimingReporter).
	lastLoad LoadTimings
}

func newWazeroEngine(ctx context.Context) (*wazeroEngine, error) {
	e := &wazeroEngine{}
	if err := e.initRuntime(ctx, 0); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *wazeroEngine) initRuntime(ctx context.Context, memoryMB int) error {
	if err := e.stopActiveLocked(ctx); err != nil {
		return fmt.Errorf("stop active module: %w", err)
	}
	if e.compiled != nil {
		_ = e.compiled.Close(ctx)
		e.compiled = nil
	}
	if e.runtime != nil {
		_ = e.runtime.Close(ctx)
		e.runtime = nil
	}
	pages := MemoryLimitPages(memoryMB)
	r, err := newBaseRuntime(ctx, pages)
	if err != nil {
		return err
	}
	e.runtime = r
	e.wasiCompat = false
	e.memoryPages = pages
	if len(e.moduleBytes) > 0 {
		compiled, err := compileModule(r, ctx, e.moduleBytes)
		if err != nil {
			return fmt.Errorf("compile module: %w", err)
		}
		e.compiled = compiled
	}
	return nil
}

func wazeroCompileCacheDir() string {
	return strings.TrimSpace(os.Getenv("AEROL_WASM_COMPILE_CACHE_DIR"))
}

// newBaseRuntime builds a wazero runtime at the given memory-limit pages with
// the shared on-disk compilation cache and the base wasip1 host, but no guest
// module compiled. Shared by the single-instance engine (initRuntime) and the
// MultiInstanceEngine (engine_multi.go) so both get identical runtime config —
// notably the same compilation cache, which is what makes a warm compile cheap.
func newBaseRuntime(ctx context.Context, pages uint32) (wazero.Runtime, error) {
	// Guests are untrusted. This enables wazero's supported concurrent
	// Module.Close path and ensures cancellation/deadlines can preempt CPU-bound
	// guest code rather than pinning an OS thread indefinitely.
	cfg := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	if pages > 0 {
		cfg = cfg.WithMemoryLimitPages(pages)
	}
	if dir := wazeroCompileCacheDir(); dir != "" {
		cache, err := wazero.NewCompilationCacheWithDir(dir)
		if err != nil {
			return nil, fmt.Errorf("compilation cache: %w", err)
		}
		cfg = cfg.WithCompilationCache(cache)
	}
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("wasi instantiate: %w", err)
	}
	return r, nil
}

func (e *wazeroEngine) ensureWasiCompatHosts(ctx context.Context) error {
	if e.wasiCompat || e.runtime == nil {
		return nil
	}
	if err := e.ensureNetworkHost(ctx); err != nil {
		return err
	}
	if err := e.ensureWasiSocketsHost(ctx); err != nil {
		return err
	}
	if err := e.ensureWasiHTTPHost(ctx); err != nil {
		return err
	}
	e.wasiCompat = true
	return nil
}

func (e *wazeroEngine) ensureMemoryLimit(ctx context.Context, memoryMB int) error {
	want := MemoryLimitPages(memoryMB)
	if want == e.memoryPages {
		return nil
	}
	return e.initRuntime(ctx, memoryMB)
}

func (e *wazeroEngine) LoadModule(ctx context.Context, path string, opts LoadOptions) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if err := e.ensureOpenLocked(); err != nil {
		return err
	}
	if err := e.stopActiveLocked(ctx); err != nil {
		return fmt.Errorf("stop active module: %w", err)
	}
	if e.compiled != nil {
		_ = e.compiled.Close(ctx)
		e.compiled = nil
	}
	// Drop stale bytes before initRuntime — it recompiles moduleBytes when
	// rebuilding the runtime (ensureMemoryLimit path), and a failed prior load
	// must not poison the next path.
	e.moduleBytes = nil
	e.lastLoad = LoadTimings{}
	initStart := time.Now()
	if err := e.initRuntime(ctx, opts.MemoryMB); err != nil {
		return err
	}
	e.lastLoad.RuntimeInit = time.Since(initStart)
	readStart := time.Now()
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	e.lastLoad.Read = time.Since(readStart)
	compileStart := time.Now()
	compiled, err := compileModule(e.runtime, ctx, b)
	if err != nil {
		return fmt.Errorf("compile module: %w", err)
	}
	e.lastLoad.Compile = time.Since(compileStart)
	e.moduleBytes = append([]byte(nil), b...)
	e.compiled = compiled
	return nil
}

// LastLoadTimings returns the sub-stage breakdown of the most recent LoadModule
// (LoadTimingReporter). NewEngine is left zero here — it is filled in by the
// worker, which owns the NewEngineFor call that precedes LoadModule.
func (e *wazeroEngine) LastLoadTimings() LoadTimings {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.lastLoad
}

func (e *wazeroEngine) Instantiate(ctx context.Context, caps Capabilities) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if err := e.ensureOpenLocked(); err != nil {
		return err
	}
	return e.instantiateLocked(ctx, caps)
}

func (e *wazeroEngine) instantiateLocked(ctx context.Context, caps Capabilities) error {
	if len(e.moduleBytes) == 0 && e.compiled == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	if err := e.ensureMemoryLimit(ctx, caps.MemoryMB); err != nil {
		return err
	}
	if e.compiled == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	if err := e.stopActiveLocked(ctx); err != nil {
		return fmt.Errorf("stop active module: %w", err)
	}
	cfg := e.moduleConfig(caps)
	if fsCfg := e.fsConfigForCaps(caps); fsCfg != nil {
		cfg = cfg.WithFSConfig(fsCfg)
	}
	instCtx := e.withNetworkContext(ctx, caps)
	if err := e.ensureWasiCompatHosts(instCtx); err != nil {
		return err
	}
	mod, err := e.runtime.InstantiateModule(instCtx, e.compiled, cfg)
	if err != nil {
		return fmt.Errorf("instantiate module: %w", err)
	}
	e.publishModule(mod)
	return nil
}

func (e *wazeroEngine) StopInstance(ctx context.Context) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.stopActiveLocked(ctx)
}

func (e *wazeroEngine) ensureOpenLocked() error {
	e.callMu.Lock()
	closed := e.closed
	e.callMu.Unlock()
	if closed {
		return fmt.Errorf("engine is closed")
	}
	return nil
}

func (e *wazeroEngine) publishModule(mod api.Module) {
	e.callMu.Lock()
	instanceCtx, instanceEnd := context.WithCancel(context.Background())
	e.module = mod
	e.instanceCtx = instanceCtx
	e.instanceEnd = instanceEnd
	e.stopping = false
	e.callMu.Unlock()
}

// beginCall admits one invocation while the active module is stable. The
// returned callback must always be called. stopActiveLocked first prevents new
// admissions, then uses wazero's supported concurrent Close path to interrupt
// the guest, and finally waits for all admitted calls before releasing runtime
// or compiled-module state.
func (e *wazeroEngine) beginCall(ctx context.Context) (api.Module, context.Context, func(), error) {
	e.callMu.Lock()
	if e.closed {
		e.callMu.Unlock()
		return nil, nil, nil, fmt.Errorf("engine is closed")
	}
	if e.stopping || e.module == nil {
		e.callMu.Unlock()
		return nil, nil, nil, fmt.Errorf("no active instance")
	}
	mod := e.module
	instanceCtx := e.instanceCtx
	e.callWG.Add(1)
	e.callMu.Unlock()
	callCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(instanceCtx, cancel)
	done := func() {
		stop()
		cancel()
		e.callWG.Done()
	}
	return mod, callCtx, done, nil
}

func (e *wazeroEngine) stopActiveLocked(ctx context.Context) error {
	e.callMu.Lock()
	mod := e.module
	if mod == nil {
		e.callMu.Unlock()
		return nil
	}
	e.stopping = true
	instanceEnd := e.instanceEnd
	e.callMu.Unlock()

	// Host-network reads do not necessarily observe a Go context while blocked.
	// Closing mediated sockets first makes those calls unwind. Wait before
	// Module.Close: wazero permits concurrent Close for instruction preemption,
	// but closing a module while a WASI socket host call is returning can race in
	// wazero's resource table. The caller controls invocation cancellation; this
	// barrier guarantees resources are released only after host calls unwind.
	if e.netHost != nil {
		e.netHost.closeConns()
	}
	if instanceEnd != nil {
		instanceEnd()
	}
	e.callWG.Wait()
	err := mod.Close(ctx)

	e.callMu.Lock()
	if e.module == mod {
		e.module = nil
		e.instanceCtx = nil
		e.instanceEnd = nil
	}
	if !e.closed {
		e.stopping = false
	}
	e.callMu.Unlock()
	return err
}

func (e *wazeroEngine) InvokeExport(ctx context.Context, name string) error {
	mod, callCtx, done, err := e.beginCall(ctx)
	if err != nil {
		return err
	}
	defer done()
	fn := mod.ExportedFunction(name)
	if fn == nil {
		return fmt.Errorf("export %q not found", name)
	}
	_, err = fn.Call(callCtx)
	return err
}

func (e *wazeroEngine) moduleConfig(caps Capabilities) wazero.ModuleConfig {
	return moduleConfigFor(caps)
}

// moduleConfigFor builds the wazero ModuleConfig for a set of capabilities. It
// is a pure function of caps (no engine state), so both the single-instance
// engine and the MultiInstanceEngine share it — the latter additionally sets a
// per-instance WithName so many instances can coexist on one runtime.
func moduleConfigFor(caps Capabilities) wazero.ModuleConfig {
	cfg := wazero.NewModuleConfig().WithArgs(caps.Args...)
	// Driver/worker invoke _start explicitly (background on create; after listen for HTTP).
	cfg = cfg.WithSysWalltime().WithSysNanotime().WithStartFunctions()
	for k, v := range caps.Env {
		cfg = cfg.WithEnv(k, v)
	}
	// Tell HTTP guests which fd the wasip1 listener landed on. wazero appends the
	// listener after dir preopens, so it is not always fd 3 once /work is mounted.
	if caps.ListenEnabled() {
		cfg = cfg.WithEnv(ListenFDEnv, strconv.Itoa(ListenerFD(caps)))
	}
	return cfg
}

// ListenFDEnv carries the wasip1 listener fd to AerolVM-aware guests. Guests that
// hardcode fd 3 (the bare-wasip1 convention) keep working when no dir preopens are
// configured; guests that also need /work read this env var to find the listener.
const ListenFDEnv = "AEROL_WASM_LISTEN_FD"

// ListenerFD returns the fd wazero assigns the single wasip1 TCP listener:
// stdio (0–2), then len(preopens) dir fds, then the listener (InitFSContext order).
func ListenerFD(caps Capabilities) int {
	return int(fdPreopen) + len(caps.Preopens)
}

func (e *wazeroEngine) Run(ctx context.Context, caps Capabilities, export string) (RunResult, error) {
	if export == "" {
		export = "_start"
	}
	invokeCtx, cancel := WithInvocationDeadline(ctx, caps)
	defer cancel()
	start := time.Now()

	var stdout, stderr bytes.Buffer
	e.lifecycleMu.Lock()
	if err := e.ensureOpenLocked(); err != nil {
		e.lifecycleMu.Unlock()
		return RunResult{}, err
	}
	err := e.instantiateWithIOLocked(invokeCtx, caps, &stdout, &stderr)
	e.lifecycleMu.Unlock()
	if err != nil {
		return RunResult{}, err
	}
	exitCode, err := e.callExport(invokeCtx, export)
	result := RunResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Usage:    UsageStats{WallDurationMs: time.Since(start).Milliseconds()},
	}
	if err != nil {
		var exitErr *sys.ExitError
		if errors.As(err, &exitErr) {
			return result, nil
		}
		result.Stderr = stringsTrimJoin(result.Stderr, err.Error())
		return result, err
	}
	return result, nil
}

func (e *wazeroEngine) instantiateWithIOLocked(ctx context.Context, caps Capabilities, stdout, stderr *bytes.Buffer) error {
	if err := e.ensureMemoryLimit(ctx, caps.MemoryMB); err != nil {
		return err
	}
	if e.compiled == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	if err := e.stopActiveLocked(ctx); err != nil {
		return fmt.Errorf("stop active module: %w", err)
	}
	cfg := e.moduleConfig(caps)
	if stdout != nil {
		cfg = cfg.WithStdout(stdout)
	}
	if stderr != nil {
		cfg = cfg.WithStderr(stderr)
	}
	if fsCfg := e.fsConfigForCaps(caps); fsCfg != nil {
		cfg = cfg.WithFSConfig(fsCfg)
	}
	instCtx := e.withNetworkContext(ctx, caps)
	if err := e.ensureWasiCompatHosts(instCtx); err != nil {
		return err
	}
	mod, err := e.runtime.InstantiateModule(instCtx, e.compiled, cfg)
	if err != nil {
		return fmt.Errorf("instantiate module: %w", err)
	}
	e.publishModule(mod)
	return nil
}

// fsConfigForCaps builds wazero FS mounts. Directory preopens are mounted even
// when a wasip1 listener is enabled, so an HTTP guest can also read /work. wazero
// assigns dir fds before TCP listeners (InitFSContext), so the listener lands at
// fd (3 + len(preopens)) rather than fd 3 — guests learn the right fd from the
// AEROL_WASM_LISTEN_FD env var injected by moduleConfig (see listenerFD).
func (e *wazeroEngine) fsConfigForCaps(caps Capabilities) wazero.FSConfig {
	return fsConfigFor(caps)
}

// fsConfigFor builds directory preopens for a set of capabilities. Pure function
// of caps (no engine state); shared with the MultiInstanceEngine.
func fsConfigFor(caps Capabilities) wazero.FSConfig {
	preopens := caps.Preopens
	if len(preopens) == 0 {
		return nil
	}
	fsCfg := wazero.NewFSConfig()
	for _, p := range preopens {
		guest := p.GuestPath
		if guest == "" {
			guest = "/work"
		}
		fsCfg = fsCfg.WithDirMount(p.HostPath, guest)
	}
	return fsCfg
}

func (e *wazeroEngine) callExport(ctx context.Context, name string) (int, error) {
	mod, callCtx, done, err := e.beginCall(ctx)
	if err != nil {
		return 1, err
	}
	defer done()
	fn := mod.ExportedFunction(name)
	if fn == nil {
		return 1, fmt.Errorf("export %q not found", name)
	}
	_, err = fn.Call(callCtx)
	return exitCodeFromInvoke(err), err
}

func exitCodeFromInvoke(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *sys.ExitError
	if errors.As(err, &exitErr) {
		return int(exitErr.ExitCode())
	}
	return 1
}

func stringsTrimJoin(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "\n" + b
	}
}

func (e *wazeroEngine) CaptureSnapshot(ctx context.Context) (SnapshotCapture, error) {
	mod, _, done, err := e.beginCall(ctx)
	if err != nil {
		return SnapshotCapture{}, err
	}
	defer done()
	mem := mod.Memory()
	if mem == nil || reflect.ValueOf(mem).IsNil() {
		return SnapshotCapture{}, fmt.Errorf("module has no linear memory")
	}
	data, ok := mem.Read(0, mem.Size())
	if !ok {
		return SnapshotCapture{}, fmt.Errorf("read linear memory failed")
	}
	out := append([]byte(nil), data...)
	return SnapshotCapture{
		Memory:    out,
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}, nil
}

func (e *wazeroEngine) RestoreSnapshot(ctx context.Context, snap SnapshotRestoreInput, caps Capabilities) error {
	if err := e.Instantiate(ctx, caps); err != nil {
		return err
	}
	if len(snap.Memory) == 0 {
		return nil
	}
	mod, _, done, err := e.beginCall(ctx)
	if err != nil {
		return err
	}
	defer done()
	mem := mod.Memory()
	if mem == nil {
		return fmt.Errorf("module has no memory export")
	}
	if !mem.Write(0, snap.Memory) {
		return fmt.Errorf("restore linear memory failed (guest size %d, snapshot %d)", mem.Size(), len(snap.Memory))
	}
	return nil
}

func (e *wazeroEngine) ResolvedListenPort() (int, bool) {
	mod, _, done, err := e.beginCall(context.Background())
	if err != nil {
		return 0, false
	}
	defer done()
	return ResolvedListenPort(mod)
}

func (e *wazeroEngine) SupportsListen() bool { return true }

func (e *wazeroEngine) Close(ctx context.Context) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.callMu.Lock()
	if e.closed {
		e.callMu.Unlock()
		return nil
	}
	e.closed = true
	e.callMu.Unlock()
	_ = e.stopActiveLocked(ctx)
	if e.compiled != nil {
		_ = e.compiled.Close(ctx)
		e.compiled = nil
	}
	if e.runtime != nil {
		err := e.runtime.Close(ctx)
		e.runtime = nil
		return err
	}
	return nil
}
