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
	runtime     wazero.Runtime
	compiled    wazero.CompiledModule
	module      api.Module
	moduleBytes []byte
	memoryPages uint32
	netHook     *NetworkHook
	netHost     *wazeroNetHost
	wasiCompat  bool
}

func newWazeroEngine(ctx context.Context) (*wazeroEngine, error) {
	e := &wazeroEngine{}
	if err := e.initRuntime(ctx, 0); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *wazeroEngine) initRuntime(ctx context.Context, memoryMB int) error {
	if e.module != nil {
		_ = e.module.Close(ctx)
		e.module = nil
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
	cfg := wazero.NewRuntimeConfig()
	if pages > 0 {
		cfg = cfg.WithMemoryLimitPages(pages)
	}
	if dir := wazeroCompileCacheDir(); dir != "" {
		cache, err := wazero.NewCompilationCacheWithDir(dir)
		if err != nil {
			return fmt.Errorf("compilation cache: %w", err)
		}
		cfg = cfg.WithCompilationCache(cache)
	}
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return fmt.Errorf("wasi instantiate: %w", err)
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
	if e.module != nil {
		_ = e.module.Close(ctx)
		e.module = nil
	}
	if e.compiled != nil {
		_ = e.compiled.Close(ctx)
		e.compiled = nil
	}
	// Drop stale bytes before initRuntime — it recompiles moduleBytes when
	// rebuilding the runtime (ensureMemoryLimit path), and a failed prior load
	// must not poison the next path.
	e.moduleBytes = nil
	if err := e.initRuntime(ctx, opts.MemoryMB); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	compiled, err := compileModule(e.runtime, ctx, b)
	if err != nil {
		return fmt.Errorf("compile module: %w", err)
	}
	e.moduleBytes = append([]byte(nil), b...)
	e.compiled = compiled
	return nil
}

func (e *wazeroEngine) Instantiate(ctx context.Context, caps Capabilities) error {
	if len(e.moduleBytes) == 0 && e.compiled == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	if err := e.ensureMemoryLimit(ctx, caps.MemoryMB); err != nil {
		return err
	}
	if e.compiled == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	if e.module != nil {
		_ = e.module.Close(ctx)
		e.module = nil
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
	e.module = mod
	return nil
}

func (e *wazeroEngine) StopInstance(ctx context.Context) error {
	if e.module == nil {
		return nil
	}
	err := e.module.Close(ctx)
	e.module = nil
	return err
}

func (e *wazeroEngine) InvokeExport(ctx context.Context, name string) error {
	if e.module == nil {
		return fmt.Errorf("no active instance")
	}
	fn := e.module.ExportedFunction(name)
	if fn == nil {
		return fmt.Errorf("export %q not found", name)
	}
	_, err := fn.Call(ctx)
	return err
}

func (e *wazeroEngine) moduleConfig(caps Capabilities) wazero.ModuleConfig {
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
	if err := e.instantiateWithIO(invokeCtx, caps, &stdout, &stderr); err != nil {
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

func (e *wazeroEngine) instantiateWithIO(ctx context.Context, caps Capabilities, stdout, stderr *bytes.Buffer) error {
	if err := e.ensureMemoryLimit(ctx, caps.MemoryMB); err != nil {
		return err
	}
	if e.compiled == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	if e.module != nil {
		_ = e.module.Close(ctx)
		e.module = nil
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
	e.module = mod
	return nil
}

// fsConfigForCaps builds wazero FS mounts. Directory preopens are mounted even
// when a wasip1 listener is enabled, so an HTTP guest can also read /work. wazero
// assigns dir fds before TCP listeners (InitFSContext), so the listener lands at
// fd (3 + len(preopens)) rather than fd 3 — guests learn the right fd from the
// AEROL_WASM_LISTEN_FD env var injected by moduleConfig (see listenerFD).
func (e *wazeroEngine) fsConfigForCaps(caps Capabilities) wazero.FSConfig {
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
	if e.module == nil {
		return 1, fmt.Errorf("no active instance")
	}
	fn := e.module.ExportedFunction(name)
	if fn == nil {
		return 1, fmt.Errorf("export %q not found", name)
	}
	_, err := fn.Call(ctx)
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

func (e *wazeroEngine) CaptureSnapshot(_ context.Context) (SnapshotCapture, error) {
	if e.module == nil {
		return SnapshotCapture{}, fmt.Errorf("no active instance")
	}
	mem := e.module.Memory()
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
	mem := e.module.Memory()
	if mem == nil {
		return fmt.Errorf("module has no memory export")
	}
	if !mem.Write(0, snap.Memory) {
		return fmt.Errorf("restore linear memory failed (guest size %d, snapshot %d)", mem.Size(), len(snap.Memory))
	}
	return nil
}

func (e *wazeroEngine) ResolvedListenPort() (int, bool) {
	return ResolvedListenPort(e.module)
}

func (e *wazeroEngine) SupportsListen() bool { return true }

func (e *wazeroEngine) Close(ctx context.Context) error {
	if e.module != nil {
		_ = e.module.Close(ctx)
		e.module = nil
	}
	if e.compiled != nil {
		_ = e.compiled.Close(ctx)
		e.compiled = nil
	}
	if e.runtime != nil {
		return e.runtime.Close(ctx)
	}
	return nil
}
