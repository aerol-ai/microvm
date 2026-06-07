//go:build wasmtime

package wasm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bytecodealliance/wasmtime-go/v37"
)

const defaultWasmtimeFuel uint64 = 10_000_000_000

type wasmtimeEngine struct {
	engine      *wasmtime.Engine
	module      *wasmtime.Module
	moduleBytes []byte
	store       *wasmtime.Store
	instance    *wasmtime.Instance
	linker      *wasmtime.Linker
	wasi        *wasmtime.WasiConfig
	lastCaps    Capabilities
	netHook     *NetworkHook
	netHost     *wasmtimeNetHost
}

func newWasmtimeEngine(_ context.Context) (Engine, error) {
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetEpochInterruption(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	return &wasmtimeEngine{engine: engine}, nil
}

func (e *wasmtimeEngine) LoadModule(_ context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read module: %w", err)
	}
	mod, err := wasmtime.NewModule(e.engine, data)
	if err != nil {
		return fmt.Errorf("compile module: %w", err)
	}
	if e.module != nil {
		e.module.Close()
	}
	e.module = mod
	e.moduleBytes = append([]byte(nil), data...)
	e.dropInstance()
	return nil
}

func (e *wasmtimeEngine) dropInstance() {
	e.instance = nil
	e.linker = nil
	e.netHost = nil
	if e.store != nil {
		e.store.Close()
		e.store = nil
	}
	if e.wasi != nil {
		e.wasi.Close()
		e.wasi = nil
	}
}

func (e *wasmtimeEngine) Instantiate(ctx context.Context, caps Capabilities) error {
	if e.module == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	e.dropInstance()
	if err := e.buildInstance(ctx, caps, "", ""); err != nil {
		return err
	}
	e.lastCaps = caps
	return nil
}

func (e *wasmtimeEngine) buildInstance(_ context.Context, caps Capabilities, stdoutPath, stderrPath string) error {
	store := wasmtime.NewStore(e.engine)
	if err := store.SetFuel(defaultWasmtimeFuel); err != nil {
		store.Close()
		return fmt.Errorf("set fuel: %w", err)
	}
	if d := WallTimeoutFromCaps(caps); d > 0 {
		store.SetEpochDeadline(uint64(d.Milliseconds()))
	}

	wasi := wasmtime.NewWasiConfig()
	if len(caps.Args) > 0 {
		wasi.SetArgv(caps.Args)
	} else {
		wasi.InheritArgv()
	}
	if len(caps.Env) > 0 {
		keys := make([]string, 0, len(caps.Env))
		vals := make([]string, 0, len(caps.Env))
		for k, v := range caps.Env {
			keys = append(keys, k)
			vals = append(vals, v)
		}
		wasi.SetEnv(keys, vals)
	} else {
		wasi.InheritEnv()
	}
	for _, p := range caps.Preopens {
		guest := p.GuestPath
		if guest == "" {
			guest = "/"
		}
		dirPerms := wasmtime.DIR_READ | wasmtime.DIR_WRITE
		filePerms := wasmtime.FILE_READ | wasmtime.FILE_WRITE
		if err := wasi.PreopenDir(p.HostPath, guest, dirPerms, filePerms); err != nil {
			wasi.Close()
			store.Close()
			return fmt.Errorf("preopen %s: %w", p.HostPath, err)
		}
	}
	if stdoutPath != "" {
		if err := wasi.SetStdoutFile(stdoutPath); err != nil {
			wasi.Close()
			store.Close()
			return fmt.Errorf("stdout file: %w", err)
		}
	} else {
		wasi.InheritStdout()
	}
	if stderrPath != "" {
		if err := wasi.SetStderrFile(stderrPath); err != nil {
			wasi.Close()
			store.Close()
			return fmt.Errorf("stderr file: %w", err)
		}
	} else {
		wasi.InheritStderr()
	}
	store.SetWasi(wasi)

	linker := wasmtime.NewLinker(e.engine)
	if err := linker.DefineWasi(); err != nil {
		wasi.Close()
		store.Close()
		return fmt.Errorf("define wasi: %w", err)
	}
	if err := e.ensureNetworkHost(linker); err != nil {
		wasi.Close()
		store.Close()
		return err
	}
	instance, err := linker.Instantiate(store, e.module)
	if err != nil {
		wasi.Close()
		store.Close()
		return fmt.Errorf("instantiate module: %w", err)
	}
	e.store = store
	e.wasi = wasi
	e.linker = linker
	e.instance = instance
	return nil
}

func (e *wasmtimeEngine) StopInstance(_ context.Context) error {
	e.dropInstance()
	return nil
}

func (e *wasmtimeEngine) InvokeExport(_ context.Context, name string) error {
	if e.instance == nil || e.store == nil {
		return fmt.Errorf("no active instance")
	}
	fn := e.instance.GetFunc(e.store, name)
	if fn == nil {
		return fmt.Errorf("export %q not found", name)
	}
	_, err := fn.Call(e.store)
	return err
}

func (e *wasmtimeEngine) Run(ctx context.Context, caps Capabilities, export string) (RunResult, error) {
	if export == "" {
		export = "_start"
	}
	invokeCtx, cancel := WithInvocationDeadline(ctx, caps)
	defer cancel()

	dir := os.TempDir()
	stdoutPath := filepath.Join(dir, fmt.Sprintf("aerol-wasm-stdout-%d", time.Now().UnixNano()))
	stderrPath := filepath.Join(dir, fmt.Sprintf("aerol-wasm-stderr-%d", time.Now().UnixNano()))
	defer os.Remove(stdoutPath)
	defer os.Remove(stderrPath)

	start := time.Now()
	fuelBefore := defaultWasmtimeFuel
	if e.store != nil {
		if f, err := e.store.GetFuel(); err == nil {
			fuelBefore = f
		}
	}
	e.dropInstance()
	if err := e.buildInstance(invokeCtx, caps, stdoutPath, stderrPath); err != nil {
		return RunResult{}, err
	}
	e.lastCaps = caps

	fn := e.instance.GetFunc(e.store, export)
	if fn == nil {
		return RunResult{}, fmt.Errorf("export %q not found", export)
	}
	_, err := fn.Call(e.store)
	exitCode := wasmtimeExitCode(err)
	stdout, _ := os.ReadFile(stdoutPath)
	stderr, _ := os.ReadFile(stderrPath)

	fuelAfter, fuelErr := e.store.GetFuel()
	instructions := int64(0)
	if fuelErr == nil && fuelBefore >= fuelAfter {
		instructions = int64(fuelBefore - fuelAfter)
	}

	result := RunResult{
		ExitCode: exitCode,
		Stdout:   string(stdout),
		Stderr:   string(stderr),
		Usage: UsageStats{
			WallDurationMs: time.Since(start).Milliseconds(),
			Instructions:   instructions,
		},
	}
	if err != nil && exitCode == 0 {
		result.Stderr = stringsTrimJoin(result.Stderr, err.Error())
		return result, err
	}
	return result, nil
}

func wasmtimeExitCode(err error) int {
	if err == nil {
		return 0
	}
	var trap *wasmtime.Trap
	if errors.As(err, &trap) {
		msg := trap.Message()
		if strings.Contains(msg, "exit") {
			return 1
		}
	}
	return 1
}

func (e *wasmtimeEngine) CaptureSnapshot(_ context.Context) (SnapshotCapture, error) {
	if e.instance == nil || e.store == nil {
		return SnapshotCapture{}, fmt.Errorf("no active instance")
	}
	memExport := e.instance.GetExport(e.store, "memory")
	if memExport == nil {
		return SnapshotCapture{}, fmt.Errorf("module has no memory export")
	}
	mem := memExport.Memory()
	if mem == nil {
		return SnapshotCapture{}, fmt.Errorf("module has no linear memory")
	}
	data := mem.UnsafeData(e.store)
	out := append([]byte(nil), data...)
	return SnapshotCapture{
		Memory:    out,
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}, nil
}

func (e *wasmtimeEngine) RestoreSnapshot(ctx context.Context, snap SnapshotRestoreInput, caps Capabilities) error {
	if err := e.Instantiate(ctx, caps); err != nil {
		return err
	}
	if len(snap.Memory) == 0 {
		return nil
	}
	memExport := e.instance.GetExport(e.store, "memory")
	if memExport == nil {
		return fmt.Errorf("module has no memory export")
	}
	mem := memExport.Memory()
	if mem == nil {
		return fmt.Errorf("module has no linear memory")
	}
	if int(mem.DataSize(e.store)) < len(snap.Memory) {
		currentPages := mem.Size(e.store)
		needPages := uint64((len(snap.Memory) + 65535) / 65536)
		if needPages > currentPages {
			if _, err := mem.Grow(e.store, needPages-currentPages); err != nil {
				return fmt.Errorf("grow memory: %w", err)
			}
		}
	}
	buf := mem.UnsafeData(e.store)
	if len(buf) < len(snap.Memory) {
		return fmt.Errorf("restore linear memory failed (guest size %d, snapshot %d)", len(buf), len(snap.Memory))
	}
	copy(buf[:len(snap.Memory)], snap.Memory)
	return nil
}

func (e *wasmtimeEngine) ResolvedListenPort() (int, bool) {
	return 0, false
}

// SupportsListen is false: the wasmtime backend does not yet wire a wasip1 TCP
// listener, so HTTP ingress / expose_port is rejected up front (see
// plans/wasm-runtime.md "Still open"). Use the default wazero engine for ingress.
func (e *wasmtimeEngine) SupportsListen() bool { return false }

func (e *wasmtimeEngine) Close(_ context.Context) error {
	e.dropInstance()
	if e.module != nil {
		e.module.Close()
		e.module = nil
	}
	e.moduleBytes = nil
	if e.engine != nil {
		e.engine.Close()
		e.engine = nil
	}
	return nil
}
