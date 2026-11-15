//go:build wasmtime

package wasm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/wasmtime-go/v37"
)

const defaultWasmtimeFuel uint64 = 10_000_000_000

type wasmtimeEngine struct {
	engine      *wasmtime.Engine
	module      *wasmtime.Module
	moduleBytes []byte
	// memoryOK is whether module exports the memory the WASI layer needs
	// (wasip1MemoryExported). Without it the guest gets wasmtime's WASI
	// alone, and no listener.
	memoryOK bool
	// tramp is the WASI layer's trampoline (wasmtime_sockets.go), compiled
	// on first use and instantiated per store.
	tramp    *wasmtime.Module
	lastCaps Capabilities
	netHook  *NetworkHook

	// mu guards cur. A call into the guest runs without it, holding a
	// place in cur.calls instead, so stopping an instance never queues
	// behind the guest it stops.
	mu  sync.Mutex
	cur *wasmtimeInstance
}

// wasmtimeInstance is one instantiation of the module: its store and what
// lives in it. A wasmtime store is not safe to release while a call runs
// in it, so release waits for calls, and interrupt makes them end: the
// epoch for guest code, the stop pipe for a wait in the socket layer, and
// closing the egress connections for a mediated read.
type wasmtimeInstance struct {
	store    *wasmtime.Store
	instance *wasmtime.Instance
	linker   *wasmtime.Linker
	netHost  *wasmtimeNetHost
	// wasi is the socket and poll layer; nil when the module exports no
	// memory it can use.
	wasi *wasmtimeWasip1

	calls sync.WaitGroup
	// mu orders interrupt against release: an interrupt that comes late
	// (a context's AfterFunc) must not touch an engine that may be closed.
	mu       sync.Mutex
	released bool
	// ended is set when a call into the guest fails: it exited, trapped or
	// was stopped, and serves no listener from then on.
	ended atomic.Bool
}

func newWasmtimeEngine(_ context.Context) (Engine, error) {
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetEpochInterruption(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	return &wasmtimeEngine{engine: engine}, nil
}

func (e *wasmtimeEngine) LoadModule(_ context.Context, path string, _ LoadOptions) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read module: %w", err)
	}
	mod, err := wasmtime.NewModule(e.engine, data)
	if err != nil {
		return fmt.Errorf("compile module: %w", err)
	}
	e.dropInstance()
	if e.module != nil {
		e.module.Close()
	}
	e.module = mod
	e.moduleBytes = append([]byte(nil), data...)
	e.memoryOK = wasip1MemoryExported(mod)
	return nil
}

// dropInstance stops the current instance and releases it once no call
// runs in it.
func (e *wasmtimeEngine) dropInstance() {
	e.mu.Lock()
	inst := e.cur
	e.cur = nil
	e.mu.Unlock()
	if inst == nil {
		return
	}
	inst.interrupt(e.engine)
	inst.calls.Wait()
	inst.release()
}

// interrupt makes every call running in the instance end. Safe from any
// goroutine; after release it does nothing.
func (inst *wasmtimeInstance) interrupt(engine *wasmtime.Engine) {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.released {
		return
	}
	if inst.wasi != nil {
		inst.wasi.socks.stop()
	}
	inst.netHost.shutdown()
	// Every store's deadline is one epoch ahead (buildInstance), so one
	// tick traps guest code at its next loop head or call. The engine is
	// this sandbox's alone: no other sandbox's store sees the tick.
	engine.IncrementEpoch()
}

// release frees the store and the host sockets. The caller has made sure
// no call runs in the instance.
func (inst *wasmtimeInstance) release() {
	inst.mu.Lock()
	inst.released = true
	inst.mu.Unlock()
	inst.netHost.shutdown()
	if inst.wasi != nil {
		inst.wasi.socks.close()
	}
	if inst.linker != nil {
		inst.linker.Close()
	}
	if inst.store != nil {
		inst.store.Close()
	}
}

// publish makes inst the current instance.
func (e *wasmtimeEngine) publish(inst *wasmtimeInstance) {
	e.mu.Lock()
	e.cur = inst
	e.mu.Unlock()
}

// begin admits one call into the current instance. The caller ends it
// with inst.calls.Done.
func (e *wasmtimeEngine) begin() (*wasmtimeInstance, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur == nil {
		return nil, fmt.Errorf("no active instance")
	}
	e.cur.calls.Add(1)
	return e.cur, nil
}

// call runs export in inst until it returns or ctx ends. Wall time is the
// caller's context (WithInvocationDeadline): when it ends, the instance is
// interrupted and the call traps, as wazero closes a module whose context
// ends.
func (e *wasmtimeEngine) call(ctx context.Context, inst *wasmtimeInstance, export string) error {
	fn := inst.instance.GetFunc(inst.store, export)
	if fn == nil {
		return fmt.Errorf("export %q not found", export)
	}
	engine := e.engine
	stop := context.AfterFunc(ctx, func() { inst.interrupt(engine) })
	_, err := fn.Call(inst.store)
	stop()
	if err != nil {
		inst.ended.Store(true)
	}
	return err
}

func (e *wasmtimeEngine) Instantiate(_ context.Context, caps Capabilities) error {
	if e.module == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	e.dropInstance()
	inst, err := e.buildInstance(caps, "", "")
	if err != nil {
		return err
	}
	e.publish(inst)
	e.lastCaps = caps
	return nil
}

func (e *wasmtimeEngine) meter() ByteMeter {
	if e.netHook == nil {
		return nil
	}
	return e.netHook.Meter
}

// trampoline is the compiled WASI trampoline, compiled on first use.
func (e *wasmtimeEngine) trampoline() (*wasmtime.Module, error) {
	if e.tramp == nil {
		mod, err := compileWasip1Trampoline(e.engine)
		if err != nil {
			return nil, err
		}
		e.tramp = mod
	}
	return e.tramp, nil
}

func (e *wasmtimeEngine) buildInstance(caps Capabilities, stdoutPath, stderrPath string) (*wasmtimeInstance, error) {
	listeners := caps.Listeners()
	if len(listeners) > 0 && (!wasip1SocketsSupported || !e.memoryOK) {
		return nil, errors.New("a wasip1 listener on the wasmtime engine needs Linux or macOS and a module that exports its memory as \"memory\"")
	}
	inst := &wasmtimeInstance{store: wasmtime.NewStore(e.engine)}
	fail := func(err error) (*wasmtimeInstance, error) {
		inst.release()
		return nil, err
	}
	if err := inst.store.SetFuel(defaultWasmtimeFuel); err != nil {
		return fail(fmt.Errorf("set fuel: %w", err))
	}
	// The deadline is the next epoch: guest code runs until interrupt
	// advances it. Wall time is enforced by the call's context instead
	// (call), so a guest blocked in a host call is stopped too.
	inst.store.SetEpochDeadline(1)

	if e.memoryOK && wasip1SocketsSupported {
		socks, err := newWasip1Sockets(listeners, caps.WASIListenHost, e.meter())
		if err != nil {
			return fail(err)
		}
		inst.wasi = &wasmtimeWasip1{socks: socks, sockets: len(listeners) > 0}
	}

	wasi, err := e.wasiConfig(caps, inst.wasi, stdoutPath, stderrPath)
	if err != nil {
		return fail(err)
	}
	inst.store.SetWasi(wasi)

	inst.linker = wasmtime.NewLinker(e.engine)
	if err := inst.linker.DefineWasi(); err != nil {
		return fail(fmt.Errorf("define wasi: %w", err))
	}
	if inst.wasi != nil {
		if err := inst.wasi.define(inst.linker); err != nil {
			return fail(err)
		}
	}
	if inst.netHost, err = e.newNetworkHost(inst.linker); err != nil {
		return fail(err)
	}
	instance, err := inst.linker.Instantiate(inst.store, e.module)
	if err != nil {
		return fail(fmt.Errorf("instantiate module: %w", err))
	}
	inst.instance = instance
	if inst.wasi != nil {
		tramp, err := e.trampoline()
		if err != nil {
			return fail(err)
		}
		if err := inst.wasi.attach(e.engine, inst.store, instance, tramp); err != nil {
			return fail(err)
		}
	}
	return inst, nil
}

// wasiConfig is the WASI configuration for caps. A guest with listeners
// learns their fds from ListenFDEnv / ListenFDsEnv, as on wazero; only the
// numbers differ (wasip1SocketFDBase).
func (e *wasmtimeEngine) wasiConfig(caps Capabilities, layer *wasmtimeWasip1, stdoutPath, stderrPath string) (*wasmtime.WasiConfig, error) {
	wasi := wasmtime.NewWasiConfig()
	fail := func(err error) (*wasmtime.WasiConfig, error) {
		wasi.Close()
		return nil, err
	}
	if len(caps.Args) > 0 {
		wasi.SetArgv(caps.Args)
	} else {
		wasi.InheritArgv()
	}
	env := make(map[string]string, len(caps.Env)+2)
	for k, v := range caps.Env {
		env[k] = v
	}
	if layer != nil {
		if fds := layer.socks.listenerFDs(); len(fds) > 0 {
			env[ListenFDEnv] = strconv.Itoa(fds[0])
			if len(caps.WASIListeners) > 0 {
				env[ListenFDsEnv] = listenFDsValueFor(caps.Listeners(), fds)
			}
		}
	}
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		vals := make([]string, 0, len(env))
		for k, v := range env {
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
		// wasmtime's WASI resolves preopens with cap-std, which already
		// keeps every lookup inside the directory; only the access mode is
		// ours to set.
		dirPerms := wasmtime.DIR_READ | wasmtime.DIR_WRITE
		filePerms := wasmtime.FILE_READ | wasmtime.FILE_WRITE
		if p.ReadOnly {
			dirPerms, filePerms = wasmtime.DIR_READ, wasmtime.FILE_READ
		}
		if err := wasi.PreopenDir(p.HostPath, guest, dirPerms, filePerms); err != nil {
			return fail(fmt.Errorf("preopen %s: %w", p.HostPath, err))
		}
	}
	if stdoutPath != "" {
		if err := wasi.SetStdoutFile(stdoutPath); err != nil {
			return fail(fmt.Errorf("stdout file: %w", err))
		}
	} else {
		wasi.InheritStdout()
	}
	if stderrPath != "" {
		if err := wasi.SetStderrFile(stderrPath); err != nil {
			return fail(fmt.Errorf("stderr file: %w", err))
		}
	} else {
		wasi.InheritStderr()
	}
	return wasi, nil
}

func (e *wasmtimeEngine) StopInstance(_ context.Context) error {
	e.dropInstance()
	return nil
}

func (e *wasmtimeEngine) InvokeExport(ctx context.Context, name string) error {
	inst, err := e.begin()
	if err != nil {
		return err
	}
	defer inst.calls.Done()
	return e.call(ctx, inst, name)
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
	if e.module == nil {
		return RunResult{}, fmt.Errorf("no compiled module loaded")
	}
	e.dropInstance()
	inst, err := e.buildInstance(caps, stdoutPath, stderrPath)
	if err != nil {
		return RunResult{}, err
	}
	// Admitted before it is published, so a stop that finds it waits for
	// this run.
	inst.calls.Add(1)
	defer inst.calls.Done()
	e.publish(inst)
	e.lastCaps = caps

	err = e.call(invokeCtx, inst, export)
	exitCode, exited := wasmtimeExitCode(err)
	if exited {
		// proc_exit is how a guest ends, not a failure of the run (wazero
		// treats its sys.ExitError the same way).
		err = nil
	}
	stdout, _ := os.ReadFile(stdoutPath)
	stderr, _ := os.ReadFile(stderrPath)

	// The store started with defaultWasmtimeFuel; what is gone is what the
	// run used.
	instructions := int64(0)
	if fuelAfter, fuelErr := inst.store.GetFuel(); fuelErr == nil && fuelAfter <= defaultWasmtimeFuel {
		instructions = int64(defaultWasmtimeFuel - fuelAfter)
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
	if err != nil {
		// A trap: exit code 1 with the trap in stderr, as on wazero.
		result.Stderr = stringsTrimJoin(result.Stderr, err.Error())
		return result, err
	}
	return result, nil
}

// wasmtimeExitCode is the guest's exit code for a call's error, and whether
// the guest exited (proc_exit) rather than failed. A trap is exit code 1.
func wasmtimeExitCode(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var werr *wasmtime.Error
	if errors.As(err, &werr) {
		if status, ok := werr.ExitStatus(); ok {
			return int(status), true
		}
	}
	return 1, false
}

func (e *wasmtimeEngine) CaptureSnapshot(_ context.Context) (SnapshotCapture, error) {
	inst, err := e.begin()
	if err != nil {
		return SnapshotCapture{}, err
	}
	defer inst.calls.Done()
	memExport := inst.instance.GetExport(inst.store, "memory")
	if memExport == nil {
		return SnapshotCapture{}, fmt.Errorf("module has no memory export")
	}
	mem := memExport.Memory()
	if mem == nil {
		return SnapshotCapture{}, fmt.Errorf("module has no linear memory")
	}
	data := mem.UnsafeData(inst.store)
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
	inst, err := e.begin()
	if err != nil {
		return err
	}
	defer inst.calls.Done()
	memExport := inst.instance.GetExport(inst.store, "memory")
	if memExport == nil {
		return fmt.Errorf("module has no memory export")
	}
	mem := memExport.Memory()
	if mem == nil {
		return fmt.Errorf("module has no linear memory")
	}
	if int(mem.DataSize(inst.store)) < len(snap.Memory) {
		currentPages := mem.Size(inst.store)
		needPages := uint64((len(snap.Memory) + 65535) / 65536)
		if needPages > currentPages {
			if _, err := mem.Grow(inst.store, needPages-currentPages); err != nil {
				return fmt.Errorf("grow memory: %w", err)
			}
		}
	}
	buf := mem.UnsafeData(inst.store)
	if len(buf) < len(snap.Memory) {
		return fmt.Errorf("restore linear memory failed (guest size %d, snapshot %d)", len(buf), len(snap.Memory))
	}
	copy(buf[:len(snap.Memory)], snap.Memory)
	return nil
}

// liveListen is the running instance's listener state, nil when it has
// none or its guest has stopped serving. Safe while the guest runs: it
// never touches the store.
func (e *wasmtimeEngine) liveListen() *instanceListen {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur == nil || e.cur.wasi == nil || e.cur.ended.Load() {
		return nil
	}
	return e.cur.wasi.socks.listen
}

// ResolvedListenPort is the host port of the first live listener.
func (e *wasmtimeEngine) ResolvedListenPort() (int, bool) {
	live := e.liveListen().live()
	if len(live) == 0 {
		return 0, false
	}
	return live[0].hostPort, true
}

// ResolvedListeners is MultiListenEngine: the live listeners, ascending by
// guest port.
func (e *wasmtimeEngine) ResolvedListeners() []WASIListener {
	live := e.liveListen().live()
	if len(live) == 0 {
		return nil
	}
	out := make([]WASIListener, len(live))
	for i, b := range live {
		out[i] = WASIListener{GuestPort: b.guestPort, HostPort: b.hostPort}
	}
	return out
}

// ListenerAccepted is MultiListenEngine: whether the guest has called
// sock_accept on guestPort's listener.
func (e *wasmtimeEngine) ListenerAccepted(guestPort int) bool {
	return e.liveListen().acceptedOn(guestPort)
}

// SupportsListen: the engine pre-opens listeners itself through its WASI
// socket layer (wasmtime_sockets.go), on the hosts that layer runs on and
// for a module that exports its memory, as every WASI guest does. For any
// other the worker moves the sandbox to wazero (worker/listen_engine.go).
func (e *wasmtimeEngine) SupportsListen() bool {
	return wasip1SocketsSupported && (e.module == nil || e.memoryOK)
}

func (e *wasmtimeEngine) Close(_ context.Context) error {
	e.dropInstance()
	if e.module != nil {
		e.module.Close()
		e.module = nil
	}
	if e.tramp != nil {
		e.tramp.Close()
		e.tramp = nil
	}
	e.moduleBytes = nil
	if e.engine != nil {
		e.engine.Close()
		e.engine = nil
	}
	return nil
}
