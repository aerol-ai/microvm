package wasm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero/sys"
)

// NoWallTimeout, set as Capabilities.WallTimeoutNs, asks Start for a run with
// no wall-clock deadline. Zero cannot mean that: zero has always meant "use
// DefaultWallTimeout", and every one-shot path relies on it. Only Start reads
// the sentinel; Run, Instantiate and InvokeExport keep treating it like zero.
const NoWallTimeout int64 = -1

// ErrRunKilled is what a killed run's stdin, stdout and stderr return to the
// guest once Kill (or its deadline) has fired.
var ErrRunKilled = errors.New("wasm run killed")

// closeRunWait bounds how long Close waits for killed runs to unwind before
// it releases the runtime underneath them.
var closeRunWait = 5 * time.Second

// Stdio is a long-lived run's standard streams. In may be nil (the guest
// reads EOF). Pass an *io.PipeReader, or any reader whose Close makes a
// blocked Read return, so Kill can free a guest waiting for input: wazero
// cannot interrupt a host read, it only checks the context once the guest is
// back in wasm code. Out and Err may be nil (output is dropped).
type Stdio struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// Running is one long-lived guest started by MultiInstanceEngine.Start.
type Running struct {
	name     string
	cancel   context.CancelFunc
	done     chan struct{}
	killReq  atomic.Bool
	killed   bool
	timedOut bool
	result   RunResult
	err      error
}

// Name is the instance name the run was started under.
func (r *Running) Name() string { return r.name }

// Done is closed once the guest has returned and its module is closed.
func (r *Running) Done() <-chan struct{} { return r.done }

// Wait blocks until the run ends. A guest exit(code) is a normal result, not
// an error; an error means the guest trapped or could not be called.
func (r *Running) Wait() (RunResult, error) {
	<-r.done
	return r.result, r.err
}

// Kill stops the run and returns at once; Wait or Done observe the end. It is
// safe to call more than once, and after the run has ended.
func (r *Running) Kill() {
	r.killReq.Store(true)
	r.cancel()
}

// Killed reports whether Kill was called before the run ended. Valid after Done.
func (r *Running) Killed() bool {
	<-r.done
	return r.killed
}

// TimedOut reports whether the wall-clock deadline ended the run. Valid after Done.
func (r *Running) TimedOut() bool {
	<-r.done
	return r.timedOut
}

// gateWriter forwards to w until the run is stopped, then fails every write,
// so a guest that keeps printing after Kill gets an error instead of more
// output reaching the caller.
type gateWriter struct {
	w      io.Writer
	closed atomic.Bool
}

func newGateWriter(w io.Writer) *gateWriter {
	if w == nil {
		w = io.Discard
	}
	return &gateWriter{w: w}
}

func (g *gateWriter) Write(p []byte) (int, error) {
	if g.closed.Load() {
		return 0, ErrRunKilled
	}
	return g.w.Write(p)
}

// closeStdin makes a Read blocked on in return. A pipe gets ErrRunKilled so
// its writer learns why; any other closer is just closed.
func closeStdin(in io.Reader) {
	switch c := in.(type) {
	case interface{ CloseWithError(error) error }:
		_ = c.CloseWithError(ErrRunKilled)
	case io.Closer:
		_ = c.Close()
	}
}

// startContext applies caps' wall-clock budget, or none for NoWallTimeout.
func startContext(ctx context.Context, caps Capabilities) (context.Context, context.CancelFunc) {
	if caps.WallTimeoutNs == NoWallTimeout {
		return context.WithCancel(ctx)
	}
	return WithInvocationDeadline(ctx, caps)
}

// Start instantiates a fresh instance called name with the given stdio and
// runs export (default _start) on it in the background. It is the streaming
// sibling of Run: the instance lives as long as the guest does, its output
// reaches stdio as it is written, and many runs share this engine's compiled
// module without touching each other or any instance made by Instantiate.
//
// The network hook bound to name (SetNetworkHook) belongs to the run and is
// dropped when it ends. The context, the caps' wall timeout (or none with
// NoWallTimeout) and Kill all stop the run the same way.
func (m *MultiInstanceEngine) Start(ctx context.Context, name string, caps Capabilities, export string, stdio Stdio) (*Running, error) {
	if name == "" {
		return nil, fmt.Errorf("instance name required")
	}
	if export == "" {
		export = "_start"
	}
	m.mu.Lock()
	if m.compiled == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("no compiled module loaded")
	}
	if err := m.ensureNetworkHostLocked(ctx); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if _, ok := m.instances[name]; ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("instance %q already exists", name)
	}
	// Runtime.Module also covers the host modules (wasi_snapshot_preview1,
	// aerol/vm/net): wazero fails an instantiate under one of their names
	// only after dropping the existing module from its namespace, which
	// would break every later instantiate on this runtime.
	if _, ok := m.running[name]; ok || m.runtime.Module(name) != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("instance %q already exists", name)
	}
	if m.running == nil {
		m.running = make(map[string]*Running)
	}
	runCtx, cancel := startContext(ctx, caps)
	r := &Running{name: name, cancel: cancel, done: make(chan struct{})}
	// Reserve the name before instantiating outside the lock, so a second
	// Start with the same name fails instead of racing wazero's own check.
	m.running[name] = r
	compiled, runtime, host := m.compiled, m.runtime, m.netHost
	m.mu.Unlock()

	release := func() {
		m.mu.Lock()
		if m.running[name] == r {
			delete(m.running, name)
		}
		m.mu.Unlock()
	}
	out, errw := newGateWriter(stdio.Out), newGateWriter(stdio.Err)
	cfg := moduleConfigFor(caps).WithName(name).WithStdout(out).WithStderr(errw)
	if stdio.In != nil {
		cfg = cfg.WithStdin(stdio.In)
	}
	// wazero stops a guest in wasm code when runCtx ends, but not one
	// blocked in a host call. Free those first, in the order the engine
	// teardown uses (engine_wazero.go stopActiveLocked): mediated sockets,
	// then stdin, then the output writers.
	stopUnblock := context.AfterFunc(runCtx, func() {
		host.closeConns(name)
		closeStdin(stdio.In)
		out.closed.Store(true)
		errw.closed.Store(true)
	})
	fail := func(err error) (*Running, error) {
		stopUnblock()
		cancel()
		host.clearSandbox(name)
		release()
		return nil, err
	}
	start := time.Now()
	// Through instantiateWithPreopens like every other instance, so the
	// run's /work is the same confined mount (confined_fs.go).
	mod, err := instantiateWithPreopens(runCtx, runtime, compiled, cfg, caps)
	if err != nil {
		return fail(fmt.Errorf("instantiate module: %w", err))
	}
	fn := mod.ExportedFunction(export)
	if fn == nil {
		_ = mod.Close(context.Background())
		return fail(fmt.Errorf("export %q not found", export))
	}
	go func() {
		_, callErr := fn.Call(runCtx)
		r.killed = r.killReq.Load()
		r.timedOut = !r.killed && errors.Is(runCtx.Err(), context.DeadlineExceeded)
		stopUnblock()
		// The guest has returned, so nothing is blocked in a host call any
		// more: drop its sockets and hook, then close the module.
		host.clearSandbox(name)
		_ = mod.Close(context.Background())
		cancel()
		r.result = RunResult{
			ExitCode: exitCodeFromInvoke(callErr),
			Usage:    UsageStats{WallDurationMs: time.Since(start).Milliseconds()},
		}
		var exitErr *sys.ExitError
		if callErr != nil && !errors.As(callErr, &exitErr) {
			r.err = callErr
		}
		release()
		close(r.done)
	}()
	return r, nil
}

// RunningCount is the number of live Start runs (for tests and idle reaping).
func (m *MultiInstanceEngine) RunningCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.running)
}

// killRunning stops every live run and waits, up to closeRunWait in all, for
// them to unwind. Close calls it before releasing the runtime.
func killRunning(runs map[string]*Running) {
	for _, r := range runs {
		r.Kill()
	}
	deadline := time.NewTimer(closeRunWait)
	defer deadline.Stop()
	for _, r := range runs {
		select {
		case <-r.done:
		case <-deadline.C:
			return
		}
	}
}
