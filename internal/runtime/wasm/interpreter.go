package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/drivers"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// Code interpreter on WASM (issue #178, plans/code-interpreter.md D5, D12,
// W5). A context is one long-lived python.wasm instance in the sandbox's
// own worker, started with StartStream like any other run: it gets the
// sandbox's /work, memory limit, env, network blocks and egress policy, and
// counts toward the sandbox's run cap. The shared Python driver runs in
// "stdio" mode: requests go to the instance's stdin and events come back on
// its stdout as frames. The driver source travels as an argument, so
// nothing is written under /work and nothing runs on the host.

// interpreterDefaultCwd is where a context starts when it names no cwd: the
// only folder a WASM sandbox has.
const interpreterDefaultCwd = "/work"

// interpreterDriverName is the file name Python reports for the driver's
// own frames. It is not "<string>", so the driver trims only its own frames
// from a traceback, not those of code the user runs with exec().
const interpreterDriverName = "<aerolvm-interpreter>"

// interpreterBootstrap is the -c program: it compiles the driver source
// (the next argument) under interpreterDriverName and runs it as __main__.
var interpreterBootstrap = `import sys;exec(compile(sys.argv.pop(1),"` + interpreterDriverName + `","exec"))`

// interpreterStderrTail is how much of an instance's raw stderr is kept
// outside a run, to explain a driver that dies before READY.
const interpreterStderrTail = 4 << 10

// interpStream is the part of a Stream a kernel uses; tests fake it. There
// is no Kill: closing the stream ends the run (see interpKernel.Close).
type interpStream interface {
	Recv() (StreamEvent, error)
	WriteStdin(p []byte) error
	Close() error
}

// interpreterLauncher implements codeinterp.Launcher for one sandbox.
type interpreterLauncher struct {
	sandboxID string
	// module resolves the python module ("" and an error when none is
	// configured); forget drops a cached path after a failed start.
	module func() (string, error)
	forget func(path string)
	start  func(ctx context.Context, spec StreamSpec) (interpStream, error)
	// readyTimeout bounds the wait for the driver's READY.
	readyTimeout time.Duration
}

func (d *Driver) interpreterLauncher(sandboxID string) *interpreterLauncher {
	return &interpreterLauncher{
		sandboxID: sandboxID,
		module:    d.interpreterModulePath,
		forget: func(path string) {
			for _, lang := range interpreterModuleLanguages {
				d.forgetCodeRunModule(lang, path)
			}
		},
		start: func(ctx context.Context, spec StreamSpec) (interpStream, error) {
			st, err := d.StartStream(ctx, sandboxID, spec)
			if err != nil {
				return nil, err
			}
			return st, nil
		},
		readyTimeout: codeinterp.LaunchTimeout,
	}
}

// Languages is python only: it is the one language with a stdio driver and
// a WASI build (D9). The adapters refuse the others with HTTP 400 before
// anything starts.
func (l *interpreterLauncher) Languages() []string { return []string{codeinterp.LangPython} }

// interpreterModuleLanguages are the code-run languages whose module runs
// the python driver, first configured wins (SB_WASM_CODERUN_MODULES, which
// defaults from SB_WASM_STANDARD_MODULES).
var interpreterModuleLanguages = []string{"python", "python3", "py"}

// interpreterModulePath resolves the python module the way code-run does,
// and shares its cache.
func (d *Driver) interpreterModulePath() (string, error) {
	for _, lang := range interpreterModuleLanguages {
		if ref := strings.TrimSpace(d.cfg.CodeRunModules[lang]); ref != "" {
			return d.codeRunModulePath(lang, ref)
		}
	}
	return "", &codeinterp.MissingInterpreterError{
		Language: codeinterp.LangPython,
		Programs: []string{"python.wasm"},
		Detail:   "no python module is configured for wasm sandboxes on this node (SB_WASM_STANDARD_MODULES or SB_WASM_CODERUN_MODULES)",
	}
}

// Launch starts a python.wasm instance with the stdio driver and waits for
// it to be ready. ctx bounds the start only.
func (l *interpreterLauncher) Launch(ctx context.Context, spec codeinterp.Spec) (codeinterp.Kernel, error) {
	if spec.Language != codeinterp.LangPython {
		return nil, fmt.Errorf("%w: %q (wasm sandboxes run python only)", codeinterp.ErrUnsupportedLanguage, spec.Language)
	}
	d, ok := drivers.Lookup(codeinterp.LangPython)
	if !ok {
		return nil, fmt.Errorf("%w: no python driver", codeinterp.ErrUnsupportedLanguage)
	}
	path, err := l.module()
	if err != nil {
		return nil, err
	}
	cwd := spec.Cwd
	if cwd == "" {
		cwd = interpreterDefaultCwd
	}
	env := make(map[string]string, len(spec.Env)+len(d.Env)+2)
	for _, m := range []map[string]string{spec.Env, d.Env} {
		for k, v := range m {
			env[k] = v
		}
	}
	env["AEROL_INTERP_MODE"] = "stdio"
	env["AEROL_INTERP_CWD"] = cwd
	st, err := l.start(ctx, StreamSpec{
		ModulePath: path,
		Args:       []string{"python", "-c", interpreterBootstrap, string(d.Script)},
		Env:        env,
		// A context lives until it is deleted, stopped idle or killed; a
		// run's own timeout is the Manager's.
		NoDeadline: true,
		Stdin:      true,
	})
	if err != nil {
		if errors.Is(err, ErrStreamLimit) || errors.Is(err, worker.ErrStreamLimit) {
			// An interpreter is a run like any other: past the sandbox's run
			// cap (sandboxd's, or the worker's own) the adapters answer 429 /
			// close 1008.
			return nil, fmt.Errorf("%w: %v", codeinterp.ErrLimit, err)
		}
		if l.forget != nil {
			l.forget(path)
		}
		return nil, err
	}
	k := newInterpKernel(st)
	if err := k.awaitReady(ctx, l.readyTimeout); err != nil {
		_ = k.Close()
		return nil, err
	}
	return k, nil
}

type interpFrame struct {
	kind    string
	payload []byte
}

// interpRun is how the stream reader hands raw stderr to the run in
// progress.
type interpRun struct {
	stderr chan []byte
	done   chan struct{}
}

// interpKernel is one python.wasm instance speaking the stdio protocol.
//
// One goroutine (pump) reads the stream: stdout bytes go through a frame
// reader and frames out on frames; raw stderr goes to the run in progress
// or is dropped (a tail is kept for launch errors). Both leave that one
// goroutine in the order the worker sent them, so a run sees its stderr
// where it was written relative to its frames.
type interpKernel struct {
	st interpStream

	frames  chan interpFrame
	exited  chan struct{}
	closing chan struct{}

	// interrupted makes a run that ends because Interrupt killed the
	// instance report "interrupted".
	interrupted atomic.Bool

	mu   sync.Mutex
	run  *interpRun
	tail []byte
	exit *StreamExit

	execMu    sync.Mutex
	closeOnce sync.Once
}

func newInterpKernel(st interpStream) *interpKernel {
	k := &interpKernel{
		st:      st,
		frames:  make(chan interpFrame),
		exited:  make(chan struct{}),
		closing: make(chan struct{}),
	}
	go k.pump()
	return k
}

func (k *interpKernel) pump() {
	defer close(k.exited)
	defer close(k.frames)
	// The Manager forgets a kernel that died without closing it, so the
	// kernel frees its run slot and connection itself. Dropping the
	// connection also ends an instance that is still running: one whose
	// driver broke the protocol (a bad frame) cannot be trusted with
	// another run.
	defer k.st.Close()
	fr := codeinterp.NewFrameReader(&interpStdout{k: k})
	for {
		kind, payload, err := fr.Read()
		if err != nil {
			return
		}
		select {
		case k.frames <- interpFrame{kind, payload}:
		case <-k.closing:
			return
		}
	}
}

// interpStdout is the instance's stdout as a reader, for the frame reader.
// Reading it is what receives every stream event, so stderr and the exit
// are handled on the way.
type interpStdout struct {
	k   *interpKernel
	buf []byte
}

func (s *interpStdout) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		ev, err := s.k.st.Recv()
		if err != nil {
			// A dropped connection ends the instance as surely as its exit.
			return 0, io.EOF
		}
		if ev.Exit != nil {
			s.k.mu.Lock()
			s.k.exit = ev.Exit
			s.k.mu.Unlock()
			return 0, io.EOF
		}
		if len(ev.Stderr) > 0 {
			s.k.stderr(ev.Stderr)
		}
		s.buf = ev.Stdout
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// stderr routes the instance's raw stderr. The driver frames everything
// Python code writes to sys.stderr, so this is only what bypasses it:
// CPython's own fatal messages, os.write(2, ...). It belongs to the run in
// progress; between runs it is dropped.
func (k *interpKernel) stderr(b []byte) {
	k.mu.Lock()
	run := k.run
	if run == nil {
		k.tail = append(k.tail, b...)
		if len(k.tail) > interpreterStderrTail {
			k.tail = append([]byte(nil), k.tail[len(k.tail)-interpreterStderrTail:]...)
		}
	}
	k.mu.Unlock()
	if run == nil {
		return
	}
	select {
	case run.stderr <- append([]byte(nil), b...):
	case <-run.done:
	case <-k.closing:
	}
}

func (k *interpKernel) awaitReady(ctx context.Context, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case fr, ok := <-k.frames:
		if !ok {
			return k.exitedEarly()
		}
		switch fr.kind {
		case "READY":
			return nil
		case "FATAL":
			return fmt.Errorf("codeinterp: python driver failed to start: %s", strings.TrimSpace(string(fr.payload)))
		}
		return fmt.Errorf("codeinterp: python driver sent %s before READY", fr.kind)
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("codeinterp: python driver did not start within %s", timeout)
	}
}

// exitedEarly explains an instance that ended before READY: python.wasm
// says why on stderr, or the worker in its exit (out of memory, a trap).
func (k *interpKernel) exitedEarly() error {
	<-k.exited
	k.mu.Lock()
	defer k.mu.Unlock()
	reason := strings.TrimSpace(string(k.tail))
	if reason == "" && k.exit != nil {
		reason = k.exit.Error
		if reason == "" {
			reason = fmt.Sprintf("exit code %d", k.exit.ExitCode)
		}
	}
	if reason == "" {
		reason = "the run ended"
	}
	return fmt.Errorf("codeinterp: python driver exited before it was ready: %s", reason)
}

// Interrupt kills the instance. WASI has no signals, so there is no way to
// stop running code and keep the interpreter (D12): the run ends at once
// with status "interrupted" and Died, the context reports active:false,
// and its next run starts a new, empty interpreter.
//
// It closes rather than waits for the worker's exit: the state is lost
// either way, and wazero can take seconds to unwind a busy python.wasm
// (about 2 s measured on a laptop), longer than an SDK waits for an
// interrupt to be confirmed.
func (k *interpKernel) Interrupt() error {
	select {
	case <-k.exited:
		return nil
	default:
	}
	k.interrupted.Store(true)
	return k.Close()
}

// Close ends the instance. Dropping the stream's connection is enough: the
// worker kills a run whose connection goes, and no kill round trip holds up
// a Manager closing many contexts. The stream's run slot is free at once;
// the worker finishes the kill in the background.
func (k *interpKernel) Close() error {
	k.closeOnce.Do(func() {
		close(k.closing)
		_ = k.st.Close()
	})
	return nil
}

// Done is closed when the instance has ended.
func (k *interpKernel) Done() <-chan struct{} { return k.exited }

// Execute runs one request. See codeinterp.Kernel.
func (k *interpKernel) Execute(req codeinterp.Request, sink codeinterp.Sink) (codeinterp.Outcome, error) {
	k.execMu.Lock()
	defer k.execMu.Unlock()
	if sink == nil {
		sink = func(codeinterp.Event) {}
	}
	select {
	case <-k.exited:
		return k.died(), nil
	case <-k.closing:
		return k.died(), nil
	default:
	}
	run := &interpRun{stderr: make(chan []byte), done: make(chan struct{})}
	k.mu.Lock()
	k.run = run
	k.mu.Unlock()
	defer func() {
		k.mu.Lock()
		k.run = nil
		k.mu.Unlock()
		close(run.done)
	}()

	if err := k.st.WriteStdin(interpRequest(req)); err != nil {
		_ = k.Close()
		return k.died(), nil
	}
	for {
		select {
		case fr, ok := <-k.frames:
			if !ok {
				return k.died(), nil
			}
			if fr.kind == "DONE" {
				return codeinterp.Outcome{Status: string(fr.payload)}, nil
			}
			// READY, FATAL and kinds a newer driver may add mean nothing
			// mid-run.
			if ev, ok := codeinterp.EventFromFrame(fr.kind, fr.payload); ok {
				sink(ev)
			}
		case b := <-run.stderr:
			sink(codeinterp.Event{Kind: codeinterp.EventStderr, Text: string(b)})
		case <-k.closing:
			// Closed under the run (a delete, a restart, the sandbox
			// stopping): the reader may be gone, so do not wait for it.
			return k.died(), nil
		}
	}
}

func (k *interpKernel) died() codeinterp.Outcome {
	out := codeinterp.Outcome{Died: true}
	if k.interrupted.Load() {
		out.Status = "interrupted"
	}
	return out
}

// interpRequest is a run's ENV frames and its EXEC frame, written to stdin
// in one piece.
func interpRequest(req codeinterp.Request) []byte {
	var buf bytes.Buffer
	names := make([]string, 0, len(req.Env))
	for name := range req.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_ = codeinterp.WriteFrame(&buf, "ENV", []byte(name+"="+req.Env[name]))
	}
	_ = codeinterp.WriteFrame(&buf, "EXEC", []byte(req.Code))
	return buf.Bytes()
}
