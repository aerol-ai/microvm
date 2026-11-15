package wasm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/drivers"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// fakeInterpStream is a python.wasm instance the test plays by hand: it
// pushes stream events and reads what the kernel wrote to stdin.
type fakeInterpStream struct {
	events   chan StreamEvent
	closed   chan struct{}
	stdin    chan []byte
	writeErr error
	// exitOnKill makes Kill end the run the way the worker does.
	exitOnKill bool

	mu        sync.Mutex
	kills     int
	closes    int
	closeOnce sync.Once
}

func newFakeInterpStream() *fakeInterpStream {
	return &fakeInterpStream{
		events:     make(chan StreamEvent, 64),
		closed:     make(chan struct{}),
		stdin:      make(chan []byte, 16),
		exitOnKill: true,
	}
}

func (f *fakeInterpStream) Recv() (StreamEvent, error) {
	select {
	case ev := <-f.events:
		return ev, nil
	case <-f.closed:
		return StreamEvent{}, errors.New("use of closed network connection")
	}
}

func (f *fakeInterpStream) WriteStdin(p []byte) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.stdin <- append([]byte(nil), p...)
	return nil
}

func (f *fakeInterpStream) Kill() error {
	f.mu.Lock()
	f.kills++
	f.mu.Unlock()
	if f.exitOnKill {
		f.events <- StreamEvent{Exit: &StreamExit{ExitCode: -1, Killed: true}}
	}
	return nil
}

func (f *fakeInterpStream) Close() error {
	f.mu.Lock()
	f.closes++
	f.mu.Unlock()
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeInterpStream) counts() (kills, closes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.kills, f.closes
}

// out pushes frames as stdout bytes, split into the given chunks so frames
// straddle stream events.
func (f *fakeInterpStream) out(chunk int, frames ...string) {
	var b bytes.Buffer
	for i := 0; i+1 < len(frames); i += 2 {
		_ = codeinterp.WriteFrame(&b, frames[i], []byte(frames[i+1]))
	}
	data := b.Bytes()
	for len(data) > 0 {
		n := min(chunk, len(data))
		f.events <- StreamEvent{Stdout: append([]byte(nil), data[:n]...)}
		data = data[n:]
	}
}

func (f *fakeInterpStream) errOut(s string) { f.events <- StreamEvent{Stderr: []byte(s)} }

func (f *fakeInterpStream) exit(e StreamExit) { f.events <- StreamEvent{Exit: &e} }

// request reads one write to stdin.
func (f *fakeInterpStream) request(t *testing.T) []byte {
	t.Helper()
	select {
	case b := <-f.stdin:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("kernel wrote no request")
		return nil
	}
}

// fakeLauncherFor is a launcher whose stream is st, with the spec it got.
func fakeLauncherFor(st *fakeInterpStream, specs *[]StreamSpec) *interpreterLauncher {
	return &interpreterLauncher{
		sandboxID: "sb-interp",
		module:    func() (string, error) { return "/modules/python.wasm", nil },
		start: func(_ context.Context, spec StreamSpec) (interpStream, error) {
			if specs != nil {
				*specs = append(*specs, spec)
			}
			return st, nil
		},
		readyTimeout: 5 * time.Second,
	}
}

func launchReady(t *testing.T, st *fakeInterpStream) *interpKernel {
	t.Helper()
	st.out(1<<10, "READY", "1")
	k, err := fakeLauncherFor(st, nil).Launch(context.Background(), codeinterp.Spec{Language: codeinterp.LangPython})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k.(*interpKernel)
}

type sinkLog struct {
	mu     sync.Mutex
	events []codeinterp.Event
}

func (s *sinkLog) sink(ev codeinterp.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *sinkLog) kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, ev := range s.events {
		switch ev.Kind {
		case codeinterp.EventCount:
			out = append(out, "count")
		case codeinterp.EventStdout:
			out = append(out, "out:"+ev.Text)
		case codeinterp.EventStderr:
			out = append(out, "err:"+ev.Text)
		case codeinterp.EventResult:
			out = append(out, "result:"+ev.Bundle["text/plain"].(string))
		case codeinterp.EventError:
			out = append(out, "error:"+ev.ErrName)
		}
	}
	return out
}

type execResult struct {
	out codeinterp.Outcome
	err error
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func execAsync(k *interpKernel, req codeinterp.Request, log *sinkLog) chan execResult {
	done := make(chan execResult, 1)
	go func() {
		out, err := k.Execute(req, log.sink)
		done <- execResult{out, err}
	}()
	return done
}

func waitExec(t *testing.T, done chan execResult) codeinterp.Outcome {
	t.Helper()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.out
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return")
		return codeinterp.Outcome{}
	}
}

func TestInterpreterLauncherSpec(t *testing.T) {
	cases := []struct {
		name    string
		spec    codeinterp.Spec
		wantCwd string
	}{
		{name: "default cwd", spec: codeinterp.Spec{Language: codeinterp.LangPython}, wantCwd: "/work"},
		{name: "context cwd and env", spec: codeinterp.Spec{Language: codeinterp.LangPython, Cwd: "/work/app", Env: map[string]string{"A": "1"}}, wantCwd: "/work/app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeInterpStream()
			st.out(3, "READY", "1")
			var specs []StreamSpec
			k, err := fakeLauncherFor(st, &specs).Launch(context.Background(), tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()
			d, _ := drivers.Lookup(codeinterp.LangPython)
			got := specs[0]
			if got.ModulePath != "/modules/python.wasm" || !got.NoDeadline || !got.Stdin || got.Timeout != 0 || got.MaxOutputBytes != 0 {
				t.Fatalf("spec = %+v", got)
			}
			if want := []string{"python", "-c", interpreterBootstrap, string(d.Script)}; !reflect.DeepEqual(got.Args, want) {
				t.Fatalf("args = %q", got.Args[:3])
			}
			if got.Env["AEROL_INTERP_MODE"] != "stdio" || got.Env["AEROL_INTERP_CWD"] != tc.wantCwd || got.Env["A"] != tc.spec.Env["A"] {
				t.Fatalf("env = %v", got.Env)
			}
			if !reflect.DeepEqual(fakeLauncherFor(st, nil).Languages(), []string{"python"}) {
				t.Fatal("languages")
			}
		})
	}
}

func TestInterpreterLauncherErrors(t *testing.T) {
	missing := &codeinterp.MissingInterpreterError{Language: "python"}
	cases := []struct {
		name     string
		language string
		module   error
		start    error
		frames   []string
		exit     *StreamExit
		stderr   string
		timeout  time.Duration
		want     string
		is       error
		forgets  bool
	}{
		{name: "not python", language: "javascript", want: "python only", is: codeinterp.ErrUnsupportedLanguage},
		{name: "no module", module: missing, is: missing},
		{name: "run cap", start: ErrStreamLimit, is: codeinterp.ErrLimit},
		{name: "worker's run cap", start: worker.ErrStreamLimit, is: codeinterp.ErrLimit},
		{name: "start fails", start: errors.New("worker gone"), want: "worker gone", forgets: true},
		{name: "fatal", frames: []string{"FATAL", "FileNotFoundError: /work/x"}, want: "failed to start: FileNotFoundError: /work/x"},
		{name: "wrong first frame", frames: []string{"COUNT", "1"}, want: "sent COUNT before READY"},
		{name: "exits with stderr", stderr: "Fatal Python error: init", exit: &StreamExit{ExitCode: 1}, want: "exited before it was ready: Fatal Python error: init"},
		{name: "exits with a trap", exit: &StreamExit{ExitCode: -1, Error: "out of memory"}, want: "ready: out of memory"},
		{name: "exits with a code", exit: &StreamExit{ExitCode: 3}, want: "ready: exit code 3"},
		{name: "never ready", timeout: 50 * time.Millisecond, want: "did not start within 50ms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeInterpStream()
			forgot := ""
			l := fakeLauncherFor(st, nil)
			l.forget = func(path string) { forgot = path }
			if tc.module != nil {
				l.module = func() (string, error) { return "", tc.module }
			}
			if tc.start != nil {
				l.start = func(context.Context, StreamSpec) (interpStream, error) { return nil, tc.start }
			}
			if tc.timeout > 0 {
				l.readyTimeout = tc.timeout
			}
			if tc.stderr != "" {
				st.errOut(tc.stderr)
			}
			if len(tc.frames) > 0 {
				st.out(4, tc.frames...)
			}
			if tc.exit != nil {
				st.exit(*tc.exit)
			}
			lang := tc.language
			if lang == "" {
				lang = codeinterp.LangPython
			}
			k, err := l.Launch(context.Background(), codeinterp.Spec{Language: lang})
			if err == nil {
				_ = k.Close()
				t.Fatal("launch succeeded")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want %v", err, tc.is)
			}
			if tc.forgets != (forgot == "/modules/python.wasm") {
				t.Fatalf("forgot = %q", forgot)
			}
			if tc.start == nil && tc.module == nil && tc.language == "" {
				// A failed launch must not leave the instance running.
				select {
				case <-st.closed:
				case <-time.After(5 * time.Second):
					t.Fatal("stream not closed after a failed launch")
				}
			}
		})
	}
}

func TestInterpreterLaunchCancelled(t *testing.T) {
	st := newFakeInterpStream()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fakeLauncherFor(st, nil).Launch(ctx, codeinterp.Spec{Language: codeinterp.LangPython}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestInterpKernelRun(t *testing.T) {
	st := newFakeInterpStream()
	k := launchReady(t, st)
	// Raw stderr between runs is not the next run's: it only feeds the
	// tail kept for launch errors.
	st.errOut("idle noise")
	waitFor(t, "idle stderr read", func() bool {
		k.mu.Lock()
		defer k.mu.Unlock()
		return strings.Contains(string(k.tail), "idle noise")
	})

	log := &sinkLog{}
	done := execAsync(k, codeinterp.Request{Code: "x", Env: map[string]string{"B": "2", "A": "1"}}, log)
	var want bytes.Buffer
	_ = codeinterp.WriteFrame(&want, "ENV", []byte("A=1"))
	_ = codeinterp.WriteFrame(&want, "ENV", []byte("B=2"))
	_ = codeinterp.WriteFrame(&want, "EXEC", []byte("x"))
	if got := st.request(t); !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("request = %q, want %q", got, want.Bytes())
	}
	st.out(5, "COUNT", "1", "OUT", "hi\n")
	st.errOut("raw\n")
	st.out(7, "SYNC", "1", "TEXT", "5", "ERROR", "NameError\x1fx\x1ftb", "FUTURE", "?", "DONE", "error")
	out := waitExec(t, done)
	if out.Status != "error" || out.Died {
		t.Fatalf("outcome = %+v", out)
	}
	want2 := []string{"count", "out:hi\n", "err:raw\n", "result:5", "error:NameError"}
	if got := log.kinds(); !reflect.DeepEqual(got, want2) {
		t.Fatalf("events = %q, want %q", got, want2)
	}
	select {
	case <-k.Done():
		t.Fatal("kernel done after a normal run")
	default:
	}
	if kills, _ := st.counts(); kills != 0 {
		t.Fatalf("%d kills", kills)
	}
}

func TestInterpKernelDeath(t *testing.T) {
	t.Run("mid run", func(t *testing.T) {
		st := newFakeInterpStream()
		k := launchReady(t, st)
		log := &sinkLog{}
		done := execAsync(k, codeinterp.Request{Code: "import os; os._exit(3)"}, log)
		st.request(t)
		st.out(64, "COUNT", "1")
		st.exit(StreamExit{ExitCode: 3})
		if out := waitExec(t, done); !out.Died || out.Status != "" {
			t.Fatalf("outcome = %+v", out)
		}
		<-k.Done()
		if _, closes := st.counts(); closes == 0 {
			t.Fatal("a dead kernel kept its stream")
		}
		// A dead kernel answers at once.
		if out, _ := k.Execute(codeinterp.Request{Code: "1"}, nil); !out.Died {
			t.Fatalf("after death = %+v", out)
		}
	})
	t.Run("interrupt kills", func(t *testing.T) {
		st := newFakeInterpStream()
		k := launchReady(t, st)
		log := &sinkLog{}
		done := execAsync(k, codeinterp.Request{Code: "while True: pass"}, log)
		st.request(t)
		st.out(64, "COUNT", "1")
		if err := k.Interrupt(); err != nil {
			t.Fatal(err)
		}
		if out := waitExec(t, done); !out.Died || !out.Interrupted() {
			t.Fatalf("outcome = %+v", out)
		}
		<-k.Done()
		if err := k.Interrupt(); err != nil {
			t.Fatal(err)
		}
		if kills, _ := st.counts(); kills != 1 {
			t.Fatalf("%d kills, want 1 (none after the end)", kills)
		}
	})
	t.Run("closed mid run", func(t *testing.T) {
		st := newFakeInterpStream()
		k := launchReady(t, st)
		done := execAsync(k, codeinterp.Request{Code: "x"}, &sinkLog{})
		st.request(t)
		_ = k.Close()
		_ = k.Close()
		if out := waitExec(t, done); !out.Died {
			t.Fatalf("outcome = %+v", out)
		}
		<-k.Done()
		if out, _ := k.Execute(codeinterp.Request{Code: "1"}, nil); !out.Died {
			t.Fatalf("after close = %+v", out)
		}
	})
	t.Run("stdin write fails", func(t *testing.T) {
		st := newFakeInterpStream()
		k := launchReady(t, st)
		st.writeErr = io.ErrClosedPipe
		if out, _ := k.Execute(codeinterp.Request{Code: "x"}, nil); !out.Died {
			t.Fatalf("outcome = %+v", out)
		}
	})
	t.Run("bad frame", func(t *testing.T) {
		st := newFakeInterpStream()
		k := launchReady(t, st)
		done := execAsync(k, codeinterp.Request{Code: "x"}, &sinkLog{})
		st.request(t)
		st.events <- StreamEvent{Stdout: []byte("not a frame\n")}
		if out := waitExec(t, done); !out.Died {
			t.Fatalf("outcome = %+v", out)
		}
		if kills, _ := st.counts(); kills != 1 {
			t.Fatalf("a protocol break left the instance running (%d kills)", kills)
		}
	})
	t.Run("stderr while the run is closing", func(t *testing.T) {
		st := newFakeInterpStream()
		st.exitOnKill = false
		k := launchReady(t, st)
		done := execAsync(k, codeinterp.Request{Code: "x"}, &sinkLog{})
		st.request(t)
		// DONE, then stderr nobody reads any more: it must not hold the
		// stream reader.
		st.out(64, "DONE", "ok")
		if out := waitExec(t, done); out.Status != "ok" {
			t.Fatalf("outcome = %+v", out)
		}
		st.errOut("late")
		st.exit(StreamExit{})
		select {
		case <-k.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("stream reader stuck on stderr after the run")
		}
	})
}

func TestInterpreterModulePath(t *testing.T) {
	d := New(Config{}, nil)
	if _, err := d.interpreterModulePath(); err == nil || !strings.Contains(err.Error(), "SB_WASM_STANDARD_MODULES") {
		t.Fatalf("no module configured: %v", err)
	}
	var missing *codeinterp.MissingInterpreterError
	if _, err := d.interpreterModulePath(); !errors.As(err, &missing) {
		t.Fatalf("err = %T", err)
	}
	// The first configured python-family language wins, and resolves the
	// way code-run does (shared cache).
	d = New(Config{CodeRunModules: map[string]string{"py": "mypython", "ruby": "ruby"}}, nil)
	d.SetModuleResolver(fakeResolver{path: "/modules/py.wasm"})
	if path, err := d.interpreterModulePath(); err != nil || path != "/modules/py.wasm" {
		t.Fatalf("path = %q %v", path, err)
	}
	if d.codeRunPaths["py"] != "/modules/py.wasm" {
		t.Fatalf("cache = %v", d.codeRunPaths)
	}
	l := d.interpreterLauncher("sb-x")
	l.forget("/modules/py.wasm") // the file does not exist: the cache drops it
	if _, ok := d.codeRunPaths["py"]; ok {
		t.Fatal("forget kept a missing module")
	}
	// The driver's start refuses a sandbox it does not have.
	if _, err := l.start(context.Background(), StreamSpec{}); err == nil {
		t.Fatal("start for an unknown sandbox succeeded")
	}
}
