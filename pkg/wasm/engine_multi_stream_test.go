package wasm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/wasmtestguest"
)

// syncBuffer is a bytes.Buffer safe for the guest goroutine to write while a
// test polls it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var (
	sharedStdioOnce sync.Once
	sharedStdioEng  *MultiInstanceEngine
	sharedStdioErr  error
)

// newStdioEngine returns one engine with the stdio guest compiled, shared by
// the Start tests: compiling the guest costs seconds (far more under -race),
// and runs on one engine never see each other, which is what Start promises.
// Each test checks it leaves no run behind.
func newStdioEngine(t *testing.T) *MultiInstanceEngine {
	t.Helper()
	path := wasmtestguest.Path(t, wasmtestguest.Stdio)
	sharedStdioOnce.Do(func() {
		ctx := context.Background()
		sharedStdioEng, sharedStdioErr = NewMultiInstanceEngine(ctx, 64)
		if sharedStdioErr == nil {
			sharedStdioErr = sharedStdioEng.LoadModule(ctx, path)
		}
	})
	if sharedStdioErr != nil {
		t.Fatal(sharedStdioErr)
	}
	eng := sharedStdioEng
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
		for eng.RunningCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := eng.RunningCount(); n != 0 {
			t.Errorf("%d runs left behind", n)
		}
	})
	return eng
}

func stdioCaps(args ...string) Capabilities {
	return Capabilities{Args: append([]string{"aerolstdio"}, args...), WASIListenPort: WASIListenPortDisabled}
}

func waitRun(t *testing.T, r *Running) RunResult {
	t.Helper()
	select {
	case <-r.Done():
	case <-time.After(20 * time.Second):
		t.Fatal("run did not end")
	}
	res, err := r.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	return res
}

func TestStartEchoesStdinToStdout(t *testing.T) {
	eng := newStdioEngine(t)
	pr, pw := io.Pipe()
	var out, errOut syncBuffer
	r, err := eng.Start(context.Background(), "sb/x/1", stdioCaps("echo"), "", Stdio{In: pr, Out: &out, Err: &errOut})
	if err != nil {
		t.Fatal(err)
	}
	if r.Name() != "sb/x/1" {
		t.Fatalf("name = %q", r.Name())
	}
	if _, err := pw.Write([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	res := waitRun(t, r)
	if res.ExitCode != 0 || out.String() != "hello world" {
		t.Fatalf("exit=%d out=%q err=%q", res.ExitCode, out.String(), errOut.String())
	}
	if r.Killed() || r.TimedOut() {
		t.Fatal("a clean exit reported killed or timed out")
	}
	if eng.RunningCount() != 0 {
		t.Fatalf("running = %d after exit", eng.RunningCount())
	}
}

func TestStartReportsStderrAndExitCodes(t *testing.T) {
	eng := newStdioEngine(t)
	var errOut syncBuffer
	r, err := eng.Start(context.Background(), "a", stdioCaps("stderr", "oops"), "_start", Stdio{Err: &errOut})
	if err != nil {
		t.Fatal(err)
	}
	if res := waitRun(t, r); res.ExitCode != 0 || errOut.String() != "oops" {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, errOut.String())
	}
	r, err = eng.Start(context.Background(), "a", stdioCaps("exit", "7"), "", Stdio{})
	if err != nil {
		t.Fatal(err)
	}
	if res := waitRun(t, r); res.ExitCode != 7 {
		t.Fatalf("exit=%d, want 7", res.ExitCode)
	}
}

func TestStartKillsAGuestBlockedOnStdin(t *testing.T) {
	eng := newStdioEngine(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	caps := stdioCaps("block")
	caps.WallTimeoutNs = NoWallTimeout
	r, err := eng.Start(context.Background(), "blocked", caps, "", Stdio{In: pr})
	if err != nil {
		t.Fatal(err)
	}
	// Let the guest reach its blocking read.
	time.Sleep(100 * time.Millisecond)
	r.Kill()
	waitRun(t, r)
	if !r.Killed() || r.TimedOut() {
		t.Fatalf("killed=%v timedOut=%v", r.Killed(), r.TimedOut())
	}
	// The writer side learns the run is gone.
	if _, err := pw.Write([]byte("late")); !errors.Is(err, ErrRunKilled) {
		t.Fatalf("write after kill = %v, want ErrRunKilled", err)
	}
	r.Kill() // idempotent after the end
}

func TestStartKillsASpinningGuest(t *testing.T) {
	eng := newStdioEngine(t)
	caps := stdioCaps("spin")
	caps.WallTimeoutNs = NoWallTimeout
	r, err := eng.Start(context.Background(), "spin", caps, "", Stdio{})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	r.Kill()
	waitRun(t, r)
	if !r.Killed() {
		t.Fatal("spinning guest not reported killed")
	}
}

func TestStartWallTimeoutEndsTheRun(t *testing.T) {
	eng := newStdioEngine(t)
	caps := stdioCaps("spin")
	caps.WallTimeoutNs = int64(200 * time.Millisecond)
	r, err := eng.Start(context.Background(), "slow", caps, "", Stdio{})
	if err != nil {
		t.Fatal(err)
	}
	waitRun(t, r)
	if !r.TimedOut() || r.Killed() {
		t.Fatalf("timedOut=%v killed=%v", r.TimedOut(), r.Killed())
	}
}

func TestStartContextHasNoDeadlineForNoWallTimeout(t *testing.T) {
	ctx, cancel := startContext(context.Background(), Capabilities{WallTimeoutNs: NoWallTimeout})
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("NoWallTimeout run has a deadline")
	}
	ctx2, cancel2 := startContext(context.Background(), Capabilities{})
	defer cancel2()
	if _, ok := ctx2.Deadline(); !ok {
		t.Fatal("zero wall timeout lost its default deadline")
	}
}

func TestStartTwoRunsAtOnceStayApart(t *testing.T) {
	eng := newStdioEngine(t)
	type run struct {
		r   *Running
		pw  *io.PipeWriter
		out *syncBuffer
	}
	var runs []run
	for _, name := range []string{"sb/x/a", "sb/x/b"} {
		pr, pw := io.Pipe()
		out := &syncBuffer{}
		r, err := eng.Start(context.Background(), name, stdioCaps("echo"), "", Stdio{In: pr, Out: out})
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, run{r: r, pw: pw, out: out})
	}
	if eng.RunningCount() != 2 {
		t.Fatalf("running = %d", eng.RunningCount())
	}
	_, _ = runs[0].pw.Write([]byte("first"))
	_, _ = runs[1].pw.Write([]byte("second"))
	_ = runs[1].pw.Close()
	if res := waitRun(t, runs[1].r); res.ExitCode != 0 || runs[1].out.String() != "second" {
		t.Fatalf("b: exit=%d out=%q", res.ExitCode, runs[1].out.String())
	}
	// a is still running and has seen only its own input.
	select {
	case <-runs[0].r.Done():
		t.Fatal("a ended with b")
	default:
	}
	_ = runs[0].pw.Close()
	if res := waitRun(t, runs[0].r); res.ExitCode != 0 || runs[0].out.String() != "first" {
		t.Fatalf("a: exit=%d out=%q", res.ExitCode, runs[0].out.String())
	}
}

func TestStartWritesThroughTheWorkPreopen(t *testing.T) {
	eng := newStdioEngine(t)
	work := t.TempDir()
	caps := stdioCaps("write-work", "f.txt", "data")
	caps.Preopens = []Preopen{{GuestPath: "/work", HostPath: work}}
	r, err := eng.Start(context.Background(), "w", caps, "", Stdio{})
	if err != nil {
		t.Fatal(err)
	}
	if res := waitRun(t, r); res.ExitCode != 0 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
	got, err := os.ReadFile(filepath.Join(work, "f.txt"))
	if err != nil || string(got) != "data" {
		t.Fatalf("file = %q %v", got, err)
	}
}

// blockingWriter holds the first write until release is closed, the way a
// slow consumer would.
type blockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func TestStartKillFailsLaterWrites(t *testing.T) {
	eng := newStdioEngine(t)
	w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	caps := stdioCaps("flood", "0")
	caps.WallTimeoutNs = NoWallTimeout
	r, err := eng.Start(context.Background(), "flood", caps, "", Stdio{Out: w})
	if err != nil {
		t.Fatal(err)
	}
	<-w.entered
	r.Kill()
	close(w.release)
	waitRun(t, r)
	if !r.Killed() {
		t.Fatal("not killed")
	}
}

func TestStartKillClosesABlockedSocket(t *testing.T) {
	eng := newStdioEngine(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	eng.SetNetworkHook("dialer", &NetworkHook{SandboxID: "sb", Dial: &net.Dialer{}})
	var out syncBuffer
	caps := stdioCaps("dial-read", ln.Addr().String())
	caps.WallTimeoutNs = NoWallTimeout
	r, err := eng.Start(context.Background(), "dialer", caps, "", Stdio{Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	var server net.Conn
	select {
	case server = <-accepted:
		defer server.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("guest never dialed")
	}
	// The guest is now parked in tcp_read; only closing its conn frees it.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "dialed") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	r.Kill()
	waitRun(t, r)
	if !r.Killed() {
		t.Fatal("not killed")
	}
	// The run's hook went with it.
	if eng.netHost.resolveHook("dialer") != nil {
		t.Fatal("run left its network hook behind")
	}
}

func TestStartRejectsBadRequests(t *testing.T) {
	ctx := context.Background()
	empty, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close(ctx)
	if _, err := empty.Start(ctx, "x", Capabilities{}, "", Stdio{}); err == nil {
		t.Fatal("Start without a module succeeded")
	}

	eng := newStdioEngine(t)
	if _, err := eng.Start(ctx, "", stdioCaps("exit", "0"), "", Stdio{}); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := eng.Start(ctx, "noexport", stdioCaps("exit", "0"), "no_such_export", Stdio{}); err == nil {
		t.Fatal("missing export accepted")
	}
	if eng.RunningCount() != 0 {
		t.Fatal("failed start left a reservation")
	}
	// A name held by a run or by an Instantiate instance is refused.
	pr, pw := io.Pipe()
	defer pw.Close()
	r, err := eng.Start(ctx, "dup", stdioCaps("block"), "", Stdio{In: pr})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Start(ctx, "dup", stdioCaps("exit", "0"), "", Stdio{}); err == nil {
		t.Fatal("duplicate run name accepted")
	}
	if err := eng.Instantiate(ctx, "inst", stdioCaps("exit", "0")); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Start(ctx, "inst", stdioCaps("exit", "0"), "", Stdio{}); err == nil {
		t.Fatal("name of a live instance accepted")
	}
	r.Kill()
	waitRun(t, r)
	if err := eng.StopInstance(ctx, "inst"); err != nil {
		t.Fatal(err)
	}
	// A host module's name is refused up front: letting wazero refuse it
	// would drop the host module from the runtime first.
	for _, name := range []string{"wasi_snapshot_preview1", "aerol/vm/net"} {
		if _, err := eng.Start(ctx, name, stdioCaps("exit", "0"), "", Stdio{}); err == nil {
			t.Fatalf("host module name %q accepted", name)
		}
	}
	// An instantiate on a dead context fails or ends at once; either way
	// the name is released.
	dead, cancel := context.WithCancel(ctx)
	cancel()
	if r, err := eng.Start(dead, "dead", stdioCaps("exit", "0"), "", Stdio{}); err == nil {
		waitRunAny(t, r)
	}
	if eng.RunningCount() != 0 {
		t.Fatal("failed start left a reservation")
	}
	// The runtime still works after all of that.
	r, err = eng.Start(ctx, "after", stdioCaps("exit", "4"), "", Stdio{})
	if err != nil {
		t.Fatal(err)
	}
	if res := waitRun(t, r); res.ExitCode != 4 {
		t.Fatalf("exit = %d", res.ExitCode)
	}
}

// waitRunAny waits for the end of a run whose outcome does not matter.
func waitRunAny(t *testing.T, r *Running) {
	t.Helper()
	select {
	case <-r.Done():
	case <-time.After(20 * time.Second):
		t.Fatal("run did not end")
	}
}

func TestStartCallerContextCancelStopsTheRun(t *testing.T) {
	eng := newStdioEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	defer pw.Close()
	caps := stdioCaps("block")
	caps.WallTimeoutNs = NoWallTimeout
	r, err := eng.Start(ctx, "ctx", caps, "", Stdio{In: pr})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	waitRun(t, r)
	if r.Killed() || r.TimedOut() {
		t.Fatalf("caller cancel reported killed=%v timedOut=%v", r.Killed(), r.TimedOut())
	}
}

func TestCloseKillsLiveRuns(t *testing.T) {
	path := wasmtestguest.Path(t, wasmtestguest.Stdio)
	ctx := context.Background()
	eng, err := NewMultiInstanceEngine(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.LoadModule(ctx, path); err != nil {
		t.Fatal(err)
	}
	caps := stdioCaps("spin")
	caps.WallTimeoutNs = NoWallTimeout
	r, err := eng.Start(ctx, "spin", caps, "", Stdio{})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Close left the run going")
	}
}

func TestKillRunningGivesUpAfterTheWait(t *testing.T) {
	old := closeRunWait
	closeRunWait = 20 * time.Millisecond
	t.Cleanup(func() { closeRunWait = old })
	stuck := &Running{cancel: func() {}, done: make(chan struct{})}
	start := time.Now()
	killRunning(map[string]*Running{"stuck": stuck})
	if time.Since(start) > 2*time.Second {
		t.Fatal("killRunning waited past closeRunWait")
	}
	if !stuck.killReq.Load() {
		t.Fatal("killRunning did not kill")
	}
}

func TestStartGateWriterAndCloseStdin(t *testing.T) {
	g := newGateWriter(nil)
	if n, err := g.Write([]byte("x")); n != 1 || err != nil {
		t.Fatalf("discard write = %d %v", n, err)
	}
	g.closed.Store(true)
	if _, err := g.Write([]byte("x")); !errors.Is(err, ErrRunKilled) {
		t.Fatalf("closed write = %v", err)
	}
	// A plain closer is closed; a reader with no Close is left alone.
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	closeStdin(f)
	if _, err := f.Read(make([]byte, 1)); err == nil || err == io.EOF {
		t.Fatalf("file still open: %v", err)
	}
	closeStdin(strings.NewReader("x"))
	closeStdin(nil)
}
