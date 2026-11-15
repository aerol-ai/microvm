package wasm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/wasmtestguest"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// streamDriver is a driver whose one sandbox runs the stdio guest on an
// in-process worker.
func streamDriver(t *testing.T, cfg Config, req models.CreateSandboxRequest) (*Driver, string) {
	t.Helper()
	return streamDriverWith(t, cfg, req, wasmtestguest.Path(t, wasmtestguest.Stdio))
}

// streamDriverWith is streamDriver with the sandbox's own module at guest.
func streamDriverWith(t *testing.T, cfg Config, req models.CreateSandboxRequest, guest string) (*Driver, string) {
	t.Helper()
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", streamCompileCache(t))
	runDir := filepath.Join(os.TempDir(), fmt.Sprintf("aw-stream-%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	cfg.RunDir = runDir
	cfg.ModulesDir = t.TempDir()
	if cfg.DefaultMemoryMB == 0 {
		cfg.DefaultMemoryMB = 64
	}
	if cfg.DefaultWallTimeout == 0 {
		cfg.DefaultWallTimeout = time.Minute
	}
	d := New(cfg, nil)
	d.SetModuleResolver(fakeResolver{path: guest, digest: "stdio"})
	d.SetWorkerSupervisor(sup)
	if req.Image == "" {
		req.Image = "stdio.wasm"
	}
	sandboxID := "sb-stream"
	if _, err := d.Create(context.Background(), req, sandboxID, "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return d, sandboxID
}

var (
	streamCacheOnce sync.Once
	streamCacheDir  string
)

// streamCompileCache shares one wazero compile cache across this file's
// tests: the stdio guest is compiled on the sandbox engine and on each aux
// engine, seconds apiece under -race.
func streamCompileCache(t *testing.T) string {
	streamCacheOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aw-stream-cache-")
		if err == nil {
			streamCacheDir = dir
		}
	})
	return streamCacheDir
}

type streamResult struct {
	stdout, stderr string
	exit           *StreamExit
}

func drain(t *testing.T, st *Stream) (streamResult, error) {
	t.Helper()
	var out, errOut strings.Builder
	deadline := time.AfterFunc(30*time.Second, func() { _ = st.Close() })
	defer deadline.Stop()
	for {
		ev, err := st.Recv()
		if err != nil {
			return streamResult{stdout: out.String(), stderr: errOut.String()}, err
		}
		if ev.Exit != nil {
			return streamResult{stdout: out.String(), stderr: errOut.String(), exit: ev.Exit}, nil
		}
		out.Write(ev.Stdout)
		errOut.Write(ev.Stderr)
	}
}

func mustDrain(t *testing.T, st *Stream) streamResult {
	t.Helper()
	res, err := drain(t, st)
	if err != nil {
		t.Fatalf("stream ended without an exit: %v (stdout %q stderr %q)", err, res.stdout, res.stderr)
	}
	return res
}

func TestStartStreamRunsInTheSandbox(t *testing.T) {
	d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{
		ContainerCommand: []string{"aerolstdio", "env", "BASE"},
		Env:              map[string]string{"BASE": "from-create"},
	})
	ctx := context.Background()

	// Empty args run the sandbox's own command line with its env.
	st, err := d.StartStream(ctx, id, StreamSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if st.ID == "" {
		t.Fatal("stream has no id")
	}
	if res := mustDrain(t, st); res.stdout != "from-create" || res.exit.ExitCode != 0 {
		t.Fatalf("own args: %+v %+v", res, res.exit)
	}
	_ = st.Close()

	// The request env is added on top.
	st, err = d.StartStream(ctx, id, StreamSpec{Args: []string{"aerolstdio", "env", "EXTRA"}, Env: map[string]string{"EXTRA": "x1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res := mustDrain(t, st); res.stdout != "x1" {
		t.Fatalf("env: %q", res.stdout)
	}
	_ = st.Close()

	// stdin in, stdout out.
	st, err = d.StartStream(ctx, id, StreamSpec{Args: []string{"aerolstdio", "echo"}, Stdin: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteStdin([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseStdin(); err != nil {
		t.Fatal(err)
	}
	if res := mustDrain(t, st); res.stdout != "ping" {
		t.Fatalf("echo: %q", res.stdout)
	}
	_ = st.Close()

	// /work is the sandbox's work folder.
	st, err = d.StartStream(ctx, id, StreamSpec{Args: []string{"aerolstdio", "write-work", "made.txt", "yes"}})
	if err != nil {
		t.Fatal(err)
	}
	if res := mustDrain(t, st); res.exit.ExitCode != 0 {
		t.Fatalf("write-work: %+v %q", res.exit, res.stderr)
	}
	_ = st.Close()
	inst, _ := d.instance(id)
	if b, err := os.ReadFile(filepath.Join(inst.workDir, "made.txt")); err != nil || string(b) != "yes" {
		t.Fatalf("work file = %q %v", b, err)
	}

	// stderr, exit codes, timeouts.
	st, err = d.StartStream(ctx, id, StreamSpec{Args: []string{"aerolstdio", "stderr", "bad"}})
	if err != nil {
		t.Fatal(err)
	}
	if res := mustDrain(t, st); res.stderr != "bad" {
		t.Fatalf("stderr: %q", res.stderr)
	}
	_ = st.Close()
	st, err = d.StartStream(ctx, id, StreamSpec{Args: []string{"aerolstdio", "spin"}, Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res := mustDrain(t, st); !res.exit.TimedOut || res.exit.ExitCode != -1 {
		t.Fatalf("timeout: %+v", res.exit)
	}
	_ = st.Close()
	if n := inst.streams.count(); n != 0 {
		t.Fatalf("%d slots held after every run ended", n)
	}
}

func TestStartStreamLimitAndKill(t *testing.T) {
	d, id := streamDriver(t, Config{MaxStreamsPerSandbox: 1}, models.CreateSandboxRequest{})
	ctx := context.Background()
	st, err := d.StartStream(ctx, id, StreamSpec{Args: []string{"aerolstdio", "block"}, Stdin: true, NoDeadline: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartStream(ctx, id, StreamSpec{Args: []string{"aerolstdio", "exit", "0"}}); !errors.Is(err, ErrStreamLimit) {
		t.Fatalf("second stream = %v, want ErrStreamLimit", err)
	}
	if err := st.Kill(); err != nil {
		t.Fatal(err)
	}
	if res := mustDrain(t, st); !res.exit.Killed {
		t.Fatalf("kill: %+v", res.exit)
	}
	// The slot is free once the exit is read, before Close.
	st2, err := d.StartStream(ctx, id, StreamSpec{Args: []string{"aerolstdio", "exit", "3"}})
	if err != nil {
		t.Fatalf("slot not freed: %v", err)
	}
	if res := mustDrain(t, st2); res.exit.ExitCode != 3 {
		t.Fatalf("exit: %+v", res.exit)
	}
	_ = st2.Close()
	_ = st.Close()
	_ = st.Close()
}

func TestStopAndDestroyEndStreams(t *testing.T) {
	for _, op := range []string{"stop", "destroy"} {
		t.Run(op, func(t *testing.T) {
			d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{})
			st, err := d.StartStream(context.Background(), id, StreamSpec{Args: []string{"aerolstdio", "block"}, Stdin: true, NoDeadline: true})
			if err != nil {
				t.Fatal(err)
			}
			inst, _ := d.instance(id)
			switch op {
			case "stop":
				if err := d.Stop(context.Background(), id); err != nil {
					t.Fatal(err)
				}
			case "destroy":
				if err := d.Destroy(context.Background(), &models.Sandbox{ID: id}); err != nil {
					t.Fatal(err)
				}
			}
			// The run ends, with or without an exit frame (the connection
			// is dropped), and its slot is free.
			res, _ := drain(t, st)
			if res.exit != nil && !res.exit.Killed {
				t.Fatalf("%s: run exited on its own: %+v", op, res.exit)
			}
			if n := inst.streams.count(); n != 0 {
				t.Fatalf("%s left %d slots", op, n)
			}
			if op == "stop" {
				if _, err := d.StartStream(context.Background(), id, StreamSpec{}); err == nil {
					t.Fatal("stream started on a stopped sandbox")
				}
			}
		})
	}
}

func TestStartStreamRefusals(t *testing.T) {
	d := New(Config{}, nil)
	if _, err := d.StartStream(context.Background(), "missing", StreamSpec{}); err == nil {
		t.Fatal("unknown sandbox accepted")
	}
	d.byID["sb"] = &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock"}
	// A worker client without the streaming surface is an older build.
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	if _, err := d.StartStream(context.Background(), "sb", StreamSpec{}); !errors.Is(err, ErrStreamingUnsupported) {
		t.Fatalf("no streaming client = %v", err)
	}
	// A refused start gives its slot back.
	fake := &fakeStreamingClient{startErr: worker.ErrStreamingUnsupported}
	d.SetWorkerClientFactory(func(string) WorkerClient { return fake })
	if _, err := d.StartStream(context.Background(), "sb", StreamSpec{}); !errors.Is(err, ErrStreamingUnsupported) {
		t.Fatalf("refused start = %v", err)
	}
	if n := d.byID["sb"].streams.count(); n != 0 {
		t.Fatalf("refused start held %d slots", n)
	}
}

// fakeStreamingClient records the payload a stream starts with.
type fakeStreamingClient struct {
	recordingWorkerClient
	mu       sync.Mutex
	starts   []worker.ExecStartPayload
	startErr error
	streams  []*fakeExecStream
}

func (c *fakeStreamingClient) StartExec(_ context.Context, _ string, p worker.ExecStartPayload) (workerExecStream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.starts = append(c.starts, p)
	if c.startErr != nil {
		return nil, c.startErr
	}
	st := &fakeExecStream{events: make(chan worker.ExecEvent, 8), closed: make(chan struct{})}
	c.streams = append(c.streams, st)
	return st, nil
}

type fakeExecStream struct {
	events    chan worker.ExecEvent
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	stdin     []byte
	stdinEOF  bool
	kills     int
	// stdinErr fails stdin writes; onStdin runs inside a write, which then
	// fails (a run ending under the write).
	stdinErr error
	onStdin  func()
}

func (s *fakeExecStream) Recv() (worker.ExecEvent, error) {
	select {
	case ev, ok := <-s.events:
		if !ok {
			return worker.ExecEvent{}, io.EOF
		}
		return ev, nil
	case <-s.closed:
		return worker.ExecEvent{}, io.ErrClosedPipe
	}
}

func (s *fakeExecStream) WriteStdin(p []byte) error {
	s.mu.Lock()
	s.stdin = append(s.stdin, p...)
	hook, err := s.onStdin, s.stdinErr
	s.mu.Unlock()
	if hook != nil {
		hook()
		return io.ErrClosedPipe
	}
	return err
}

func (s *fakeExecStream) CloseStdin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stdinEOF = true
	return nil
}

func (s *fakeExecStream) Kill() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kills++
	return nil
}

func (s *fakeExecStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func TestStartStreamPayload(t *testing.T) {
	d := New(Config{DefaultWallTimeout: 2 * time.Minute}, nil)
	d.byID["sb"] = &sandboxInstance{
		sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock",
		workDir: "/run/sb", memoryMB: 96, entryExport: "_start",
		baseEnv: map[string]string{"A": "1"}, baseArgs: []string{"mod", "serve"},
	}
	fake := &fakeStreamingClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return fake })
	d.SetNetworkBlocks("sb", false, true)
	d.seedNetworkPolicy("sb", nil, []string{"10.0.0.0/8"}, false)

	st, err := d.StartStream(context.Background(), "sb", StreamSpec{Env: map[string]string{"B": "2"}, Stdin: true, MaxOutputBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	p := fake.starts[0]
	if strings.Join(p.Caps.Args, " ") != "mod serve" || p.Caps.Env["A"] != "1" || p.Caps.Env["B"] != "2" {
		t.Fatalf("args/env = %v %v", p.Caps.Args, p.Caps.Env)
	}
	if len(p.Caps.Preopens) != 1 || p.Caps.Preopens[0] != (wasmengine.Preopen{GuestPath: "/work", HostPath: "/run/sb"}) {
		t.Fatalf("preopens = %+v", p.Caps.Preopens)
	}
	if p.Caps.MemoryMB != 96 || p.Caps.WallTimeoutNs != int64(2*time.Minute) || p.Caps.ListenEnabled() {
		t.Fatalf("limits = %+v", p.Caps)
	}
	if !p.Caps.NetworkBlockEgress || p.Caps.NetworkBlockIngress || !p.Caps.EgressPolicySet || len(p.Caps.EgressDenyOut) != 1 {
		t.Fatalf("network rules = %+v", p.Caps)
	}
	if p.Export != "_start" || p.ModulePath != "" || !p.Stdin || p.MaxOutputBytes != 10 || p.NoDeadline {
		t.Fatalf("payload = %+v", p)
	}

	// Output and exit map onto stream events.
	fs := fake.streams[0]
	fs.events <- worker.ExecEvent{Stream: worker.StreamStdout, Data: []byte("o")}
	fs.events <- worker.ExecEvent{Stream: worker.StreamStderr, Data: []byte("e")}
	fs.events <- worker.ExecEvent{Exit: &worker.ExecExit{ExitCode: 2, Truncated: true, Error: "trap", Usage: wasmengine.UsageStats{WallDurationMs: 7}}}
	if ev, _ := st.Recv(); string(ev.Stdout) != "o" {
		t.Fatalf("stdout event = %+v", ev)
	}
	if ev, _ := st.Recv(); string(ev.Stderr) != "e" {
		t.Fatalf("stderr event = %+v", ev)
	}
	ev, err := st.Recv()
	if err != nil || ev.Exit == nil || ev.Exit.ExitCode != 2 || !ev.Exit.Truncated || ev.Exit.Error != "trap" || ev.Exit.DurationMS != 7 {
		t.Fatalf("exit event = %+v %v", ev.Exit, err)
	}
	if err := st.WriteStdin([]byte("in")); err != nil || st.CloseStdin() != nil || st.Kill() != nil {
		t.Fatal("stdin/kill passthrough failed")
	}
	if string(fs.stdin) != "in" || !fs.stdinEOF || fs.kills != 1 {
		t.Fatalf("fake saw stdin %q eof %v kills %d", fs.stdin, fs.stdinEOF, fs.kills)
	}
	_ = st.Close()

	// A run on another module starts at that module's _start, and
	// NoDeadline reaches the worker.
	if _, err := d.StartStream(context.Background(), "sb", StreamSpec{ModulePath: "/m/python.wasm", Args: []string{"python"}, NoDeadline: true}); err != nil {
		t.Fatal(err)
	}
	p = fake.starts[1]
	if p.Export != "" || p.ModulePath != "/m/python.wasm" || !p.NoDeadline || p.Caps.Args[0] != "python" {
		t.Fatalf("other module payload = %+v", p)
	}
}

func TestCheckpointPassivateEndsStreams(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.byID["sb"] = &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock"}
	fake := &fakeStreamingClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return fake })
	st, err := d.StartStream(context.Background(), "sb", StreamSpec{})
	if err != nil {
		t.Fatal(err)
	}
	inst := d.byID["sb"]
	// A live checkpoint keeps the sandbox, and its runs, going.
	if _, _, err := d.CheckpointLiveSandbox(context.Background(), &models.Sandbox{ID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if inst.streams.count() != 1 {
		t.Fatal("live checkpoint ended a run")
	}
	if _, _, err := d.CheckpointSandbox(context.Background(), &models.Sandbox{ID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if inst.streams.count() != 0 || fake.streams[0].kills != 1 {
		t.Fatalf("passivate left the run: count %d kills %d", inst.streams.count(), fake.streams[0].kills)
	}
	if _, err := st.Recv(); err == nil {
		t.Fatal("closed run still delivers")
	}
}

// TestStreamCloseKillsARunThatHasNotExited: dropping a run's connection is
// not enough on its own (a worker whose reader is backed up behind stdin
// the guest never reads does not see it), so Close also sends a kill when
// the run has not exited and was not killed already. Its slot frees after.
func TestStreamCloseKillsARunThatHasNotExited(t *testing.T) {
	d := New(Config{}, nil)
	d.byID["sb"] = &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock", workDir: t.TempDir()}
	fake := &fakeStreamingClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return fake })
	start := func() *Stream {
		t.Helper()
		st, err := d.StartStream(context.Background(), "sb", StreamSpec{Args: []string{"aerolstdio", "spin"}, Stdin: true, NoDeadline: true})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	kills := func(i int) int {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		fs := fake.streams[i]
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.kills
	}

	dropped := start()
	_ = dropped.Close()
	_ = dropped.Close()
	if n := kills(0); n != 1 {
		t.Fatalf("a run closed before its exit was killed %d times, want 1", n)
	}

	exited := start()
	fake.streams[1].events <- worker.ExecEvent{Exit: &worker.ExecExit{ExitCode: 0}}
	if ev, err := exited.Recv(); err != nil || ev.Exit == nil {
		t.Fatalf("Recv = %+v, %v", ev, err)
	}
	_ = exited.Close()
	if n := kills(1); n != 0 {
		t.Fatalf("a run that exited was killed %d times", n)
	}

	killed := start()
	if err := killed.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = killed.Close()
	if n := kills(2); n != 1 {
		t.Fatalf("a killed run was killed %d times on close, want 1 in all", n)
	}
	if n := d.byID["sb"].streams.count(); n != 0 {
		t.Fatalf("%d slots held after every run closed", n)
	}
}

// TestMaxStreamsPerSandbox: every run may use the sandbox's whole memory
// limit, so the default cap is low (4); a configured cap is used as given
// up to the worker's own ceiling, past which a start would fail in the
// worker as a server error rather than as this cap's 429.
func TestMaxStreamsPerSandbox(t *testing.T) {
	for _, tc := range []struct {
		configured, want int
	}{
		{0, 4},
		{1, 1},
		{12, 12},
		{worker.MaxStreamsPerSandbox, worker.MaxStreamsPerSandbox},
		{worker.MaxStreamsPerSandbox + 1, worker.MaxStreamsPerSandbox},
	} {
		if got := New(Config{MaxStreamsPerSandbox: tc.configured}, nil).maxStreamsPerSandbox(); got != tc.want {
			t.Errorf("cap for %d = %d, want %d", tc.configured, got, tc.want)
		}
	}
	if defaultMaxStreamsPerSandbox > worker.MaxStreamsPerSandbox {
		t.Fatal("the default cap is above the worker's ceiling")
	}
}
