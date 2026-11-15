package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/wasmtestguest"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// streamServer is a Server or ResidentServer under test.
type streamServer interface {
	Serve(net.Conn) error
	close()
	registry() *streamRegistry
}

func (s *Server) registry() *streamRegistry         { return &s.streams }
func (s *ResidentServer) registry() *streamRegistry { return &s.streams }

// startStreamWorker serves srv on a fresh socket and tears it all down
// (listener, live runs, aux engines) at the end of the test.
func startStreamWorker(t *testing.T, srv streamServer) *Client {
	t.Helper()
	// Compiling the stdio guest takes seconds (more under -race): share the
	// compile cache across this package's stream tests.
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", streamCompileCacheDir)
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("aerol-wasm-stream-%d.sock", time.Now().UnixNano()))
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = srv.Serve(c) }(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		srv.close()
		_ = os.Remove(socketPath)
	})
	return NewClient(socketPath)
}

func stdioGuest(t *testing.T) string {
	t.Helper()
	return wasmtestguest.Path(t, wasmtestguest.Stdio)
}

func stdioStart(args ...string) ExecStartPayload {
	return ExecStartPayload{Caps: wasmengine.Capabilities{
		Args:           append([]string{"aerolstdio"}, args...),
		MemoryMB:       64,
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}}
}

type collected struct {
	stdout, stderr string
	exit           *ExecExit
}

// collect reads a run to its exit.
func collect(t *testing.T, st *ExecStream) collected {
	t.Helper()
	_ = st.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var out, errOut strings.Builder
	for {
		ev, err := st.Recv()
		if err != nil {
			t.Fatalf("Recv: %v (stdout %q)", err, out.String())
		}
		if ev.Exit != nil {
			if _, err := st.Recv(); err != io.EOF {
				t.Fatalf("Recv after exit = %v, want EOF", err)
			}
			return collected{stdout: out.String(), stderr: errOut.String(), exit: ev.Exit}
		}
		switch ev.Stream {
		case StreamStdout:
			out.Write(ev.Data)
		case StreamStderr:
			errOut.Write(ev.Data)
		}
	}
}

func waitStream(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var streamServers = []struct {
	name string
	new  func() streamServer
}{
	{"per-sandbox", func() streamServer { return &Server{} }},
	{"resident", func() streamServer { return &ResidentServer{} }},
}

func TestStreamEchoStderrAndExitCodes(t *testing.T) {
	guest := stdioGuest(t)
	for _, kind := range streamServers {
		t.Run(kind.name, func(t *testing.T) {
			srv := kind.new()
			c := startStreamWorker(t, srv)
			if _, err := c.LoadModule("sb1", guest, 64); err != nil {
				t.Fatal(err)
			}
			p := stdioStart("echo")
			p.Stdin = true
			st, err := c.StartExec(context.Background(), "sb1", p)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if st.ID == "" {
				t.Fatal("no run id")
			}
			if err := st.WriteStdin([]byte("hello \xff")); err != nil {
				t.Fatal(err)
			}
			if err := st.CloseStdin(); err != nil {
				t.Fatal(err)
			}
			got := collect(t, st)
			// Bytes that are not UTF-8 come through unchanged.
			if got.stdout != "hello \xff" || got.exit.ExitCode != 0 || got.exit.Killed {
				t.Fatalf("got %+v exit %+v", got, got.exit)
			}

			st, err = c.StartExec(context.Background(), "sb1", stdioStart("stderr", "boom"))
			if err != nil {
				t.Fatal(err)
			}
			if got := collect(t, st); got.stderr != "boom" || got.exit.ExitCode != 0 {
				t.Fatalf("stderr run = %+v", got)
			}
			st.Close()

			st, err = c.StartExec(context.Background(), "sb1", stdioStart("exit", "5"))
			if err != nil {
				t.Fatal(err)
			}
			if got := collect(t, st); got.exit.ExitCode != 5 {
				t.Fatalf("exit run = %+v", got.exit)
			}
			st.Close()
			// Output counts toward the sandbox's network bytes, as for Exec.
			_, out, err := c.NetstatsTick("sb1")
			if err != nil || out < int64(len("hello \xffboom")) {
				t.Fatalf("netstats out = %d, %v", out, err)
			}
		})
	}
}

func TestStreamKillStopsABlockedRun(t *testing.T) {
	guest := stdioGuest(t)
	for _, kind := range streamServers {
		t.Run(kind.name, func(t *testing.T) {
			srv := kind.new()
			c := startStreamWorker(t, srv)
			if _, err := c.LoadModule("sb1", guest, 64); err != nil {
				t.Fatal(err)
			}
			p := stdioStart("block")
			p.Stdin = true
			p.NoDeadline = true
			st, err := c.StartExec(context.Background(), "sb1", p)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if err := st.Kill(); err != nil {
				t.Fatal(err)
			}
			got := collect(t, st)
			if !got.exit.Killed || got.exit.ExitCode != -1 {
				t.Fatalf("exit = %+v", got.exit)
			}
			waitStream(t, "run removed", func() bool { return srv.registry().count("sb1") == 0 })
		})
	}
}

func TestStreamConnectionDropKillsTheRun(t *testing.T) {
	guest := stdioGuest(t)
	srv := &Server{}
	c := startStreamWorker(t, srv)
	if _, err := c.LoadModule("sb1", guest, 64); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"block"}, {"flood", "0"}} {
		p := stdioStart(args...)
		p.Stdin = true
		p.NoDeadline = true
		st, err := c.StartExec(context.Background(), "sb1", p)
		if err != nil {
			t.Fatal(err)
		}
		waitStream(t, "run registered", func() bool { return srv.streams.count("sb1") == 1 })
		_ = st.Close()
		waitStream(t, args[0]+" run killed by the drop", func() bool { return srv.streams.count("sb1") == 0 })
	}
}

func TestStreamStopInstanceAndLoadModuleKillRuns(t *testing.T) {
	guest := stdioGuest(t)
	for _, kind := range streamServers {
		t.Run(kind.name, func(t *testing.T) {
			srv := kind.new()
			c := startStreamWorker(t, srv)
			if _, err := c.LoadModule("sb1", guest, 64); err != nil {
				t.Fatal(err)
			}
			if err := c.Instantiate("sb1", stdioStart("block").Caps); err != nil {
				t.Fatal(err)
			}
			p := stdioStart("spin")
			p.NoDeadline = true
			st, err := c.StartExec(context.Background(), "sb1", p)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.StopInstance("sb1"); err != nil {
				t.Fatal(err)
			}
			if got := collect(t, st); !got.exit.Killed {
				t.Fatalf("StopInstance left the run: %+v", got.exit)
			}
			st.Close()

			st, err = c.StartExec(context.Background(), "sb1", p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.LoadModule("sb1", guest, 64); err != nil {
				t.Fatal(err)
			}
			if got := collect(t, st); !got.exit.Killed {
				t.Fatalf("LoadModule left the run: %+v", got.exit)
			}
			st.Close()
		})
	}
}

func TestStreamAppliesTheSandboxNetworkRules(t *testing.T) {
	guest := stdioGuest(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, kind := range streamServers {
		t.Run(kind.name, func(t *testing.T) {
			srv := kind.new()
			c := startStreamWorker(t, srv)
			if _, err := c.LoadModule("sb1", guest, 64); err != nil {
				t.Fatal(err)
			}
			p := stdioStart("dial", ln.Addr().String())
			p.Caps.NetworkBlockEgress = true
			st, err := c.StartExec(context.Background(), "sb1", p)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			// 3 is aerol/vm/net's "blocked" result.
			if got := collect(t, st); got.stdout != "dial=3" {
				t.Fatalf("blocked dial = %q (stderr %q)", got.stdout, got.stderr)
			}
			// A policy that denies the address blocks it too, after the
			// quota block is lifted.
			if err := c.SetNetworkBlocks("sb1", false, false); err != nil {
				t.Fatal(err)
			}
			p = stdioStart("dial", ln.Addr().String())
			p.Caps.EgressPolicySet = true
			p.Caps.EgressDenyOut = []string{"127.0.0.1/32"}
			st2, err := c.StartExec(context.Background(), "sb1", p)
			if err != nil {
				t.Fatal(err)
			}
			defer st2.Close()
			if got := collect(t, st2); got.stdout != "dial=3" {
				t.Fatalf("denied dial = %q (stderr %q)", got.stdout, got.stderr)
			}
		})
	}
}

func TestStreamOutputCapAndTimeouts(t *testing.T) {
	guest := stdioGuest(t)
	srv := &Server{}
	c := startStreamWorker(t, srv)
	if _, err := c.LoadModule("sb1", guest, 64); err != nil {
		t.Fatal(err)
	}
	p := stdioStart("flood", "300000")
	p.MaxOutputBytes = 1000
	st, err := c.StartExec(context.Background(), "sb1", p)
	if err != nil {
		t.Fatal(err)
	}
	got := collect(t, st)
	st.Close()
	if len(got.stdout) != 1000 || !got.exit.Truncated || got.exit.ExitCode != 0 {
		t.Fatalf("capped run: %d bytes, exit %+v", len(got.stdout), got.exit)
	}

	// Large output without a cap arrives whole, split across frames.
	old := streamChunkMax
	streamChunkMax = 4096
	t.Cleanup(func() { streamChunkMax = old })
	st, err = c.StartExec(context.Background(), "sb1", stdioStart("flood", "70000"))
	if err != nil {
		t.Fatal(err)
	}
	if got := collect(t, st); len(got.stdout) != 70000 || got.exit.Truncated {
		t.Fatalf("uncapped run: %d bytes, exit %+v", len(got.stdout), got.exit)
	}
	st.Close()

	p = stdioStart("spin")
	p.Caps.WallTimeoutNs = int64(300 * time.Millisecond)
	st, err = c.StartExec(context.Background(), "sb1", p)
	if err != nil {
		t.Fatal(err)
	}
	if got := collect(t, st); !got.exit.TimedOut || got.exit.ExitCode != -1 {
		t.Fatalf("timed-out run: %+v", got.exit)
	}
	st.Close()

	// NoDeadline overrides a short wall timeout.
	p.NoDeadline = true
	st, err = c.StartExec(context.Background(), "sb1", p)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if srv.streams.count("sb1") != 1 {
		t.Fatal("NoDeadline run ended on the wall timeout")
	}
	_ = st.Kill()
	if got := collect(t, st); !got.exit.Killed {
		t.Fatalf("killed run: %+v", got.exit)
	}
	st.Close()
}

func TestStreamRunsAnotherModuleAndReapsIdleEngines(t *testing.T) {
	guest := stdioGuest(t)
	old := auxIdleTTL
	auxIdleTTL = 50 * time.Millisecond
	t.Cleanup(func() { auxIdleTTL = old })
	srv := &Server{}
	c := startStreamWorker(t, srv)
	// The sandbox's own module is something else entirely.
	if _, err := c.LoadModule("sb1", writeMinimalModule(t, t.TempDir()), 0); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	p := stdioStart("write-work", "out.txt", "from-stream")
	p.ModulePath = guest
	p.Caps.Preopens = []wasmengine.Preopen{{GuestPath: "/work", HostPath: work}}
	st, err := c.StartExec(context.Background(), "sb1", p)
	if err != nil {
		t.Fatal(err)
	}
	if got := collect(t, st); got.exit.ExitCode != 0 {
		t.Fatalf("exit %+v stderr %q", got.exit, got.stderr)
	}
	st.Close()
	if b, err := os.ReadFile(filepath.Join(work, "out.txt")); err != nil || string(b) != "from-stream" {
		t.Fatalf("work file = %q %v", b, err)
	}
	waitStream(t, "idle aux engine reaped", func() bool {
		srv.streams.mu.Lock()
		defer srv.streams.mu.Unlock()
		return len(srv.streams.aux) == 0
	})
}

func TestStreamStartRefusals(t *testing.T) {
	guest := stdioGuest(t)
	srv := &Server{}
	c := startStreamWorker(t, srv)
	ctx := context.Background()

	if _, err := c.StartExec(ctx, "sb1", stdioStart("exit", "0")); err == nil || !strings.Contains(err.Error(), "engine not loaded") {
		t.Fatalf("no module: %v", err)
	}
	if _, err := c.LoadModule("sb1", guest, 64); err != nil {
		t.Fatal(err)
	}
	if _, err := c.StartExec(ctx, "", stdioStart("exit", "0")); err == nil {
		t.Fatal("empty sandbox id accepted")
	}
	bad := stdioStart("exit", "0")
	bad.ModulePath = filepath.Join(t.TempDir(), "missing.wasm")
	if _, err := c.StartExec(ctx, "sb1", bad); err == nil {
		t.Fatal("missing module accepted")
	}
	noExport := stdioStart("exit", "0")
	noExport.Export = "no_such_export"
	if _, err := c.StartExec(ctx, "sb1", noExport); err == nil {
		t.Fatal("missing export accepted")
	}

	old := maxStreamsPerSandbox
	maxStreamsPerSandbox = 1
	t.Cleanup(func() { maxStreamsPerSandbox = old })
	p := stdioStart("block")
	p.Stdin = true
	first, err := c.StartExec(ctx, "sb1", p)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := c.StartExec(ctx, "sb1", p); !errors.Is(err, ErrStreamLimit) {
		t.Fatalf("second run = %v, want ErrStreamLimit", err)
	}
	// Another sandbox on the same worker has its own allowance.
	other, err := c.StartExec(ctx, "sb2", stdioStart("exit", "0"))
	if err != nil {
		t.Fatal(err)
	}
	collect(t, other)
	other.Close()

	t.Setenv("AEROL_WASM_ENGINE", "wasmtime")
	if _, err := c.StartExec(ctx, "sb1", p); !errors.Is(err, ErrStreamingUnsupported) {
		t.Fatalf("wasmtime = %v, want ErrStreamingUnsupported", err)
	}
}

// TestStreamSlotIsFreeWhenTheCallerHearsBack: a caller that reads a
// refusal or an exit and starts again at once must find its slot free.
// The slot used to go back only after the reply was written, so at the
// cap the next start could be refused for a run that was already over
// (seen as a TestStreamStartRefusals flake under load).
func TestStreamSlotIsFreeWhenTheCallerHearsBack(t *testing.T) {
	guest := stdioGuest(t)
	srv := &Server{}
	c := startStreamWorker(t, srv)
	ctx := context.Background()
	if _, err := c.LoadModule("sb1", guest, 64); err != nil {
		t.Fatal(err)
	}
	old := maxStreamsPerSandbox
	maxStreamsPerSandbox = 1
	t.Cleanup(func() { maxStreamsPerSandbox = old })

	held := func() (slots, runs int) {
		srv.streams.mu.Lock()
		slots = srv.streams.slots["sb1"]
		srv.streams.mu.Unlock()
		return slots, srv.streams.count("sb1")
	}
	noExport := stdioStart("exit", "0")
	noExport.Export = "no_such_export"
	for round := 0; round < 20; round++ {
		if _, err := c.StartExec(ctx, "sb1", noExport); err == nil {
			t.Fatal("missing export accepted")
		}
		if slots, runs := held(); slots != 0 || runs != 0 {
			t.Fatalf("round %d: after the refusal reached the caller: %d slots, %d runs held", round, slots, runs)
		}
		st, err := c.StartExec(ctx, "sb1", stdioStart("exit", "0"))
		if err != nil {
			t.Fatalf("round %d: start right after a refusal: %v", round, err)
		}
		collect(t, st)
		if slots, runs := held(); slots != 0 || runs != 0 {
			t.Fatalf("round %d: after the exit reached the caller: %d slots, %d runs held", round, slots, runs)
		}
		st.Close()
	}
}

func TestStreamOutOfBandKill(t *testing.T) {
	srv := &Server{}
	c := startStreamWorker(t, srv)
	// Killing a run that is gone is fine; a kill without an id is not.
	body, _ := encodePayload(execKillPayload{ID: "nope"})
	reply, err := c.roundTrip(Envelope{Type: MsgExecKill, SandboxID: "sb1", Payload: body})
	if err != nil || c.expectOK(reply) != nil {
		t.Fatalf("unknown id kill = %+v %v", reply, err)
	}
	body, _ = encodePayload(execKillPayload{})
	reply, err = c.roundTrip(Envelope{Type: MsgExecKill, SandboxID: "sb1", Payload: body})
	if err != nil || c.expectOK(reply) == nil {
		t.Fatalf("empty id kill = %+v %v", reply, err)
	}
	reply, err = c.roundTrip(Envelope{Type: MsgExecKill, SandboxID: "sb1"})
	if err != nil || c.expectOK(reply) == nil {
		t.Fatalf("no payload kill = %+v %v", reply, err)
	}
}

func TestStreamInBandKillAndCloseAll(t *testing.T) {
	guest := stdioGuest(t)
	srv := &ResidentServer{}
	c := startStreamWorker(t, srv)
	if _, err := c.LoadModule("sb1", guest, 64); err != nil {
		t.Fatal(err)
	}
	p := stdioStart("block")
	p.Stdin = true
	st, err := c.StartExec(context.Background(), "sb1", p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.writeMu.Lock()
	err = writeFrame(st.conn, Envelope{Type: MsgExecKill, SandboxID: "sb1"})
	st.writeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := collect(t, st); !got.exit.Killed {
		t.Fatalf("in-band kill: %+v", got.exit)
	}

	st2, err := c.StartExec(context.Background(), "sb1", p)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	srv.streams.closeAll()
	if got := collect(t, st2); !got.exit.Killed {
		t.Fatalf("closeAll: %+v", got.exit)
	}
	if _, err := c.StartExec(context.Background(), "sb1", p); err == nil {
		t.Fatal("start after closeAll succeeded")
	}
}

// fakeWorker answers the first frame on each connection with reply.
func fakeWorker(t *testing.T, reply Envelope) *Client {
	t.Helper()
	c := NewClient("unused")
	c.dial = func(string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if _, err := readFrame(server); err != nil {
				return
			}
			_ = writeFrame(server, reply)
			_, _ = io.Copy(io.Discard, server)
		}()
		return client, nil
	}
	return c
}

func TestStartExecVersionSkew(t *testing.T) {
	ctx := context.Background()
	// An old per-sandbox worker answers unknown types with an empty invoke result.
	c := fakeWorker(t, Envelope{Type: MsgInvokeResult})
	if _, err := c.StartExec(ctx, "sb", ExecStartPayload{}); !errors.Is(err, ErrStreamingUnsupported) {
		t.Fatalf("old worker = %v", err)
	}
	// An old resident host refuses them by name.
	msg, _ := encodePayload(errorPayload{Message: "exec_start not supported in resident-host mode (route to per-sandbox worker)"})
	c = fakeWorker(t, Envelope{Type: MsgError, Payload: msg})
	if _, err := c.StartExec(ctx, "sb", ExecStartPayload{}); !errors.Is(err, ErrStreamingUnsupported) {
		t.Fatalf("old resident = %v", err)
	}
	// Any other refusal keeps its message.
	msg, _ = encodePayload(errorPayload{Message: "boom"})
	c = fakeWorker(t, Envelope{Type: MsgError, Payload: msg})
	if _, err := c.StartExec(ctx, "sb", ExecStartPayload{}); err == nil || err.Error() != "boom" {
		t.Fatalf("plain error = %v", err)
	}
	c = fakeWorker(t, Envelope{Type: MsgError, Payload: []byte("{")})
	if _, err := c.StartExec(ctx, "sb", ExecStartPayload{}); err == nil {
		t.Fatal("bad error payload accepted")
	}
	c = fakeWorker(t, Envelope{Type: MsgInvokeResult, Payload: []byte(`{"exit_code":0}`)})
	if _, err := c.StartExec(ctx, "sb", ExecStartPayload{}); err == nil || errors.Is(err, ErrStreamingUnsupported) {
		t.Fatalf("non-empty invoke result = %v", err)
	}
	c = fakeWorker(t, Envelope{Type: MsgExecStarted, Payload: []byte("{")})
	if _, err := c.StartExec(ctx, "sb", ExecStartPayload{}); err == nil {
		t.Fatal("bad started payload accepted")
	}
	c = fakeWorker(t, Envelope{Type: MsgPong})
	if _, err := c.StartExec(ctx, "sb", ExecStartPayload{}); err == nil {
		t.Fatal("unexpected reply accepted")
	}
}

func TestStartExecContextAndDialErrors(t *testing.T) {
	c := NewClient("unused")
	c.dial = func(string) (net.Conn, error) { return nil, errors.New("no worker") }
	if _, err := c.StartExec(nil, "sb", ExecStartPayload{}); err == nil { //nolint:staticcheck // nil ctx is accepted
		t.Fatal("dial error swallowed")
	}
	// A worker that never answers: the cancel ends the handshake.
	c.dial = func(string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
		}()
		t.Cleanup(func() { server.Close() })
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.StartExec(ctx, "sb", ExecStartPayload{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung worker = %v", err)
	}
	// A payload that cannot be encoded never dials.
	bad := ExecStartPayload{Caps: wasmengine.Capabilities{}}
	old := encodePayload
	encodePayload = func(any) ([]byte, error) { return nil, errors.New("encode") }
	_, err := c.StartExec(context.Background(), "sb", bad)
	encodePayload = old
	if err == nil {
		t.Fatal("encode error swallowed")
	}
}

func TestExecStreamClientEdges(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	st := &ExecStream{ID: "id", client: NewClient("unused"), sandboxID: "sb", conn: client}
	go func() {
		_ = writeFrame(server, Envelope{Type: MsgExecChunk})                      // empty chunk: skipped
		_ = writeFrame(server, Envelope{Type: MsgExecExit, Payload: []byte("{")}) // bad exit
	}()
	if _, err := st.Recv(); err == nil {
		t.Fatal("bad exit accepted")
	}
	go func() { _ = writeFrame(server, Envelope{Type: MsgPong}) }()
	if _, err := st.Recv(); err == nil {
		t.Fatal("unexpected frame accepted")
	}
	// Large stdin is split into several frames.
	big := make([]byte, stdinFrameMax+10)
	done := make(chan int)
	go func() {
		n := 0
		for {
			f, err := readFrame(server)
			if err != nil {
				done <- n
				return
			}
			n += len(f.Payload)
		}
	}()
	if err := st.WriteStdin(big); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if n := <-done; n != len(big) {
		t.Fatalf("stdin bytes = %d", n)
	}
	if err := st.WriteStdin([]byte("x")); err == nil {
		t.Fatal("write after close succeeded")
	}
	if err := st.Close(); err != nil {
		t.Fatal("second close failed")
	}
	// Kill against no worker reports the dial error.
	st.client.dial = func(string) (net.Conn, error) { return nil, errors.New("gone") }
	if err := st.Kill(); err == nil {
		t.Fatal("kill without a worker succeeded")
	}
}
