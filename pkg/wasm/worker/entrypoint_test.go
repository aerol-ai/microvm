package worker

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func stdioCaps(args ...string) wasmengine.Capabilities {
	return wasmengine.Capabilities{
		Args:           append([]string{"aerolstdio"}, args...),
		MemoryMB:       64,
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}
}

// entrypointWorker is a per-sandbox worker with the stdio guest loaded for
// sb1 and instantiated with args, its entrypoint not yet invoked.
func entrypointWorker(t *testing.T, args ...string) (*Server, *Client) {
	t.Helper()
	guest := stdioGuest(t)
	srv := &Server{}
	c := startStreamWorker(t, srv)
	if _, err := c.LoadModule("sb1", guest, 64); err != nil {
		t.Fatal(err)
	}
	if err := c.Instantiate("sb1", stdioCaps(args...)); err != nil {
		t.Fatal(err)
	}
	return srv, c
}

// The serving guest's output, dropped before, is kept for the sandbox
// whose entrypoint ran, with its exit code once it ends.
func TestEntrypointLogsKeepTheServingGuestsOutput(t *testing.T) {
	_, c := entrypointWorker(t, "stderr", "boom")
	ctx := context.Background()
	if logs, err := c.EntrypointLogs(ctx, "sb1", true); err != nil || logs.Ran {
		t.Fatalf("before invoke = %+v %v, want not run", logs, err)
	}
	_ = c.Invoke("sb1", "_start") // a guest that returns exits through proc_exit, reported as an error
	logs, err := c.EntrypointLogs(ctx, "sb1", true)
	if err != nil || !logs.Ran || logs.Running || logs.ExitCode == nil || *logs.ExitCode != 0 ||
		string(logs.Stderr) != "boom" || logs.StderrTotal != 4 || len(logs.Stdout) != 0 {
		t.Fatalf("after invoke = %+v %v", logs, err)
	}
	// Without logs only the state comes back.
	if logs, _ := c.EntrypointLogs(ctx, "sb1", false); logs.Stderr != nil || logs.StderrTotal != 4 {
		t.Fatalf("state only = %+v", logs)
	}
	// Another sandbox id never sees it.
	if logs, _ := c.EntrypointLogs(ctx, "sb2", true); logs.Ran || logs.Stderr != nil {
		t.Fatalf("other sandbox = %+v", logs)
	}
	// A guest started again (the driver re-instantiates a serving guest
	// that died) keeps the earlier output.
	if err := c.Instantiate("sb1", stdioCaps("stderr", "boom")); err != nil {
		t.Fatal(err)
	}
	_ = c.Invoke("sb1", "_start")
	if logs, _ := c.EntrypointLogs(ctx, "sb1", true); string(logs.Stderr) != "boomboom" {
		t.Fatalf("second run = %q", logs.Stderr)
	}
	// A new module is a new entrypoint.
	if _, err := c.LoadModule("sb1", stdioGuest(t), 64); err != nil {
		t.Fatal(err)
	}
	if logs, _ := c.EntrypointLogs(ctx, "sb1", true); logs.Ran {
		t.Fatalf("after reload = %+v", logs)
	}

	// A one-shot exec's output is its result, not the entrypoint's.
	if err := c.Instantiate("sb1", stdioCaps("stderr", "serve")); err != nil {
		t.Fatal(err)
	}
	_ = c.Invoke("sb1", "_start") // a guest that returns exits through proc_exit, reported as an error
	if res, err := c.Exec("sb1", stdioCaps("args", "exec-out"), "_start"); err != nil || res.Stdout != "exec-out\n" {
		t.Fatalf("exec = %+v %v", res, err)
	}
	if logs, _ := c.EntrypointLogs(ctx, "sb1", true); string(logs.Stderr) != "serve" || len(logs.Stdout) != 0 {
		t.Fatalf("entrypoint after exec = %+v", logs)
	}
}

// The ring keeps the newest bytes and counts them all; the exit code is
// the guest's.
func TestEntrypointLogsCapAndExitCode(t *testing.T) {
	old := entrypointLogBytes
	entrypointLogBytes = 1000
	t.Cleanup(func() { entrypointLogBytes = old })
	_, c := entrypointWorker(t, "flood", "5000")
	_ = c.Invoke("sb1", "_start")
	logs, err := c.EntrypointLogs(context.Background(), "sb1", true)
	if err != nil || len(logs.Stdout) != 1000 || logs.StdoutTotal != 5000 || *logs.ExitCode != 0 {
		t.Fatalf("flood = %d bytes of %d, exit %v, %v", len(logs.Stdout), logs.StdoutTotal, logs.ExitCode, err)
	}

	_, c = entrypointWorker(t, "exit", "7")
	_ = c.Invoke("sb1", "_start")
	if logs, _ := c.EntrypointLogs(context.Background(), "sb1", false); logs.ExitCode == nil || *logs.ExitCode != 7 {
		t.Fatalf("exit = %+v", logs)
	}
}

// Following streams what the entrypoint writes while it runs and ends with
// its exit; following one that ended is its replay and exit at once.
func TestFollowEntrypoint(t *testing.T) {
	srv, c := entrypointWorker(t, "stderr", "early")
	ctx := context.Background()
	if _, st, err := c.FollowEntrypoint(ctx, "sb1"); err != nil || st != nil {
		t.Fatalf("follow before any run = %v %v", st, err)
	}
	_ = c.Invoke("sb1", "_start") // a guest that returns exits through proc_exit, reported as an error
	logs, st, err := c.FollowEntrypoint(ctx, "sb1")
	if err != nil || string(logs.Stderr) != "early" {
		t.Fatalf("follow ended = %+v %v", logs, err)
	}
	got := collect(t, st)
	if got.exit.ExitCode != 0 || got.stdout != "" || got.stderr != "" {
		t.Fatalf("ended follow = %+v", got)
	}
	_ = st.Close()

	// A running entrypoint, driven by hand: what it writes after the
	// follow starts arrives live, then its exit.
	gen := srv.entry.begin("sb1")
	logs, st, err = c.FollowEntrypoint(ctx, "sb1")
	if err != nil || !logs.Running || logs.ExitCode != nil {
		t.Fatalf("follow running = %+v %v", logs, err)
	}
	defer st.Close()
	_, _ = entrypointWriter{&srv.entry, StreamStdout}.Write([]byte("live"))
	_, _ = entrypointWriter{&srv.entry, StreamStderr}.Write([]byte("warn"))
	srv.entry.end(gen, errors.New("trap"))
	got = collect(t, st)
	if got.stdout != "live" || got.stderr != "warn" || got.exit.ExitCode != 1 {
		t.Fatalf("live follow = %+v %+v", got, got.exit)
	}
	// A stale end (an earlier invoke returning late) changes nothing.
	gen2 := srv.entry.begin("sb1")
	srv.entry.end(gen, nil)
	if logs, _ := c.EntrypointLogs(ctx, "sb1", false); !logs.Running {
		t.Fatal("a stale end stopped the running entrypoint")
	}
	srv.entry.end(gen2, nil)
}

// A follower that stops reading has chunks dropped instead of slowing the
// guest, and the number of followers is capped.
func TestFollowEntrypointBounds(t *testing.T) {
	srv, c := entrypointWorker(t)
	ctx := context.Background()
	gen := srv.entry.begin("sb1")
	defer srv.entry.end(gen, nil)

	var streams []*ExecStream
	for i := 0; i < maxEntrypointFollowers; i++ {
		_, st, err := c.FollowEntrypoint(ctx, "sb1")
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, st)
	}
	if _, _, err := c.FollowEntrypoint(ctx, "sb1"); !errors.Is(err, ErrStreamLimit) {
		t.Fatalf("follower past the cap = %v", err)
	}
	// Nobody reads: the guest's writes return at once all the same.
	chunk := strings.Repeat("x", 64<<10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 64; i++ {
			_, _ = entrypointWriter{&srv.entry, StreamStdout}.Write([]byte(chunk))
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled follower blocked the guest's writes")
	}
	srv.entry.mu.Lock()
	for f := range srv.entry.followers {
		if f.queued > entrypointFollowQueueBytes {
			t.Errorf("follower queued %d bytes", f.queued)
		}
	}
	srv.entry.mu.Unlock()
	// A follower that hangs up is dropped.
	_ = streams[0].Close()
	waitStream(t, "follower to go", func() bool {
		srv.entry.mu.Lock()
		defer srv.entry.mu.Unlock()
		return len(srv.entry.followers) == maxEntrypointFollowers-1
	})
	for _, st := range streams[1:] {
		_ = st.Close()
	}
}

// A resident host never runs an entrypoint; wasmtime and old workers keep
// no output and say so.
func TestEntrypointLogsSkew(t *testing.T) {
	ctx := context.Background()
	c := startStreamWorker(t, &ResidentServer{})
	if logs, err := c.EntrypointLogs(ctx, "sb", true); err != nil || logs.Ran {
		t.Fatalf("resident = %+v %v", logs, err)
	}

	// An old per-sandbox worker answers unknown types with an empty invoke result.
	old := fakeWorker(t, Envelope{Type: MsgInvokeResult})
	if _, err := old.EntrypointLogs(ctx, "sb", true); !errors.Is(err, ErrEntrypointLogsUnsupported) {
		t.Fatalf("old worker = %v", err)
	}
	if _, _, err := old.FollowEntrypoint(ctx, "sb"); !errors.Is(err, ErrEntrypointLogsUnsupported) {
		t.Fatalf("old worker follow = %v", err)
	}
	// An old resident host refuses them by name.
	msg, _ := encodePayload(errorPayload{Message: "entrypoint_logs not supported in resident-host mode (route to per-sandbox worker)"})
	if _, err := fakeWorker(t, Envelope{Type: MsgError, Payload: msg}).EntrypointLogs(ctx, "sb", true); !errors.Is(err, ErrEntrypointLogsUnsupported) {
		t.Fatalf("old resident = %v", err)
	}
	msg, _ = encodePayload(errorPayload{Message: "boom"})
	if _, err := fakeWorker(t, Envelope{Type: MsgError, Payload: msg}).EntrypointLogs(ctx, "sb", true); err == nil || err.Error() != "boom" {
		t.Fatalf("plain error = %v", err)
	}
	for _, reply := range []Envelope{
		{Type: MsgError, Payload: []byte("{")},
		{Type: MsgOK, Payload: []byte("{")},
		{Type: MsgInvokeResult, Payload: []byte(`{"exit_code":0}`)},
		{Type: MsgPong},
	} {
		if _, err := fakeWorker(t, reply).EntrypointLogs(ctx, "sb", true); err == nil || errors.Is(err, ErrEntrypointLogsUnsupported) {
			t.Fatalf("reply %s %q = %v", reply.Type, reply.Payload, err)
		}
	}

	// wasmtime: the guest's output goes to the worker's own stdio.
	t.Setenv("AEROL_WASM_ENGINE", "wasmtime")
	c = startStreamWorker(t, &Server{})
	if _, err := c.EntrypointLogs(ctx, "sb", true); !errors.Is(err, ErrEntrypointLogsUnsupported) {
		t.Fatalf("wasmtime = %v", err)
	}
}

func TestEntrypointLogsRequestErrors(t *testing.T) {
	c := NewClient("unused")
	c.dial = func(string) (net.Conn, error) { return nil, errors.New("no worker") }
	if _, err := c.EntrypointLogs(nil, "sb", true); err == nil { //nolint:staticcheck // nil ctx is accepted
		t.Fatal("dial error swallowed")
	}
	// A worker that never answers: the deadline ends the request.
	c.dial = func(string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, server) }()
		t.Cleanup(func() { server.Close() })
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.EntrypointLogs(ctx, "sb", true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung worker = %v", err)
	}
	old := encodePayload
	encodePayload = func(any) ([]byte, error) { return nil, errors.New("encode") }
	_, err := c.EntrypointLogs(context.Background(), "sb", true)
	encodePayload = old
	if err == nil {
		t.Fatal("encode error swallowed")
	}
	// A request the worker cannot decode is refused.
	srv := &Server{}
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_ = srv.entry.serve(server, Envelope{Type: MsgEntrypointLogs, SandboxID: "sb", Payload: []byte("{")})
	}()
	reply, err := readFrame(client)
	if err != nil || reply.Type != MsgError {
		t.Fatalf("bad payload reply = %+v %v", reply, err)
	}
}
