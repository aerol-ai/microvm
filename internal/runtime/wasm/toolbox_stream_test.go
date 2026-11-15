package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/gorilla/websocket"
)

// toolboxServer serves a driver sandbox's toolbox the way sandboxd does
// (Driver.ServeToolbox), with token "tok".
func toolboxServer(t *testing.T, d *Driver, id string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.ServeToolbox(r.Context(), id, "tok", w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

type wsRun struct {
	stdout, stderr string
	exit           toolboxwire.ExecStreamControlOut
}

// runExecStream drives one exec stream to its end over a real WebSocket.
func runExecStream(t *testing.T, base string, start toolboxwire.ExecStreamStart, stdin string) wsRun {
	t.Helper()
	dialer := websocket.Dialer{Subprotocols: []string{toolboxwire.BearerSubprotocol}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(base, "http")+"/process/exec/stream", http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	if err := conn.WriteJSON(start); err != nil {
		t.Fatal(err)
	}
	if stdin != "" {
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte(stdin)); err != nil {
			t.Fatal(err)
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"close"}`)); err != nil {
			t.Fatal(err)
		}
	}
	var res wsRun
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v (so far %+v)", err, res)
		}
		if mt == websocket.TextMessage {
			if err := json.Unmarshal(data, &res.exit); err != nil {
				t.Fatal(err)
			}
			return res
		}
		switch data[0] {
		case toolboxwire.FramePrefixStdout:
			res.stdout += string(data[1:])
		case toolboxwire.FramePrefixStderr:
			res.stderr += string(data[1:])
		}
	}
}

func TestToolboxExecStreamEndToEnd(t *testing.T) {
	d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{Env: map[string]string{"BASE": "b"}})
	base := toolboxServer(t, d, id)

	res := runExecStream(t, base, toolboxwire.ExecStreamStart{Command: "aerolstdio echo"}, "over the wire")
	if res.stdout != "over the wire" || res.exit.Type != "exit" || res.exit.Code != 0 {
		t.Fatalf("echo = %+v", res)
	}
	res = runExecStream(t, base, toolboxwire.ExecStreamStart{Argv: []string{"aerolstdio", "env", "PWD"}, Workdir: "/work/sub"}, "")
	if res.stdout != "/work/sub" {
		t.Fatalf("PWD = %+v", res)
	}
	res = runExecStream(t, base, toolboxwire.ExecStreamStart{Command: `aerolstdio stderr "two words"`}, "")
	if res.stderr != "two words" {
		t.Fatalf("stderr = %+v", res)
	}
	res = runExecStream(t, base, toolboxwire.ExecStreamStart{Command: "aerolstdio exit 9"}, "")
	if res.exit.Code != 9 {
		t.Fatalf("exit = %+v", res)
	}
	res = runExecStream(t, base, toolboxwire.ExecStreamStart{Command: "aerolstdio env BASE", Env: map[string]string{"X": "1"}}, "")
	if res.stdout != "b" {
		t.Fatalf("sandbox env = %+v", res)
	}
}

// TestToolboxRunsCannotReachTheHost is the confinement regression test for
// issue #535: a command or code payload that tries to read or write a host
// file outside the sandbox's /work fails, because it runs inside the wasm
// engine with /work as its only file system.
func TestToolboxRunsCannotReachTheHost(t *testing.T) {
	d, id := streamDriver(t, Config{CodeRunModules: map[string]string{"python": "python"}}, models.CreateSandboxRequest{})
	base := toolboxServer(t, d, id)
	canaryDir := t.TempDir()
	canary := filepath.Join(canaryDir, "canary.txt")
	if err := os.WriteFile(canary, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(canaryDir, "planted.txt")

	res := runExecStream(t, base, toolboxwire.ExecStreamStart{Argv: []string{"aerolstdio", "read-file", canary}}, "")
	if res.exit.Code == 0 || strings.Contains(res.stdout, "host secret") {
		t.Fatalf("exec stream read the host canary: %+v", res)
	}
	res = runExecStream(t, base, toolboxwire.ExecStreamStart{Argv: []string{"aerolstdio", "write-file", planted, "pwned"}}, "")
	if res.exit.Code == 0 {
		t.Fatalf("exec stream wrote outside /work: %+v", res)
	}
	// A /work path that climbs out with .. stays inside the preopen.
	inst, _ := d.instance(id)
	res = runExecStream(t, base, toolboxwire.ExecStreamStart{Argv: []string{"aerolstdio", "read-file", "/work/../../../.." + canary}}, "")
	if strings.Contains(res.stdout, "host secret") {
		t.Fatalf("exec stream climbed out of /work: %+v", res)
	}
	if _, err := os.Stat(planted); !os.IsNotExist(err) {
		t.Fatalf("a run planted a host file: %v", err)
	}
	if b, _ := os.ReadFile(canary); string(b) != "host secret" {
		t.Fatalf("canary changed: %q", b)
	}
	// The same guest can use /work, so the failures above are confinement,
	// not a broken guest.
	res = runExecStream(t, base, toolboxwire.ExecStreamStart{Argv: []string{"aerolstdio", "write-file", "/work/ok.txt", "fine"}}, "")
	if res.exit.Code != 0 {
		t.Fatalf("write to /work failed: %+v", res)
	}
	if b, err := os.ReadFile(filepath.Join(inst.workDir, "ok.txt")); err != nil || string(b) != "fine" {
		t.Fatalf("/work file = %q %v", b, err)
	}
}

func TestToolboxProcessErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{ErrStreamLimit, http.StatusTooManyRequests},
		{ErrStreamingUnsupported, http.StatusNotImplemented},
		{ErrSandboxNotRunning, http.StatusConflict},
		{&CodeRunLanguageError{Language: "x"}, http.StatusBadRequest},
		{errors.New("other"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		mapped := toolhostProcessError(tc.err)
		var langErr *toolhost.CodeRunLanguageError
		got := http.StatusInternalServerError
		switch {
		case errors.Is(mapped, toolhost.ErrTooManyProcesses):
			got = http.StatusTooManyRequests
		case errors.Is(mapped, toolhost.ErrStreamingUnsupported):
			got = http.StatusNotImplemented
		case errors.Is(mapped, toolhost.ErrSandboxNotRunning):
			got = http.StatusConflict
		case errors.As(mapped, &langErr):
			got = http.StatusBadRequest
		}
		if got != tc.want {
			t.Fatalf("%v -> %v (%d), want %d", tc.err, mapped, got, tc.want)
		}
	}
}

func TestSandboxProcessesAdapter(t *testing.T) {
	d := New(Config{MaxStreamsPerSandbox: 1, CodeRunModules: map[string]string{"python": "python"}}, nil)
	d.byID["sb"] = &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock"}
	fake := &fakeStreamingClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return fake })
	module := filepath.Join(t.TempDir(), "py.wasm")
	_ = os.WriteFile(module, []byte("\x00asm"), 0o600)
	d.SetModuleResolver(fakeResolver{path: module})
	p := sandboxProcesses{driver: d, id: "sb"}
	ctx := context.Background()

	if err := p.CanStart(); err != nil {
		t.Fatalf("CanStart on an idle sandbox = %v", err)
	}
	st, err := p.StartStream(ctx, toolhost.StreamSpec{Args: []string{"a"}, Env: map[string]string{"K": "v"}, Stdin: true, NoDeadline: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := fake.starts[0]; got.Caps.Args[0] != "a" || got.Caps.Env["K"] != "v" || !got.Stdin || !got.NoDeadline {
		t.Fatalf("payload = %+v", got)
	}
	if !errors.Is(p.CanStart(), toolhost.ErrTooManyProcesses) {
		t.Fatal("CanStart at the cap did not refuse")
	}
	if _, err := p.StartCodeRun(ctx, toolhost.CodeRunSpec{Language: "python", Code: "1"}); !errors.Is(err, toolhost.ErrTooManyProcesses) {
		t.Fatalf("code-run at the cap = %v", err)
	}

	fs := fake.streams[0]
	fs.events <- workerEvent("o", "")
	fs.events <- workerExit(5)
	if ev, err := st.Recv(); err != nil || string(ev.Stdout) != "o" {
		t.Fatalf("event = %+v %v", ev, err)
	}
	if ev, err := st.Recv(); err != nil || ev.Exit == nil || ev.Exit.ExitCode != 5 {
		t.Fatalf("exit = %+v %v", ev, err)
	}
	if st.WriteStdin([]byte("x")) != nil || st.CloseStdin() != nil || st.Kill() != nil || st.Close() != nil {
		t.Fatal("passthrough failed")
	}
	if _, err := st.Recv(); err == nil {
		t.Fatal("Recv after Close succeeded")
	}

	st, err = p.StartCodeRun(ctx, toolhost.CodeRunSpec{Language: "python", Code: "print(1)", Timeout: time.Second, MaxOutputBytes: 5})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if got := fake.starts[1]; got.ModulePath != module || got.MaxOutputBytes != 5 {
		t.Fatalf("code-run payload = %+v", got)
	}
	if _, err := p.StartCodeRun(ctx, toolhost.CodeRunSpec{Language: "cobol", Code: "x"}); err == nil {
		t.Fatal("unknown language accepted")
	} else {
		var langErr *toolhost.CodeRunLanguageError
		if !errors.As(err, &langErr) {
			t.Fatalf("language error = %T %v", err, err)
		}
	}
	fake.startErr = errors.New("boom")
	if _, err := p.StartStream(ctx, toolhost.StreamSpec{}); err == nil || err.Error() != "boom" {
		t.Fatalf("start error = %v", err)
	}
	if !d.streamSlotFree("unknown-sandbox") {
		t.Fatal("an unknown sandbox has no runs to count")
	}
}

func workerEvent(stdout, stderr string) worker.ExecEvent {
	if stderr != "" {
		return worker.ExecEvent{Stream: worker.StreamStderr, Data: []byte(stderr)}
	}
	return worker.ExecEvent{Stream: worker.StreamStdout, Data: []byte(stdout)}
}

func workerExit(code int) worker.ExecEvent {
	return worker.ExecEvent{Exit: &worker.ExecExit{ExitCode: code}}
}

// TestToolboxExecStreamMessageCap: the driver hands the toolhost its cap
// on one exec stream message (SB_WASM_STREAM_MAX_MESSAGE_BYTES); past it
// the stream closes with 1009 and the run ends with it.
func TestToolboxExecStreamMessageCap(t *testing.T) {
	d, id := streamDriver(t, Config{StreamMaxMessageBytes: 64}, models.CreateSandboxRequest{})
	base := toolboxServer(t, d, id)
	dialer := websocket.Dialer{Subprotocols: []string{toolboxwire.BearerSubprotocol}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(base, "http")+"/process/exec/stream", http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	if err := conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "aerolstdio echo"}); err != nil {
		t.Fatal(err)
	}
	inst, _ := d.instance(id)
	runs := func() int {
		d.mu.Lock()
		set := inst.streams
		d.mu.Unlock()
		if set == nil {
			return 0
		}
		return set.count()
	}
	waitFor(t, "the run to start", func() bool { return runs() == 1 })
	_ = conn.WriteMessage(websocket.BinaryMessage, make([]byte, 65))
	for {
		_, _, err := conn.ReadMessage()
		if err == nil {
			continue
		}
		var closeErr *websocket.CloseError
		if !errors.As(err, &closeErr) || closeErr.Code != websocket.CloseMessageTooBig {
			t.Fatalf("read = %v, want close 1009", err)
		}
		break
	}
	waitFor(t, "the run's slot to free", func() bool { return runs() == 0 })
}
