package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// fakeEntrypointClient answers the entrypoint calls with what a test set.
type fakeEntrypointClient struct {
	recordingWorkerClient
	logs     worker.EntrypointLogs
	err      error
	stream   *fakeExecStream
	askedFor []bool
}

func (c *fakeEntrypointClient) EntrypointLogs(_ context.Context, _ string, logs bool) (worker.EntrypointLogs, error) {
	c.askedFor = append(c.askedFor, logs)
	return c.logs, c.err
}

func (c *fakeEntrypointClient) FollowEntrypoint(context.Context, string) (worker.EntrypointLogs, workerExecStream, error) {
	if c.err != nil || c.stream == nil {
		return c.logs, nil, c.err
	}
	return c.logs, c.stream, nil
}

func entrypointDriver(t *testing.T, fake WorkerClient) *Driver {
	t.Helper()
	d := New(Config{}, nil)
	d.byID["sb"] = &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock",
		baseArgs: []string{"server", "--port", "8080"}, moduleRef: "server.wasm"}
	d.SetWorkerClientFactory(func(string) WorkerClient { return fake })
	return d
}

func TestEntrypointInfo(t *testing.T) {
	code := 3
	fake := &fakeEntrypointClient{logs: worker.EntrypointLogs{Ran: true, ExitCode: &code, Stdout: []byte("out"), Stderr: []byte("err")}}
	d := entrypointDriver(t, fake)
	info, err := d.entrypoint(context.Background(), "sb", true)
	if err != nil || info.Command != "server --port 8080" || *info.ExitCode != 3 || info.Stdout != "out" || info.Stderr != "err" {
		t.Fatalf("info = %+v %v", info, err)
	}
	if len(fake.askedFor) != 1 || !fake.askedFor[0] {
		t.Fatalf("logs asked for = %v", fake.askedFor)
	}
	// Still running: no exit code. No args: the module is the command.
	fake.logs = worker.EntrypointLogs{Ran: true, Running: true}
	d.byID["sb"].baseArgs = nil
	if info, err := d.entrypoint(context.Background(), "sb", false); err != nil || info.ExitCode != nil || info.Command != "server.wasm" {
		t.Fatalf("running = %+v %v", info, err)
	}

	for _, tc := range []struct {
		logs worker.EntrypointLogs
		err  error
		want error
	}{
		{logs: worker.EntrypointLogs{}, want: toolhost.ErrNoEntrypoint},
		{err: worker.ErrEntrypointLogsUnsupported, want: toolhost.ErrEntrypointUnsupported},
		{err: fmt.Errorf("%w: busy", worker.ErrStreamLimit), want: toolhost.ErrTooManyFollowers},
	} {
		fake.logs, fake.err = tc.logs, tc.err
		if _, err := d.entrypoint(context.Background(), "sb", true); !errors.Is(err, tc.want) {
			t.Errorf("%+v %v: got %v, want %v", tc.logs, tc.err, err, tc.want)
		}
		if _, err := d.followEntrypoint(context.Background(), "sb"); !errors.Is(err, tc.want) {
			t.Errorf("follow %+v %v: got %v, want %v", tc.logs, tc.err, err, tc.want)
		}
	}
	other := errors.New("dial failed")
	fake.err = other
	if _, err := d.entrypoint(context.Background(), "sb", true); !errors.Is(err, other) {
		t.Fatalf("other error = %v", err)
	}

	// A worker client without the entrypoint surface is an older build.
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	if _, err := d.entrypoint(context.Background(), "sb", true); !errors.Is(err, toolhost.ErrEntrypointUnsupported) {
		t.Fatalf("old client = %v", err)
	}
	// A sandbox with no worker has run nothing; an unknown one is an error.
	d.byID["sb"].socketPath = ""
	if _, err := d.entrypoint(context.Background(), "sb", true); !errors.Is(err, toolhost.ErrNoEntrypoint) {
		t.Fatalf("no worker = %v", err)
	}
	if _, err := d.entrypoint(context.Background(), "missing", true); err == nil || errors.Is(err, toolhost.ErrNoEntrypoint) {
		t.Fatalf("unknown sandbox = %v", err)
	}
	if _, err := d.followEntrypoint(context.Background(), "missing"); err == nil {
		t.Fatal("follow of an unknown sandbox")
	}
}

// Following streams the worker's chunks as framed log output and ends with
// the entrypoint; stopping the sandbox ends a follow still open.
func TestFollowEntrypointFrames(t *testing.T) {
	st := &fakeExecStream{events: make(chan worker.ExecEvent, 4), closed: make(chan struct{})}
	fake := &fakeEntrypointClient{logs: worker.EntrypointLogs{Ran: true, Running: true, Stdout: []byte("old")}, stream: st}
	d := entrypointDriver(t, fake)
	f, err := d.followEntrypoint(context.Background(), "sb")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Replay, toolboxwire.LogReplay([]byte("old"), nil)) {
		t.Fatalf("replay = %q", f.Replay)
	}
	st.events <- worker.ExecEvent{Stream: worker.StreamStderr, Data: []byte("new")}
	st.events <- worker.ExecEvent{Exit: &worker.ExecExit{}}
	var got []string
	for frame := range f.Frames {
		got = append(got, string(frame))
	}
	if len(got) != 1 || got[0] != "\x02\x02\x02new" {
		t.Fatalf("frames = %q", got)
	}
	f.Close()
	f.Close() // twice is fine
	select {
	case <-st.closed:
	default:
		t.Fatal("worker stream left open")
	}

	// The sandbox's end closes an open follow.
	st2 := &fakeExecStream{events: make(chan worker.ExecEvent, 1), closed: make(chan struct{})}
	fake.stream = st2
	f2, err := d.followEntrypoint(context.Background(), "sb")
	if err != nil {
		t.Fatal(err)
	}
	d.killStreams(d.byID["sb"])
	for range f2.Frames {
	}
	select {
	case <-st2.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("stop left the follow open")
	}
	f2.Close()

	// A set that has closed takes no new follow.
	set, _ := d.sessionsFor("sb")
	set.close()
	fake.stream = &fakeExecStream{events: make(chan worker.ExecEvent), closed: make(chan struct{})}
	if _, err := d.followEntrypoint(context.Background(), "sb"); !errors.Is(err, toolhost.ErrSessionStopped) {
		t.Fatalf("follow on a closed set = %v", err)
	}
}

// End to end on the stdio guest: once the driver has run the sandbox's
// entrypoint, its output is the entrypoint session's logs, through the
// toolbox routes and the Daytona Go SDK.
func TestEntrypointLogsOnTheGuest(t *testing.T) {
	d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{ContainerCommand: []string{"aerolstdio", "stderr", "booted"}})
	if rec := serveToolbox(d, id, http.MethodGet, "/process/session/entrypoint/logs", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("before the entrypoint ran = %d %s", rec.Code, rec.Body.String())
	}
	inst, _ := d.instance(id)
	inst.bumpRunGeneration()
	d.startGuestEntryAsync(inst, d.newWorkerClient(inst.socketPath))
	waitFor(t, "entrypoint to end", func() bool {
		rec := serveToolbox(d, id, http.MethodGet, "/process/session/entrypoint", "")
		return strings.Contains(rec.Body.String(), `"exitCode":0`)
	})
	rec := serveToolbox(d, id, http.MethodGet, "/process/session/entrypoint", "")
	if rec.Body.String() != `{"commands":[{"command":"aerolstdio stderr booted","exitCode":0,"id":"entrypoint_command"}],"sessionId":"entrypoint"}`+"\n" {
		t.Fatalf("entrypoint session = %s", rec.Body.String())
	}

	proc := daytonaProcess(t, d, id)
	ctx := sdkCtx(t)
	session, err := proc.GetEntrypointSession(ctx)
	if err != nil || session.GetSessionId() != "entrypoint" || len(session.GetCommands()) != 1 || session.GetCommands()[0].GetId() != "entrypoint_command" {
		t.Fatalf("GetEntrypointSession = %+v, %v", session, err)
	}
	logs, err := proc.GetEntrypointLogs(ctx)
	if err != nil || logs.GetStderr() != "booted" || logs.GetOutput() != "booted" || logs.GetStdout() != "" {
		t.Fatalf("GetEntrypointLogs = %+v, %v", logs, err)
	}
	stdout, stderr := make(chan string, 8), make(chan string, 8)
	if err := proc.GetEntrypointLogsStream(ctx, stdout, stderr); err != nil {
		t.Fatalf("GetEntrypointLogsStream: %v", err)
	}
	var followed string
	for chunk := range stderr {
		followed += chunk
	}
	if followed != "booted" {
		t.Fatalf("followed = %q", followed)
	}
}
