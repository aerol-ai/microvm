package main

import (
	"errors"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// E3: the buffered exec result names the signal that ended the process,
// with exit_code unchanged (-1); a shell that outlives a killed child
// reports 128+n and no signal.
func TestExecReportsTheSignal(t *testing.T) {
	setExecGrace(t, 200*time.Millisecond)
	for _, tc := range []struct {
		name     string
		req      models.ExecRequest
		signal   string
		exit     int
		timedOut bool
	}{
		{name: "exits on its own", req: models.ExecRequest{Command: "exit 3"}, exit: 3},
		{name: "timeout kills the group", req: models.ExecRequest{Command: "sleep 30", TimeoutSeconds: 1}, signal: "SIGKILL", exit: -1, timedOut: true},
		{name: "the shell itself is killed", req: models.ExecRequest{Command: "kill -TERM $$"}, signal: "SIGTERM", exit: -1},
		// argv execs the program in place of the shell, so its own end shows.
		{name: "argv program crashes", req: models.ExecRequest{Argv: []string{"sh", "-c", "kill -SEGV $$"}}, signal: "SIGSEGV", exit: -1},
		{name: "argv program interrupted", req: models.ExecRequest{Argv: []string{"sh", "-c", "kill -INT $$"}}, signal: "SIGINT", exit: -1},
		// A shell that keeps running after its child dies reports 128+n.
		{name: "shell reports 128+n", req: models.ExecRequest{Command: "sh -c 'kill -KILL $$'; exit $?"}, exit: 137},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, res, body := execRequestWith(t, newExecTestServer(), tc.req)
			if code != http.StatusOK {
				t.Fatalf("exec = %d %s", code, body)
			}
			if res.Signal != tc.signal || res.ExitCode != tc.exit || res.TimedOut != tc.timedOut {
				t.Fatalf("result = signal %q exit %d timed_out %v (%s), want %q %d %v", res.Signal, res.ExitCode, res.TimedOut, body, tc.signal, tc.exit, tc.timedOut)
			}
		})
	}
}

func TestWaitSignal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "no error", err: nil, want: ""},
		{name: "plain error", err: errors.New("boom"), want: ""},
		{name: "reaper saw a kill", err: &reapedExit{status: syscall.WaitStatus(syscall.SIGKILL)}, want: "SIGKILL"},
		{name: "reaper saw an exit", err: &reapedExit{status: syscall.WaitStatus(3 << 8)}, want: ""},
	} {
		if got := waitSignal(tc.err); got != tc.want {
			t.Errorf("%s: waitSignal = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := signalName(syscall.SIGTERM); got != "SIGTERM" {
		t.Fatalf("signalName(SIGTERM) = %q", got)
	}
	if got := signalName(syscall.Signal(200)); got != "SIG200" {
		t.Fatalf("unnamed signal = %q, want SIG200", got)
	}
}
