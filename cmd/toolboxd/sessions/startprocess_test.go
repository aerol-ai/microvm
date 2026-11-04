package sessions

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A host that reaps children itself (toolboxd as PID 1) supplies
// Config.StartProcess; every session, PTY or pipes, must take its exit from
// it rather than from a bare cmd.Wait that the reaper may have beaten.
func TestConfigStartProcessOwnsTheExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  models.CreateSessionRequest
	}{
		{"pipes", models.CreateSessionRequest{Name: "bg", Command: "exit 0"}},
		{"pty", models.CreateSessionRequest{Name: "sh", Command: "exit 0", PTY: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var started int
			mgr, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
				SandboxID:    "sb-test",
				RecordingDir: t.TempDir(),
				StartProcess: func(cmd *exec.Cmd, start func() error) (func() (int, string), error) {
					started++
					if err := start(); err != nil {
						return nil, err
					}
					// What the child table reports when its reaper won:
					// the real status, which a bare cmd.Wait no longer has.
					return func() (int, string) { _ = cmd.Wait(); return 4, "" }, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(mgr.Close)
			sess, err := mgr.Create(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			select {
			case <-sess.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("session did not exit")
			}
			if code, sig := sess.ExitInfo(); started != 1 || code != 4 || sig != "" {
				t.Fatalf("StartProcess calls %d, exit (%d, %q); want 1 call and its status 4", started, code, sig)
			}
		})
	}
}

func TestConfigStartProcessFailure(t *testing.T) {
	mgr, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		SandboxID:    "sb-test",
		RecordingDir: t.TempDir(),
		StartProcess: func(*exec.Cmd, func() error) (func() (int, string), error) {
			return nil, errors.New("no more pids")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	for _, pty := range []bool{false, true} {
		if _, err := mgr.Create(context.Background(), models.CreateSessionRequest{Command: "true", PTY: pty}); err == nil {
			t.Fatalf("pty=%v: a start failure created a session", pty)
		}
	}
	if n := len(mgr.List()); n != 0 {
		t.Fatalf("%d sessions after failed starts", n)
	}
}

// Without the hook (the WASM tool host), a session still reports its
// command's own exit status.
func TestDefaultStartKeepsExitStatus(t *testing.T) {
	mgr := newTestManager(t)
	for _, pty := range []bool{false, true} {
		sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Command: "exit 5", PTY: pty})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-sess.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("session did not exit")
		}
		if code, _ := sess.ExitInfo(); code != 5 {
			t.Fatalf("pty=%v: exit %d, want 5", pty, code)
		}
	}
}
