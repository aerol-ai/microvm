package sessions

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSessionAccessorsAndPipeWrite(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	// `cat` echoes stdin back — lets us exercise Write/CloseStdin on a pipe.
	sess, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "cat-session", Command: "cat"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if sess.Name() != "cat-session" {
		t.Fatalf("Name = %q", sess.Name())
	}
	if sess.ID() == "" {
		t.Fatal("ID empty")
	}
	if sess.IsPTY() {
		t.Fatal("pipe session should not be PTY")
	}
	if sess.PID() <= 0 {
		t.Fatalf("PID = %d, want > 0", sess.PID())
	}

	// Resize is a no-op in pipe mode (no error).
	if err := sess.Resize(80, 24); err != nil {
		t.Fatalf("Resize(pipe) = %v", err)
	}

	if _, err := sess.Write([]byte("ping\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sess.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("cat session did not exit after stdin close")
	}

	// Writing after exit must error.
	if _, err := sess.Write([]byte("late")); err == nil {
		t.Fatal("Write after exit should error")
	}
}

func TestSessionPTYResizeAndWrite(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	sess, err := mgr.Create(ctx, models.CreateSessionRequest{
		Name:    "pty-session",
		Command: "cat",
		PTY:     true,
		Cols:    80,
		Rows:    24,
	})
	if err != nil {
		t.Fatalf("Create PTY: %v", err)
	}
	if !sess.IsPTY() {
		t.Fatal("expected PTY session")
	}
	// Valid resize.
	if err := sess.Resize(120, 40); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	// Invalid window size → error.
	if err := sess.Resize(0, 0); err == nil {
		t.Fatal("Resize(0,0) should error in PTY mode")
	}
	if _, err := sess.Write([]byte("hi\n")); err != nil {
		t.Fatalf("Write PTY: %v", err)
	}
	_ = mgr.Delete(sess.ID())
}

func TestBuildArgvAndDetectShell(t *testing.T) {
	// Explicit argv passes through verbatim.
	argv, err := buildArgv(models.CreateSessionRequest{Argv: []string{"/bin/echo", "x"}})
	if err != nil || len(argv) != 2 || argv[0] != "/bin/echo" {
		t.Fatalf("buildArgv(argv) = %v, %v", argv, err)
	}
	// Command wraps in shell -c.
	argv, err = buildArgv(models.CreateSessionRequest{Command: "echo hi"})
	if err != nil || len(argv) != 3 || argv[1] != "-c" {
		t.Fatalf("buildArgv(command) = %v, %v", argv, err)
	}
	// Default login shell.
	argv, err = buildArgv(models.CreateSessionRequest{})
	if err != nil || len(argv) == 0 {
		t.Fatalf("buildArgv(default) = %v, %v", argv, err)
	}

	if detectShell() == "" {
		t.Fatal("detectShell returned empty")
	}
}

func TestMapSignal(t *testing.T) {
	cases := map[string]syscall.Signal{
		"INT":     syscall.SIGINT,
		"sigterm": syscall.SIGTERM,
		"KILL":    syscall.SIGKILL,
		"HUP":     syscall.SIGHUP,
		"QUIT":    syscall.SIGQUIT,
	}
	for name, want := range cases {
		got := mapSignal(name)
		if got != want {
			t.Fatalf("mapSignal(%q) = %v, want %v", name, got, want)
		}
	}
	if mapSignal("BOGUS") != nil {
		t.Fatal("mapSignal(unknown) should be nil")
	}
}
