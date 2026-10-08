package sessions

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/loginshell"
	"github.com/aerol-ai/microvm/pkg/models"
)

func waitDone(t *testing.T, s *Session) string {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session did not exit")
	}
	return string(s.Replay())
}

// TestLoginSessionsKeepTheImagePath: a login shell given a command (the
// argv an E2B command arrives with) and a login shell fed through stdin (a
// Daytona session) both run with the image's PATH first, after
// /etc/profile has reset it.
func TestLoginSessionsKeepTheImagePath(t *testing.T) {
	t.Setenv(loginshell.Env, "/aerolvm-image/bin:/usr/bin:/bin")
	mgr := newTestManager(t)
	ctx := context.Background()

	s, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "e2b", Argv: []string{"/bin/sh", "-l", "-c", `printf 'P=%s\n' "$PATH"`}})
	if err != nil {
		t.Fatal(err)
	}
	if out := waitDone(t, s); !strings.Contains(out, "P=/aerolvm-image/bin:") {
		t.Fatalf("login -c session: %q", out)
	}

	s, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "daytona", Argv: []string{"/bin/sh", "-l"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("printf 'P=%s\\n' \"$PATH\"; exit\n")); err != nil {
		t.Fatal(err)
	}
	if out := waitDone(t, s); !strings.Contains(out, "P=/aerolvm-image/bin:") {
		t.Fatalf("stdin login session: %q", out)
	}

	// A request's own PATH is the one kept.
	s, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "req", Argv: []string{"/bin/sh", "-lc", `printf 'P=%s\n' "$PATH"`},
		Env: map[string]string{"PATH": "/req/bin:/usr/bin:/bin"}})
	if err != nil {
		t.Fatal(err)
	}
	if out := waitDone(t, s); !strings.Contains(out, "P=/req/bin:") {
		t.Fatalf("request PATH: %q", out)
	}

	// An empty request PATH is not a search path, so the image's stays.
	s, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "empty", Argv: []string{"/bin/sh", "-lc", `printf 'P=%s\n' "$PATH"`},
		Env: map[string]string{"PATH": ""}})
	if err != nil {
		t.Fatal(err)
	}
	if out := waitDone(t, s); !strings.Contains(out, "P=/aerolvm-image/bin:") {
		t.Fatalf("empty request PATH: %q", out)
	}
}

// TestStdinRestoreOnlyForALoginShellWithoutACommand: the restore line is
// written to stdin only for a pipe login shell with no -c. A -c login
// shell carries it in the command, and a terminal gets it from the profile
// hook, so neither is fed the line (it would show up as typed input).
func TestStdinRestoreOnlyForALoginShellWithoutACommand(t *testing.T) {
	var calls int
	orig := writeLoginRestore
	t.Cleanup(func() { writeLoginRestore = orig })
	writeLoginRestore = func(w io.Writer, s string) (int, error) {
		calls++
		return io.WriteString(w, s)
	}
	mgr := newTestManager(t)
	ctx := context.Background()

	s, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "plain", Argv: []string{"/bin/sh", "-c", "echo plain"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || strings.Contains(s.argv[2], loginshell.Restore) {
		t.Fatalf("plain -c was rewritten or fed stdin: calls=%d argv=%q", calls, s.argv)
	}
	waitDone(t, s)

	s, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "e2b", Argv: []string{"/bin/sh", "-lc", "echo e2b"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || !strings.HasPrefix(s.argv[2], loginshell.Restore) {
		t.Fatalf("login -c: calls=%d argv=%q", calls, s.argv)
	}
	waitDone(t, s)

	s, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "term", Argv: []string{"/bin/sh", "-l"}, PTY: true})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("a terminal login shell was written the restore on stdin")
	}
	if err := mgr.Delete(s.ID()); err != nil {
		t.Fatal(err)
	}

	s, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "day", Argv: []string{"/bin/sh", "-l"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("stdin login shell writes = %d, want 1", calls)
	}
	if _, err := s.Write([]byte("exit\n")); err != nil {
		t.Fatal(err)
	}
	waitDone(t, s)
}

// TestLoginRestoreWriteFailureLeavesTheSessionUp: a closed stdin is logged
// and the session still accepts a command. The restore is best-effort.
func TestLoginRestoreWriteFailureLeavesTheSessionUp(t *testing.T) {
	orig := writeLoginRestore
	t.Cleanup(func() { writeLoginRestore = orig })
	writeLoginRestore = func(io.Writer, string) (int, error) {
		return 0, errors.New("stdin closed")
	}
	var logs bytes.Buffer
	mgr, err := New(slog.New(slog.NewTextHandler(&logs, nil)), Config{
		SandboxID:    "sb-test",
		RecordingDir: t.TempDir(),
		BufferBytes:  1 << 14,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)

	s, err := mgr.Create(context.Background(), models.CreateSessionRequest{Name: "day", Argv: []string{"/bin/sh", "-l"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "PATH restore not written") {
		t.Fatalf("log = %s", logs.String())
	}
	if _, err := s.Write([]byte("echo still-up; exit\n")); err != nil {
		t.Fatal(err)
	}
	if out := waitDone(t, s); !strings.Contains(out, "still-up") {
		t.Fatalf("session: %q", out)
	}
}
