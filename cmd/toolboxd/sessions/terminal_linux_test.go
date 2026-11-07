//go:build linux

package sessions

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/sys/unix"
)

func TestHoldsFileAndNoPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/dev/pts/7", filepath.Join(dir, "0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, "1")); err != nil {
		t.Fatal(err)
	}
	if !holdsFile(dir, "/dev/pts/7") || holdsFile(dir, "/dev/pts/8") || holdsFile(filepath.Join(dir, "missing"), "/dev/pts/7") {
		t.Fatal("holdsFile matched wrongly")
	}
	if killTerminalHolders("") != 0 || ptsPath(nil) != "" {
		t.Fatal("empty inputs must do nothing")
	}
}

// A job started under job control sits in its own process group and keeps
// the terminal open after the shell's group is killed, so the session never
// finished (UC-387 live). KillTerminal ends every process on the terminal.
func TestKillTerminalEndsJobControlJobs(t *testing.T) {
	mgr, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{SandboxID: "sb-test", RecordingDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mgr.Close)
	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Name:    "term",
		PTY:     true,
		Command: `sh -c 'set -m; sleep 300 & echo job=$!; sleep 300'`,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !regexp.MustCompile(`^/dev/pts/\d+$`).MatchString(sess.ttyPath) {
		t.Fatalf("ttyPath = %q, want /dev/pts/N", sess.ttyPath)
	}
	var job int
	deadline := time.Now().Add(10 * time.Second)
	for job == 0 && time.Now().Before(deadline) {
		if m := regexp.MustCompile(`job=(\d+)`).FindSubmatch(sess.Replay()); m != nil {
			job, _ = strconv.Atoi(string(m[1]))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if job == 0 {
		t.Fatalf("no job pid in %q", sess.Replay())
	}
	t.Cleanup(func() { _ = syscall.Kill(job, syscall.SIGKILL) })

	// Killing the shell's group alone leaves the job, and the session open.
	_ = syscall.Kill(-sess.cmd.Process.Pid, syscall.SIGKILL)
	select {
	case <-sess.Done():
		t.Fatal("session finished while the job still held the terminal; the test no longer reproduces the bug")
	case <-time.After(500 * time.Millisecond):
	}
	if n := sess.KillTerminal(); n < 1 {
		t.Fatalf("KillTerminal signalled %d processes, want the job", n)
	}
	select {
	case <-sess.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session did not finish after KillTerminal")
	}
	if syscall.Kill(job, 0) == nil {
		// A zombie still answers kill(0); give the reaper a moment.
		time.Sleep(200 * time.Millisecond)
		if data, err := os.ReadFile("/proc/" + strconv.Itoa(job) + "/stat"); err == nil && !regexp.MustCompile(`\) Z `).Match(data) {
			t.Fatalf("job %d still running: %s", job, data)
		}
	}
	if (&Session{pty: false}).KillTerminal() != 0 {
		t.Fatal("KillTerminal signalled processes for a pipe session")
	}
	// After Hangup the master is closed and the number may be reused:
	// KillTerminal must not scan.
	if sess.KillTerminal() != 0 {
		t.Fatal("KillTerminal scanned after the session hung up")
	}
}

// masterFlags reads a session master's file status and descriptor flags
// through the raw descriptor (calling Fd would change what it measures).
func masterFlags(t *testing.T, s *Session) (nonblock, cloexec bool) {
	t.Helper()
	s.mu.Lock()
	master := s.ptmx
	s.mu.Unlock()
	if master == nil {
		t.Fatal("session has no terminal")
	}
	raw, err := master.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var status, fdFlags int
	if err := raw.Control(func(fd uintptr) {
		status, _ = unix.FcntlInt(fd, unix.F_GETFL, 0)
		fdFlags, _ = unix.FcntlInt(fd, unix.F_GETFD, 0)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	return status&unix.O_NONBLOCK != 0, fdFlags&unix.FD_CLOEXEC != 0
}

// creack/pty puts the master in blocking mode (it calls Fd), where Close
// cannot interrupt the output pump's Read. StartPTY must hand back a
// non-blocking, close-on-exec master, and a resize must not undo it.
func TestPTYMasterStaysPollable(t *testing.T) {
	mgr := newTestManager(t)
	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Name: "pollable", Command: "sleep 30", PTY: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = sess.Signal("KILL") })
	if nonblock, cloexec := masterFlags(t, sess); !nonblock || !cloexec {
		t.Fatalf("master nonblock=%v cloexec=%v, want both", nonblock, cloexec)
	}
	if err := sess.Resize(132, 43); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if nonblock, _ := masterFlags(t, sess); !nonblock {
		t.Fatal("Resize put the master back in blocking mode")
	}
}

// The way a terminal is really closed: the shell has printed something, so
// the output pump is back inside Read when Hangup runs. With a blocking
// master the Close never reached the kernel and the session never ended
// (10 of 10 before the fix); TestHangupClosesTheTerminal only passed when
// Hangup won the race against the pump's first Read.
func TestHangupAfterOutputEndsTheSession(t *testing.T) {
	mgr := newTestManager(t)
	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Name: "used", Command: "echo ready; sleep 30", PTY: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = sess.Signal("KILL") })
	frames, cancel := sess.Subscribe()
	var out []byte
	deadline := time.After(10 * time.Second)
	for !regexp.MustCompile("ready").Match(out) {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatalf("session ended before printing; output %q", out)
			}
			out = append(out, f.Data...)
		case <-deadline:
			t.Fatalf("no output within 10s; got %q", out)
		}
	}
	cancel()
	if err := sess.Resize(100, 30); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	sess.Hangup()
	waitSessionDone(t, sess)
	if _, signal := sess.ExitInfo(); signal == "" {
		t.Fatal("after Hangup the shell exited normally; want it ended by SIGHUP")
	}
}

// When the master cannot be duplicated the terminal still works, only
// without an interruptible Close, and a resize on a closed master fails.
func TestPollableMasterFallbacks(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "master")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got := pollableMaster(f); got != f {
		t.Fatal("a closed master must come back unchanged")
	}
	if err := SetWinsize(f, 80, 24); err == nil {
		t.Fatal("SetWinsize on a closed master succeeded")
	}
	open, err := os.CreateTemp(t.TempDir(), "notatty")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = open.Close() })
	if err := SetWinsize(open, 80, 24); err == nil {
		t.Fatal("SetWinsize on a regular file succeeded")
	}
}
