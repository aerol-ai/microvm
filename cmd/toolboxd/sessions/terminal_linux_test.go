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
