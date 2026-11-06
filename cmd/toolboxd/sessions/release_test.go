package sessions

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"
	"weak"

	"github.com/aerol-ai/microvm/pkg/models"
)

func waitSessionDone(t *testing.T, s *Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session did not exit within 10s")
	}
}

// ReleaseReplay is how a Daytona terminal frees its buffer after it ends
// (plan E8, R11): the buffer's memory must really become garbage, and the
// exit status must survive it.
func TestReleaseReplayFreesTheBufferAndKeepsTheExit(t *testing.T) {
	mgr, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		SandboxID:    "sb-test",
		RecordingDir: t.TempDir(),
		BufferBytes:  4 << 20,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mgr.Close)
	ctx := context.Background()

	running, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "running", Command: "sleep 30"})
	if err != nil {
		t.Fatalf("Create running: %v", err)
	}
	if running.ReleaseReplay() {
		t.Fatal("ReleaseReplay freed a running session's buffer; its pumps still write to it")
	}
	_ = running.Signal("KILL")

	sess, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "finished", Command: "printf release-me; exit 3"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	waitSessionDone(t, sess)
	if got := string(sess.Replay()); !strings.Contains(got, "release-me") {
		t.Fatalf("replay before release = %q", got)
	}

	sess.mu.Lock()
	backing := weak.Make(&sess.buf.buf[0])
	sess.mu.Unlock()

	if !sess.ReleaseReplay() {
		t.Fatal("ReleaseReplay on a finished session = false")
	}
	if sess.ReleaseReplay() {
		t.Fatal("a second ReleaseReplay = true; there is nothing left to free")
	}
	freed := false
	for i := 0; i < 10 && !freed; i++ {
		runtime.GC()
		freed = backing.Value() == nil
	}
	if !freed {
		t.Fatal("the replay buffer is still reachable after ReleaseReplay")
	}

	if got := sess.Replay(); len(got) != 0 {
		t.Fatalf("replay after release = %q, want empty", got)
	}
	frames, cancel := sess.Subscribe()
	defer cancel()
	if frame, ok := <-frames; ok {
		t.Fatalf("attach after release replayed %q, want only the end", frame.Data)
	}
	if code, signal := sess.ExitInfo(); code != 3 || signal != "" {
		t.Fatalf("exit after release = %d %q, want 3", code, signal)
	}
	if snap := sess.Snapshot(); snap.Status != models.SessionStatusExited || snap.ExitCode != 3 {
		t.Fatalf("snapshot after release = %+v", snap)
	}
	// A late write from a pump (none happen after exit) must not panic.
	sess.fanout(StreamStdout, []byte("late"))
	if got := sess.Replay(); len(got) > 1 {
		t.Fatalf("replay after a late write = %q, want at most one byte kept", got)
	}
}

func TestSessionSizeTracksResize(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	sess, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "sized", Command: "sleep 30", PTY: true, Cols: 120, Rows: 40})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = sess.Signal("KILL") })
	if cols, rows := sess.Size(); cols != 120 || rows != 40 {
		t.Fatalf("Size() = %dx%d, want 120x40", cols, rows)
	}
	if err := sess.Resize(100, 30); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if cols, rows := sess.Size(); cols != 100 || rows != 30 {
		t.Fatalf("Size() after resize = %dx%d, want 100x30", cols, rows)
	}
	if err := sess.Resize(0, 30); err == nil {
		t.Fatal("Resize(0, 30) succeeded")
	}
	if cols, rows := sess.Size(); cols != 100 || rows != 30 {
		t.Fatalf("Size() after a refused resize = %dx%d, want 100x30", cols, rows)
	}

	defaulted, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "default-size", Command: "sleep 30", PTY: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = defaulted.Signal("KILL") })
	if cols, rows := defaulted.Size(); cols != 80 || rows != 24 {
		t.Fatalf("default Size() = %dx%d, want 80x24", cols, rows)
	}
}

// Hangup closes the terminal so the shell gets SIGHUP and the output pump
// ends even when a job still holds the terminal open.
func TestHangupClosesTheTerminal(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	sess, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "hangup", Command: "sleep 30", PTY: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = sess.Signal("KILL") })
	sess.Hangup()
	sess.Hangup() // twice is harmless
	if _, err := sess.Write([]byte("x")); err == nil {
		t.Fatal("Write after Hangup succeeded")
	}
	if err := sess.Resize(100, 30); err != nil {
		t.Fatalf("Resize after Hangup = %v, want a no-op", err)
	}
	if runtime.GOOS == "linux" {
		// The kernel hangs up the terminal only when the master really
		// closes; that needs the poller, which creack/pty's master is in on
		// Linux (where toolboxd runs) but not on macOS.
		waitSessionDone(t, sess)
		if _, signal := sess.ExitInfo(); signal == "" {
			t.Fatalf("after Hangup the shell exited normally; want it ended by SIGHUP")
		}
	}

	pipe, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "pipe", Command: "sleep 30"})
	if err != nil {
		t.Fatalf("Create pipe: %v", err)
	}
	t.Cleanup(func() { _ = pipe.Signal("KILL") })
	pipe.Hangup() // no terminal: nothing happens
	if _, err := pipe.Write([]byte("x\n")); err != nil {
		t.Fatalf("pipe Write after Hangup: %v", err)
	}
}

// Exited is already true when a subscriber's stream closes, so a client that
// saw the end and asks about the session at once sees it finished; Done may
// still be open then, because finish closes it last.
func TestExitedIsSetBeforeSubscribersClose(t *testing.T) {
	mgr, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		SandboxID:    "sb-test",
		RecordingDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mgr.Close)
	for i := 0; i < 20; i++ {
		sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Name: "exits", Command: "sleep 0.05; exit 4"})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if sess.Exited() {
			t.Fatal("Exited true for a running session")
		}
		frames, unsubscribe := sess.Subscribe()
		for range frames {
		}
		if !sess.Exited() {
			t.Fatalf("run %d: stream closed but Exited is false", i)
		}
		unsubscribe()
		waitSessionDone(t, sess)
		if code, _ := sess.ExitInfo(); code != 4 {
			t.Fatalf("exit code = %d, want 4", code)
		}
	}
}
