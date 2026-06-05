package sessions

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNewManagerValidationAndSweeper(t *testing.T) {
	if _, err := New(nil, Config{RecordingDir: t.TempDir()}); err == nil {
		t.Fatal("New(nil, ...) expected error")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(logger, Config{}); err == nil {
		t.Fatal("New without recording dir expected error")
	}
	if _, err := New(logger, Config{RecordingDir: "relative/path"}); err == nil {
		t.Fatal("New with relative recording dir expected error")
	}

	root := t.TempDir()
	mgr, err := New(logger, Config{
		SandboxID:          "sb-sweep",
		RecordingDir:       root,
		RecordingRetention: time.Hour,
		SweepInterval:      time.Minute,
		BufferBytes:        1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mgr.Close)

	recDir := filepath.Join(root, "sb-sweep")
	oldCast := filepath.Join(recDir, "old.cast")
	keepText := filepath.Join(recDir, "keep.txt")
	if err := os.WriteFile(oldCast, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile(oldCast): %v", err)
	}
	if err := os.WriteFile(keepText, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile(keepText): %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(oldCast, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes(oldCast): %v", err)
	}

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Name:    "live-session",
		Command: "sleep 30",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(sess.ID()) })

	if _, err := mgr.GetByName("live-session"); err != nil {
		t.Fatalf("GetByName(live-session): %v", err)
	}

	mgr.sweepOnce()

	if _, err := os.Stat(oldCast); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old cast stat err = %v, want not-exist", err)
	}
	if _, err := os.Stat(keepText); err != nil {
		t.Fatalf("keep text removed unexpectedly: %v", err)
	}
	if _, err := os.Stat(sess.RecordingPath()); err != nil {
		t.Fatalf("live recording removed unexpectedly: %v", err)
	}
}

func TestManagerGetOrCreateAndByNameCleanup(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	if _, _, err := mgr.GetOrCreate(ctx, models.CreateSessionRequest{}); err == nil {
		t.Fatal("GetOrCreate without name expected error")
	}

	req := models.CreateSessionRequest{Name: "shared", Command: "sleep 30"}
	first, created, err := mgr.GetOrCreate(ctx, req)
	if err != nil || !created {
		t.Fatalf("first GetOrCreate = (%v, %v, %v)", first, created, err)
	}
	second, created, err := mgr.GetOrCreate(ctx, req)
	if err != nil || created {
		t.Fatalf("second GetOrCreate created = %v err=%v", created, err)
	}
	if first.ID() != second.ID() {
		t.Fatalf("GetOrCreate returned different sessions: %s vs %s", first.ID(), second.ID())
	}

	if err := mgr.Delete(first.ID()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := mgr.Delete(first.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete err = %v, want ErrNotFound", err)
	}
	if _, err := mgr.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrNotFound", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := mgr.GetByName("shared"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByName after delete err = %v, want ErrNotFound", err)
	}
}

func TestRecorderLifecycleAndPath(t *testing.T) {
	var nilRecorder *recorder
	nilRecorder.WriteOutput([]byte("ignored"))
	nilRecorder.WriteInput([]byte("ignored"))
	if err := nilRecorder.Sync(); err != nil {
		t.Fatalf("nil Sync: %v", err)
	}
	if err := nilRecorder.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
	if got := nilRecorder.Path(); got != "" {
		t.Fatalf("nil Path = %q, want empty", got)
	}

	path := filepath.Join(t.TempDir(), "cast", "session.cast")
	rec, err := newRecorder(path, 0, 0, "test title")
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	rec.WriteOutput([]byte("stdout"))
	rec.WriteInput([]byte("stdin"))
	if err := rec.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := rec.Path(); got != path {
		t.Fatalf("Path = %q, want %q", got, path)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `"version":2`) || !strings.Contains(text, `"o","stdout"`) || !strings.Contains(text, `"i","stdin"`) {
		t.Fatalf("unexpected cast contents: %s", text)
	}

	if _, err := newRecorder(filepath.Join(string([]byte{0}), "bad.cast"), 80, 24, "bad"); err == nil {
		t.Fatal("newRecorder with invalid path expected error")
	}
}

func TestSessionSnapshotAndControlHelpers(t *testing.T) {
	if got := (&Session{}).PID(); got != 0 {
		t.Fatalf("zero session PID = %d, want 0", got)
	}
	if path := (&Session{}).RecordingPath(); path != "" {
		t.Fatalf("zero session RecordingPath = %q, want empty", path)
	}
	if code, signal := (&Session{}).ExitInfo(); code != -1 || signal != "" {
		t.Fatalf("zero session ExitInfo = (%d,%q), want (-1,\"\")", code, signal)
	}
	if err := (&Session{}).CloseStdin(); err != nil {
		t.Fatalf("zero session CloseStdin: %v", err)
	}
	if err := (&Session{}).Signal("TERM"); err == nil {
		t.Fatal("zero session Signal expected error")
	}

	base := Session{
		id:        "ses-1",
		name:      "snap",
		argv:      []string{"/bin/sh", "-c", "true"},
		workdir:   "/tmp",
		pty:       true,
		createdAt: time.Now().UTC(),
		startedAt: time.Now().UTC(),
		doneCh:    make(chan struct{}),
		buf:       newRing(16),
		recorder:  &recorder{path: "/tmp/rec.cast"},
	}
	base.bytes.Store(12)
	base.attached.Store(2)
	if snap := base.Snapshot(); snap.Status != models.SessionStatusRunning || !snap.Recording || snap.Bytes != 12 || snap.Attached != 2 {
		t.Fatalf("running snapshot = %+v", snap)
	}

	base.exited.Store(true)
	base.exitCode = 7
	if snap := base.Snapshot(); snap.Status != models.SessionStatusExited || snap.ExitCode != 7 {
		t.Fatalf("exited snapshot = %+v", snap)
	}
	base.failed = true
	if snap := base.Snapshot(); snap.Status != models.SessionStatusFailed {
		t.Fatalf("failed snapshot = %+v", snap)
	}
	base.failed = false
	base.exitSignal = "terminated"
	if snap := base.Snapshot(); snap.Status != models.SessionStatusKilled {
		t.Fatalf("killed snapshot = %+v", snap)
	}
}

func TestInterpretWaitProcessResultAndRecordingPath(t *testing.T) {
	if code, signal := interpretWaitProcessResult(nil); code != 0 || signal != "" {
		t.Fatalf("interpretWaitProcessResult(nil) = (%d,%q)", code, signal)
	}
	cmd := exec.Command("sh", "-c", "exit 3")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if code, signal := interpretWaitProcessResult(err); code != 3 || signal != "" {
		t.Fatalf("interpretWaitProcessResult(exit 3) = (%d,%q)", code, signal)
	}
	if path := recordingPathForID("/tmp/root", "sb", "ses"); path != filepath.Join("/tmp/root", "sb", "ses.cast") {
		t.Fatalf("recordingPathForID = %q", path)
	}
}

func TestRingAndEnvHelpers(t *testing.T) {
	r := newRing(0)
	if r.cap != 1 {
		t.Fatalf("newRing(0) cap = %d, want 1", r.cap)
	}
	r2 := newRing(8)
	if r2.cap != 8 {
		t.Fatalf("newRing(8) cap = %d, want 8", r2.cap)
	}

	merged := mergeEnv(map[string]string{"COVERAGE_MORE_TEST": "1"})
	found := false
	for _, entry := range merged {
		if entry == "COVERAGE_MORE_TEST=1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("mergeEnv output missing injected var: %v", merged)
	}

	if id, err := newSessionID(); err != nil || !strings.HasPrefix(id, "ses-") || len(id) != 20 {
		t.Fatalf("newSessionID = (%q,%v)", id, err)
	}
}

func TestDetectShellBranchesAndCreateFailures(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", origPath)
	if shell := detectShell(); shell == "" {
		t.Fatal("detectShell with normal PATH returned empty")
	}

	tempBin := t.TempDir()
	if err := os.Symlink("/bin/sh", filepath.Join(tempBin, "sh")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	t.Setenv("PATH", tempBin)
	if shell := detectShell(); shell != filepath.Join(tempBin, "sh") {
		t.Fatalf("detectShell PATH=sh-only = %q", shell)
	}

	t.Setenv("PATH", "")
	if shell := detectShell(); shell != "/bin/sh" {
		t.Fatalf("detectShell fallback = %q, want /bin/sh", shell)
	}

	mgr := newTestManager(t)
	if _, err := mgr.Create(context.Background(), models.CreateSessionRequest{Argv: []string{"/definitely/missing-binary"}}); err == nil {
		t.Fatal("Create with missing binary expected error")
	}
	if _, err := mgr.Create(context.Background(), models.CreateSessionRequest{Argv: []string{"/definitely/missing-binary"}, PTY: true}); err == nil {
		t.Fatal("Create PTY with missing binary expected error")
	}
}
