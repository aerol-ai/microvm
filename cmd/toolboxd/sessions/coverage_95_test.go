package sessions

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestRingDefaultCapAndWrapRemainder(t *testing.T) {
	r := newRing(0)
	if r.cap != 1 {
		t.Fatalf("newRing(0).cap = %d, want 1", r.cap)
	}
	r = newRing(8)
	if _, err := r.Write([]byte("abcdef")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// end=6, first=2, rem=2 → covers the wrap-remainder copy branch.
	if _, err := r.Write([]byte("WXYZ")); err != nil {
		t.Fatalf("Write wrap: %v", err)
	}
	got := string(r.Snapshot())
	if len(got) != 8 {
		t.Fatalf("snapshot len = %d, want 8 (%q)", len(got), got)
	}
}

func TestRecorderDefaultColsRowsAndOpenError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defaults.cast")
	rec, err := newRecorder(path, 0, -1, "title")
	if err != nil {
		t.Fatalf("newRecorder defaults: %v", err)
	}
	_ = rec.Close()

	readonly := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonly, 0o555); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o755) })
	if _, err := newRecorder(filepath.Join(readonly, "blocked.cast"), 80, 24, "x"); err == nil {
		if os.Geteuid() == 0 {
			t.Skip("root can create files in mode 0555 directories")
		}
		t.Fatal("expected open failure in read-only dir")
	}
}

func TestManagerCreateDefaultNameGetOrCreateErrorAndMergeEnv(t *testing.T) {
	mgr := newTestManager(t)

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "true",
	})
	if err != nil {
		t.Fatalf("Create blank name: %v", err)
	}
	if sess.Name() != "default" {
		t.Fatalf("Name = %q, want default", sess.Name())
	}
	_ = mgr.Delete(sess.ID())

	if _, _, err := mgr.GetOrCreate(context.Background(), models.CreateSessionRequest{
		Name:    "bad",
		Command: "true",
		WorkDir: filepath.Join(t.TempDir(), "missing-workdir"),
	}); err == nil {
		t.Fatal("expected GetOrCreate Create failure")
	}

	merged := mergeEnv(map[string]string{"COV95": "1"})
	found := false
	for _, e := range merged {
		if e == "COV95=1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("mergeEnv missing COV95=1: %v", merged)
	}
}

func TestSweepOnceFiltersAndPruneRemoveError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	mgr, err := New(logger, Config{
		SandboxID:          "sb-test",
		RecordingDir:       dir,
		RecordingRetention: time.Minute,
		SweepInterval:      20 * time.Millisecond,
		BufferBytes:        1 << 12,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mgr.Close)

	base := filepath.Join(dir, "sb-test")
	if err := os.MkdirAll(filepath.Join(base, "subdir"), 0o700); err != nil {
		t.Fatalf("MkdirAll subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile notes: %v", err)
	}
	oldCast := filepath.Join(base, "stale.cast")
	if err := os.WriteFile(oldCast, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile stale cast: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(oldCast, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	// First sweep removes the stale cast while the directory is writable.
	mgr.sweepOnce()
	if _, err := os.Stat(oldCast); !os.IsNotExist(err) {
		t.Fatalf("stale cast still present: %v", err)
	}

	// Recreate a stale cast, then lock the directory so Remove fails (log path).
	if err := os.WriteFile(oldCast, []byte("old2"), 0o600); err != nil {
		t.Fatalf("Rewrite stale cast: %v", err)
	}
	if err := os.Chtimes(oldCast, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes rewrite: %v", err)
	}
	if err := os.Chmod(base, 0o555); err != nil {
		t.Fatalf("Chmod base: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o755) })
	mgr.sweepOnce()

	// Give the background sweeper a chance to tick (covers ticker.C branch).
	time.Sleep(50 * time.Millisecond)
}

func TestBuildArgvNonBashLoginShell(t *testing.T) {
	t.Setenv("PATH", "/definitely-not-a-real-path")
	argv, err := buildArgv(models.CreateSessionRequest{})
	if err != nil {
		t.Fatalf("buildArgv: %v", err)
	}
	if len(argv) != 2 || argv[0] != "/bin/sh" || argv[1] != "-l" {
		t.Fatalf("buildArgv non-bash = %v, want [/bin/sh -l]", argv)
	}
}

func TestInterpretWaitProcessResultBranches(t *testing.T) {
	code, sig := interpretWaitProcessResult(nil)
	if code != 0 || sig != "" {
		t.Fatalf("nil = (%d, %q)", code, sig)
	}
	code, sig = interpretWaitProcessResult(syscall.ECHILD)
	if code != 0 || sig != "" {
		t.Fatalf("ECHILD = (%d, %q)", code, sig)
	}
	code, sig = interpretWaitProcessResult(errors.New("wait boom"))
	if code != -1 || sig != "wait boom" {
		t.Fatalf("generic = (%d, %q)", code, sig)
	}
}

func TestSubscribeCancelAfterExit(t *testing.T) {
	s := &Session{
		buf:    newRing(8),
		doneCh: make(chan struct{}),
	}
	_, _ = s.buf.Write([]byte("replay"))
	s.exited.Store(true)
	ch, cancel := s.Subscribe()
	cancel() // subscribed=false → early return
	// Exited sessions still deliver replay then close.
	got, ok := <-ch
	if !ok || string(got.Data) != "replay" {
		t.Fatalf("replay = (%q, %v)", string(got.Data), ok)
	}
	if _, ok := <-ch; ok {
		t.Fatal("expected channel closed after replay")
	}

	s2 := &Session{
		buf:    newRing(8),
		doneCh: make(chan struct{}),
	}
	ch2, cancel2 := s2.Subscribe()
	cancel2()
	cancel2() // once.Do no-op on second call
	select {
	case <-ch2:
	case <-time.After(time.Second):
		t.Fatal("expected subscriber channel closed after cancel")
	}
}
