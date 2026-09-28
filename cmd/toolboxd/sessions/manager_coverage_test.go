package sessions

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

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
