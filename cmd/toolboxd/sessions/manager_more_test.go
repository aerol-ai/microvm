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

func TestManagerConstructionValidationBranches(t *testing.T) {
	if _, err := New(nil, Config{RecordingDir: t.TempDir()}); err == nil {
		t.Fatal("expected nil logger to fail")
	}
	if _, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{}); err == nil {
		t.Fatal("expected empty RecordingDir to fail")
	}
	if _, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{RecordingDir: "relative"}); err == nil {
		t.Fatal("expected relative RecordingDir to fail")
	}

	occupied := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(occupied, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile occupied: %v", err)
	}
	if _, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		RecordingDir: occupied,
	}); err == nil {
		t.Fatal("expected mkdir failure when RecordingDir is a file")
	}
}

func TestManagerHelpersAndSweepBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	mgr, err := New(logger, Config{
		SandboxID:          "sb-test",
		RecordingDir:       dir,
		RecordingRetention: time.Millisecond,
		SweepInterval:      time.Millisecond,
		BufferBytes:        0,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mgr.Close)

	if _, err := mgr.Get("missing"); err != ErrNotFound {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
	if _, err := mgr.GetByName("missing"); err != ErrNotFound {
		t.Fatalf("GetByName missing = %v, want ErrNotFound", err)
	}
	if _, _, err := mgr.GetOrCreate(context.Background(), models.CreateSessionRequest{}); err == nil {
		t.Fatal("expected GetOrCreate blank name to fail")
	}

	argv, err := buildArgv(models.CreateSessionRequest{Argv: []string{"a", "b"}})
	if err != nil || len(argv) != 2 || argv[0] != "a" || argv[1] != "b" {
		t.Fatalf("buildArgv argv = %v, %v", argv, err)
	}
	cmdArgv, err := buildArgv(models.CreateSessionRequest{Command: "printf ok"})
	if err != nil || len(cmdArgv) < 3 {
		t.Fatalf("buildArgv command = %v, %v", cmdArgv, err)
	}
	defArgv, err := buildArgv(models.CreateSessionRequest{})
	if err != nil || len(defArgv) == 0 {
		t.Fatalf("buildArgv default = %v, %v", defArgv, err)
	}

	if got := mergeEnv(nil); len(got) != len(os.Environ()) {
		t.Fatalf("mergeEnv(nil) length = %d, want %d", len(got), len(os.Environ()))
	}
	if got := orDefault(0, 42); got != 42 {
		t.Fatalf("orDefault(0) = %d, want 42", got)
	}
	if got := orDefault(7, 42); got != 7 {
		t.Fatalf("orDefault(7) = %d, want 7", got)
	}
	if shell := detectShell(); shell == "" {
		t.Fatal("detectShell returned empty string")
	}

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Name: "live", Command: "sleep 5"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := mgr.Get(sess.ID()); err != nil || got == nil {
		t.Fatalf("Get live = (%v, %v)", got, err)
	}
	if got, err := mgr.GetByName("live"); err != nil || got == nil {
		t.Fatalf("GetByName live = (%v, %v)", got, err)
	}
	if created, createdNow, err := mgr.GetOrCreate(context.Background(), models.CreateSessionRequest{Name: "live", Command: "sleep 5"}); err != nil || createdNow || created == nil {
		t.Fatalf("GetOrCreate existing = (%v, %v, %v)", created, createdNow, err)
	}
	if err := mgr.Delete(sess.ID()); err != nil {
		t.Fatalf("Delete live: %v", err)
	}
	if err := mgr.Delete("missing"); err != ErrNotFound {
		t.Fatalf("Delete missing = %v, want ErrNotFound", err)
	}

	oldCast := filepath.Join(dir, "sb-test", "old.cast")
	if err := os.MkdirAll(filepath.Dir(oldCast), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(oldCast, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile old cast: %v", err)
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oldCast, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes old cast: %v", err)
	}

	liveSess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Name: "sweep-live", Command: "sleep 5"})
	if err != nil {
		t.Fatalf("Create sweep-live: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(liveSess.ID()) })
	liveCast := liveSess.RecordingPath()
	if liveCast == "" {
		t.Fatal("expected live recording path")
	}
	if err := os.Chtimes(liveCast, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes live cast: %v", err)
	}

	mgr.sweepOnce()
	if _, err := os.Stat(oldCast); !os.IsNotExist(err) {
		t.Fatalf("old cast still exists: %v", err)
	}
	if _, err := os.Stat(liveCast); err != nil {
		t.Fatalf("live cast missing after sweep: %v", err)
	}

	// sweepOnce should be a no-op when the directory is missing.
	missing := &Manager{cfg: Config{RecordingDir: filepath.Join(t.TempDir(), "missing"), SandboxID: "sb-test"}}
	missing.sweepOnce()
}
