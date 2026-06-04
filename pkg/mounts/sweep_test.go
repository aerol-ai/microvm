package mounts

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

func TestDevOf(t *testing.T) {
	t.Run("existing_dir_nonzero", func(t *testing.T) {
		dir := t.TempDir()
		dev := devOf(dir)
		if dev == 0 {
			t.Fatalf("devOf(%q) = 0, want non-zero", dir)
		}
	})

	t.Run("nonexistent_path_zero", func(t *testing.T) {
		dev := devOf("/nonexistent/path/that/does/not/exist")
		if dev != 0 {
			t.Fatalf("devOf non-existent = %d, want 0", dev)
		}
	})
}

func TestKillFUSEProcessesFor_NoPanic(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// On non-Linux hosts /proc doesn't exist; function must return without panic.
	if _, err := os.Stat("/proc"); os.IsNotExist(err) {
		killFUSEProcessesFor(logger, t.TempDir())
		return
	}

	// On Linux /proc exists. Passing a dir that no process references should
	// still complete without error or panic.
	killFUSEProcessesFor(logger, t.TempDir())
}
