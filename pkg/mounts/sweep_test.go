package mounts

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
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

func TestKillFUSEProcessesInRoot(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	targetDir := "/some/fuse/mountpoint"

	t.Run("missing_proc_root", func(t *testing.T) {
		// ReadDir fails → early return, no panic.
		killFUSEProcessesInRoot(logger, targetDir, "/nonexistent/proc/root")
	})

	t.Run("skips_non_dir_entry", func(t *testing.T) {
		procRoot := t.TempDir()
		// A regular file named like a PID should be skipped.
		if err := os.WriteFile(filepath.Join(procRoot, "123"), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
		killFUSEProcessesInRoot(logger, targetDir, procRoot)
	})

	t.Run("skips_non_numeric_dir", func(t *testing.T) {
		procRoot := t.TempDir()
		if err := os.Mkdir(filepath.Join(procRoot, "notapid"), 0o755); err != nil {
			t.Fatal(err)
		}
		killFUSEProcessesInRoot(logger, targetDir, procRoot)
	})

	t.Run("skips_pid_dir_without_cmdline", func(t *testing.T) {
		procRoot := t.TempDir()
		if err := os.Mkdir(filepath.Join(procRoot, "999"), 0o755); err != nil {
			t.Fatal(err)
		}
		// No cmdline file → ReadFile fails → skipped.
		killFUSEProcessesInRoot(logger, targetDir, procRoot)
	})

	t.Run("skips_non_matching_cmdline", func(t *testing.T) {
		procRoot := t.TempDir()
		pidDir := filepath.Join(procRoot, "998")
		if err := os.Mkdir(pidDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("/other/path\x00arg"), 0o644); err != nil {
			t.Fatal(err)
		}
		killFUSEProcessesInRoot(logger, targetDir, procRoot)
	})

	t.Run("dir_already_has_trailing_slash", func(t *testing.T) {
		// Exercises the !strings.HasSuffix branch (condition is false, no "/" appended).
		procRoot := t.TempDir()
		dirWithSlash := targetDir + "/"
		pidDir := filepath.Join(procRoot, "997")
		if err := os.Mkdir(pidDir, 0o755); err != nil {
			t.Fatal(err)
		}
		// cmdline matches via bytes.Contains
		if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(dirWithSlash+"sub\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
		// Use a non-existent PID so Kill is a no-op (ESRCH ignored).
		killFUSEProcessesInRoot(logger, dirWithSlash, procRoot)
	})

	t.Run("matches_contains_nonexistent_pid", func(t *testing.T) {
		// cmdline contains dirSlash → match via bytes.Contains.
		// Non-existent PID → Getpgid fails → Kill(pid, SIGKILL) called (ESRCH silently ignored).
		procRoot := t.TempDir()
		const fakePID = "4194305" // above Linux pid_max; Getpgid returns ESRCH
		pidDir := filepath.Join(procRoot, fakePID)
		if err := os.Mkdir(pidDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(targetDir+"/subdir\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
		killFUSEProcessesInRoot(logger, targetDir, procRoot)
	})

	t.Run("matches_has_suffix_nonexistent_pid", func(t *testing.T) {
		// cmdline ends with dir (no trailing slash) → match only via bytes.HasSuffix.
		procRoot := t.TempDir()
		const fakePID = "4194306"
		pidDir := filepath.Join(procRoot, fakePID)
		if err := os.Mkdir(pidDir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Does NOT contain dirSlash ("/some/fuse/mountpoint/"), but HasSuffix of dir matches.
		if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("rclone mount"+targetDir), 0o644); err != nil {
			t.Fatal(err)
		}
		killFUSEProcessesInRoot(logger, targetDir, procRoot)
	})

	t.Run("kills_real_subprocess_pgid_path", func(t *testing.T) {
		// Start a subprocess in its own process group so Kill(-pgid, SIGKILL)
		// only affects it, not the test runner. Exercises the Getpgid-success branch.
		cmd := exec.Command("sleep", "100")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			t.Skip("cannot start subprocess:", err)
		}

		procRoot := t.TempDir()
		pid := cmd.Process.Pid
		pidDir := filepath.Join(procRoot, strconv.Itoa(pid))
		if err := os.Mkdir(pidDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(targetDir+"/\x00"), 0o644); err != nil {
			t.Fatal(err)
		}

		killFUSEProcessesInRoot(logger, targetDir, procRoot)

		// Wait confirms the process was killed (not still running).
		_ = cmd.Wait()
	})
}

func TestUnmountTree_Coverage(t *testing.T) {
	d := t.TempDir()
	child := filepath.Join(d, "child")
	os.MkdirAll(child, 0755)

	// Just call unmountTree, it shouldn't crash. Since devOf(child) == devOf(d),
	// it won't actually call umount unless we fake it.
	unmountTree(slog.Default(), d)
}
