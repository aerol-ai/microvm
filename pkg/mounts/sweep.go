package mounts

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// killFUSEProcessesFor finds processes whose cmdline mentions a path under
// dir and sends them SIGKILL. We use /proc directly rather than `pgrep -af`
// because mount tools (mountpoint-s3, sshfs, rclone) don't all show up under
// a single name and we want to match by argv path.
func killFUSEProcessesFor(logger *slog.Logger, dir string) {
	killFUSEProcessesInRoot(logger, dir, "/proc")
}

func killFUSEProcessesInRoot(logger *slog.Logger, dir, procRoot string) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		// procRoot not available (non-Linux test, container without /proc, etc.).
		return
	}
	dirSlash := dir
	if !strings.HasSuffix(dirSlash, "/") {
		dirSlash += "/"
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, name, "cmdline"))
		if err != nil {
			continue
		}
		// /proc/<pid>/cmdline is NUL-separated. We only care whether dir is a
		// substring of any arg.
		if !bytes.Contains(raw, []byte(dirSlash)) && !bytes.HasSuffix(bytes.TrimRight(raw, "\x00"), []byte(dir)) {
			continue
		}
		logger.Info("mounts sweep: killing orphan fuse process", "pid", pid, "dir", dir)
		// Try the process group first, fall back to the bare pid.
		pgid, perr := syscall.Getpgid(pid)
		if perr == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// unmountTree walks dir and umount(s) every directory that appears to be a
// mountpoint (its st_dev differs from its parent's). Lazy umount as a fallback.
func unmountTree(logger *slog.Logger, dir string) {
	parent := filepath.Dir(dir)
	parentDev := pathDevOf(parent)

	// Unmount deepest paths first so parents become unmountable.
	type entry struct {
		path string
		dev  uint64
	}
	var found []entry
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		dev := pathDevOf(path)
		if dev != 0 && dev != parentDev {
			found = append(found, entry{path: path, dev: dev})
		}
		return nil
	})

	for i := len(found) - 1; i >= 0; i-- {
		path := found[i].path
		if err := sweepUmount(path); err == nil {
			continue
		}
		if err := sweepLazyUmount(path); err != nil {
			logger.Warn("mounts sweep: umount failed", "path", path, "error", err)
		}
	}
}

var (
	sweepUmount     = func(path string) error { return exec.Command("umount", path).Run() }
	sweepLazyUmount = func(path string) error { return exec.Command("umount", "-l", path).Run() }
)

// pathDevOf returns the st_dev for path. Tests may override it to simulate a
// mountpoint without a real FUSE mount (see unmountTree tests).
var pathDevOf = devOf

func devOf(path string) uint64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(sys.Dev)
}
