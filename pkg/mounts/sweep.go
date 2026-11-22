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
// dir and sends them SIGKILL (signalListed: the process, and its group only
// when it leads one of its own). We use /proc directly rather than `pgrep
// -af` because mount tools (mountpoint-s3, sshfs, rclone) don't all show up
// under a single name and we want to match by argv path. owner, when set,
// limits it to that user's processes: in isolated mode the tools' user, so
// the helper, which runs as root, never stops another user's process (a
// shell, say) only because its command line names the folder.
func killFUSEProcessesFor(logger *slog.Logger, dir string, owner *uint32) {
	killFUSEProcessesInRoot(logger, dir, procRoot, owner)
}

func killFUSEProcessesInRoot(logger *slog.Logger, dir, procRoot string, owner *uint32) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		// procRoot not available (non-Linux test, container without /proc, etc.).
		return
	}
	dirSlash := dir
	if !strings.HasSuffix(dirSlash, "/") {
		dirSlash += "/"
	}

	// /proc/<pid>/cmdline is NUL-separated. We only care whether dir is a
	// substring of any arg.
	names := func(pid int) bool {
		raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
		if err != nil {
			return false
		}
		return bytes.Contains(raw, []byte(dirSlash)) || bytes.HasSuffix(bytes.TrimRight(raw, "\x00"), []byte(dir))
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !names(pid) || !ownerOK(procRoot, pid, owner) {
			continue
		}
		logger.Info("mounts sweep: killing orphan fuse process", "pid", pid, "dir", dir)
		_ = signalListed(pid, syscall.SIGKILL, func() bool { return names(pid) && ownerOK(procRoot, pid, owner) })
	}
}

// unmountTree umounts every mount point at or under dir (mountPointsUnder),
// deepest first, with a lazy umount as the fallback. It does not walk into
// a mount: that would list the storage itself.
func unmountTree(logger *slog.Logger, dir string) {
	unmountPoints(logger, mountPointsUnder(dir))
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
