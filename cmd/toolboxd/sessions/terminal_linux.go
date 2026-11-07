//go:build linux

package sessions

import (
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// procRoot is /proc; a variable for tests.
var procRoot = "/proc"

// ptsPath returns the path of the terminal ptmx is the master of
// ("/dev/pts/N"), or "". It asks the kernel through the raw descriptor
// without calling Fd, which would switch the master to blocking mode and
// stop a Close from waking the output pump.
func ptsPath(ptmx *os.File) string {
	if ptmx == nil {
		return ""
	}
	raw, err := ptmx.SyscallConn()
	if err != nil {
		return ""
	}
	n := -1
	_ = raw.Control(func(fd uintptr) {
		if v, err := unix.IoctlGetInt(int(fd), unix.TIOCGPTN); err == nil {
			n = v
		}
	})
	if n < 0 {
		return ""
	}
	return "/dev/pts/" + strconv.Itoa(n)
}

// killTerminalHolders sends SIGKILL to every process with a descriptor open
// on the terminal at path and returns how many it signalled. The caller must
// still hold the terminal's master open, so the pts number cannot have been
// handed to another terminal.
func killTerminalHolders(path string) int {
	if path == "" {
		return 0
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0
	}
	self := os.Getpid()
	killed := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self || pid <= 1 {
			continue
		}
		if holdsFile(procRoot+"/"+entry.Name()+"/fd", path) && syscall.Kill(pid, syscall.SIGKILL) == nil {
			killed++
		}
	}
	return killed
}

// holdsFile reports whether any descriptor link in fdDir points at path.
func holdsFile(fdDir, path string) bool {
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}
	for _, fd := range fds {
		if target, err := os.Readlink(fdDir + "/" + fd.Name()); err == nil && target == path {
			return true
		}
	}
	return false
}
