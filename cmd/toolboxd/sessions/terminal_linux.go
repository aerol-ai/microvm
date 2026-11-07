//go:build linux

package sessions

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// StartPTY starts cmd on a new terminal of the given size, like
// pty.StartWithSize, and returns a master that Close can interrupt.
//
// creack/pty (v1.1.24) reads the terminal number, unlocks it and sets its
// size through File.Fd(), and Fd switches a file to blocking mode and takes
// it out of Go's poller. Close on such a file cannot wake a Read already in
// progress, so the descriptor stays open until that Read returns: an output
// pump waiting on an idle shell keeps the master open, the kernel never
// hangs up the terminal and the shell never gets SIGHUP. Every Hangup that
// came after the shell's first output did nothing (10 of 10 in a forced
// test). The master is swapped for a non-blocking duplicate, which
// os.NewFile registers with the poller.
func StartPTY(cmd *exec.Cmd, cols, rows uint16) (*os.File, error) {
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, err
	}
	return pollableMaster(master), nil
}

// pollableMaster returns a non-blocking duplicate of master that Go's poller
// manages, and closes master. If any step fails it returns master as it is:
// a terminal that works, only without an interruptible Close. The duplicate
// is close-on-exec, so a child started later does not inherit the master
// and keep the terminal open after Hangup.
func pollableMaster(master *os.File) *os.File {
	raw, err := master.SyscallConn()
	if err != nil {
		return master
	}
	dup := -1
	var dupErr error
	if err := raw.Control(func(fd uintptr) {
		dup, dupErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil || dupErr != nil {
		return master
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		_ = unix.Close(dup)
		return master
	}
	pollable := os.NewFile(uintptr(dup), master.Name())
	_ = master.Close()
	return pollable
}

// SetWinsize sets a terminal's window size through the raw descriptor.
// pty.Setsize calls Fd, which would put the master back in blocking mode.
func SetWinsize(master *os.File, cols, rows uint16) error {
	raw, err := master.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
	}); err != nil {
		return err
	}
	return ioctlErr
}

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
