//go:build linux

package mounts

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"
)

// openFuseFD opens /dev/fuse and mounts it at hostPath: nosuid, nodev,
// allow_other, owned by uid and gid, read-only when asked. The caller hands
// the descriptor to the tool that serves it and closes its own.
func openFuseFD(hostPath, subtype string, uid, gid uint32, readOnly bool) (*os.File, error) {
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/fuse: %w", err)
	}
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV)
	if readOnly {
		flags |= unix.MS_RDONLY
	}
	data := fmt.Sprintf("fd=%d,rootmode=40000,user_id=%d,group_id=%d,allow_other", fd, uid, gid)
	if err := unix.Mount("aerolvm", hostPath, "fuse."+subtype, flags, data); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("mount: %w", err)
	}
	return os.NewFile(uintptr(fd), "/dev/fuse"), nil
}

// newCredMemfd is a memfd holding body: owned by uid and gid, mode 0400,
// sealed so nothing can change it. Only its holder, or a process allowed
// to read the holder's descriptors, can open it.
func newCredMemfd(body []byte, uid, gid uint32) (*os.File, error) {
	fd, err := unix.MemfdCreate("aerolvm-mount-credentials", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("memfd: %w", err)
	}
	f := os.NewFile(uintptr(fd), "memfd")
	if err := fillCredMemfd(fd, body, uid, gid); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func fillCredMemfd(fd int, body []byte, uid, gid uint32) error {
	for rest := body; len(rest) > 0; {
		n, err := unix.Write(fd, rest)
		if err != nil {
			return fmt.Errorf("memfd write: %w", err)
		}
		rest = rest[n:]
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return fmt.Errorf("memfd owner: %w", err)
	}
	if err := unix.Fchmod(fd, 0o400); err != nil {
		return fmt.Errorf("memfd mode: %w", err)
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		return fmt.Errorf("memfd seals: %w", err)
	}
	return nil
}

// startNoNewPrivs starts cmd from a thread with no-new-privs set, which
// the child inherits: Go's SysProcAttr cannot set it between fork and
// exec. The goroutine never unlocks its thread, so Go ends the thread with
// it and the flag never reaches another goroutine of the helper. Go ends
// every such thread but the main one, which it parks for good instead; the
// main thread's flag is also what /proc/<pid>/status shows for the whole
// process. So the flag is never set on the main thread (startOffMainThread).
func startNoNewPrivs(cmd *exec.Cmd) error {
	errc := make(chan error, 1)
	go startOffMainThread(cmd, errc)
	return <-errc
}

// startOffMainThread is startNoNewPrivs's goroutine. When it lands on the
// main thread, it holds that thread while a second goroutine does the
// start: a locked thread runs no other goroutine, so the second one runs
// on another thread. Then it unlocks the main thread, which it left as it
// found it.
func startOffMainThread(cmd *exec.Cmd, errc chan<- error) {
	runtime.LockOSThread()
	if unix.Gettid() == unix.Getpid() {
		inner := make(chan error, 1)
		go startOffMainThread(cmd, inner)
		errc <- <-inner
		runtime.UnlockOSThread()
		return
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		errc <- fmt.Errorf("no-new-privs: %w", err)
		return
	}
	errc <- cmd.Start()
}
