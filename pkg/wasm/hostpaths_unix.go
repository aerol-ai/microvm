//go:build unix

package wasm

import "golang.org/x/sys/unix"

// dupCloexec duplicates fd for one open through /proc/self/fd.
func dupCloexec(fd uintptr) (uintptr, error) {
	nfd, err := unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	return uintptr(nfd), err
}

func closeFD(fd uintptr) { _ = unix.Close(int(fd)) }
