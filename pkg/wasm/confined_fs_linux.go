//go:build linux

package wasm

import (
	"os"
	"unsafe"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
	"golang.org/x/sys/unix"
)

func datasyncFile(f *os.File) experimentalsys.Errno {
	return controlFile(f, unix.Fdatasync)
}

// futimensFile sets f's times through its descriptor: utimensat with a NULL
// path is futimens(2) on Linux, nanosecond precise and with native
// UTIME_OMIT. x/sys/unix only offers the path form, so this is the raw call,
// as wazero's own file uses.
func futimensFile(f *os.File, atim, mtim int64) experimentalsys.Errno {
	if atim == experimentalsys.UTIME_OMIT && mtim == experimentalsys.UTIME_OMIT {
		return 0
	}
	ts := [2]unix.Timespec{wasiTimespec(atim), wasiTimespec(mtim)}
	return controlFile(f, func(fd int) error {
		_, _, e := unix.Syscall6(unix.SYS_UTIMENSAT, uintptr(fd), 0, uintptr(unsafe.Pointer(&ts[0])), 0, 0, 0)
		if e != 0 {
			return e
		}
		return nil
	})
}

func wasiTimespec(ns int64) unix.Timespec {
	if ns == experimentalsys.UTIME_OMIT {
		return unix.Timespec{Nsec: unix.UTIME_OMIT}
	}
	return unix.NsecToTimespec(ns)
}
