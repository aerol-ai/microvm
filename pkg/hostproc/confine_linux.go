//go:build linux

package hostproc

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DropPrivileges makes this process uid/gid for good: no supplementary
// groups, the real, effective and saved ids all changed, a check that the
// change took and cannot be undone, the process marked not dumpable, and
// no_new_privs set. It is the shared half of the V8 jail shim and the WASM
// worker; each installs its own filter afterwards (InstallSeccomp).
//
// The id changes go through package syscall, not x/sys/unix: syscall's
// versions change every thread of a Go process (AllThreadsSyscall, or the C
// library's broadcast under cgo), where x/sys/unix's setgroups changes only
// the calling one. The jail shim execs next, so one thread would do there;
// a WASM worker keeps running Go, so every thread must drop.
//
// no_new_privs is a thread attribute: set here on the calling thread, it
// reaches the others through InstallSeccomp's TSYNC, which the kernel makes
// carry it. Both callers always install a filter.
//
// Not dumpable: another process of the same uid (another tenant's worker)
// may then neither ptrace this one nor read its /proc/<pid>/mem or environ.
func DropPrivileges(uid, gid int) error {
	if uid <= 0 || gid <= 0 {
		return fmt.Errorf("drop privileges: refusing uid/gid %d/%d (must be non-root)", uid, gid)
	}
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("drop privileges: setgroups: %w", err)
	}
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("drop privileges: setresgid %d: %w", gid, err)
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("drop privileges: setresuid %d: %w", uid, err)
	}
	if unix.Getuid() != uid || unix.Geteuid() != uid || unix.Getgid() != gid || unix.Getegid() != gid {
		return fmt.Errorf("drop privileges: did not take (uid %d euid %d gid %d egid %d)", unix.Getuid(), unix.Geteuid(), unix.Getgid(), unix.Getegid())
	}
	if groups, err := unix.Getgroups(); err != nil || len(groups) != 0 {
		return fmt.Errorf("drop privileges: supplementary groups remain (%v, %v)", groups, err)
	}
	// Must fail from here: regaining root after the drop is the escape.
	if err := syscall.Setresuid(0, 0, 0); err == nil {
		return fmt.Errorf("drop privileges: could regain root after dropping")
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("drop privileges: not dumpable: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("drop privileges: no_new_privs: %w", err)
	}
	return nil
}

// InstallSeccomp loads prog with TSYNC, so every thread of this
// (multi-threaded Go) process is filtered, and every thread gets
// no_new_privs with it.
func InstallSeccomp(prog []SockFilter) error {
	if len(prog) == 0 || len(prog) > MaxSeccompInsns {
		return fmt.Errorf("seccomp: program has %d instructions", len(prog))
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, insn := range prog {
		filter[i] = unix.SockFilter{Code: insn.Code, Jt: insn.Jt, Jf: insn.Jf, K: insn.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER): %w", errno)
	}
	return nil
}

// ConfinedProcFD is the path that reaches the open file fd from inside
// this process: the kernel follows it to the file itself, without walking
// the path the file was opened by, so a directory sandboxd opened under a
// root-only parent stays usable after this process dropped to a uid that
// may not search that parent.
func ConfinedProcFD(fd uintptr) string { return fmt.Sprintf("/proc/self/fd/%d", fd) }
