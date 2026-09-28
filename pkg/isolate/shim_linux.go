//go:build linux

package isolate

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// RunJailShim is the child half of the jail: sandboxd re-exec'd as
// `sandboxd --isolate-jail-exec` with the spec in SB_ISOLATE_JAIL_SPEC. It
// runs as root inside the group's cgroup (the parent cloned it there) and,
// in this order, chroots, changes into the run dir, drops every privilege,
// forbids regaining any, installs the seccomp filter, and execs workerd.
// The order matters: chroot needs root; the filter must be in place before
// execve so the dynamic loader already runs under it; and no_new_privs must
// precede seccomp for an unprivileged process (we are root by then anyway,
// but the kernel requires it and it is what makes the filter inescapable).
//
// Every failure is fatal and reported on stderr with a distinct exit code so
// the parent's "workerd exited during startup" has a cause next to it.
func RunJailShim(args []string) error {
	raw := os.Getenv(jailShimSpecEnv)
	if raw == "" {
		return fmt.Errorf("isolate jail shim: %s is not set", jailShimSpecEnv)
	}
	spec, err := decodeJailShimSpec(raw)
	if err != nil {
		return err
	}
	if err := unix.Chroot(spec.Chroot); err != nil {
		return fmt.Errorf("isolate jail shim: chroot %s: %w", spec.Chroot, err)
	}
	if err := unix.Chdir(spec.Cwd); err != nil {
		return fmt.Errorf("isolate jail shim: chdir %s: %w", spec.Cwd, err)
	}
	if err := unix.Setgroups([]int{}); err != nil {
		return fmt.Errorf("isolate jail shim: setgroups: %w", err)
	}
	if err := unix.Setresgid(spec.GID, spec.GID, spec.GID); err != nil {
		return fmt.Errorf("isolate jail shim: setresgid %d: %w", spec.GID, err)
	}
	if err := unix.Setresuid(spec.UID, spec.UID, spec.UID); err != nil {
		return fmt.Errorf("isolate jail shim: setresuid %d: %w", spec.UID, err)
	}
	if unix.Geteuid() != spec.UID || unix.Getegid() != spec.GID {
		return fmt.Errorf("isolate jail shim: privilege drop did not take (euid %d egid %d)", unix.Geteuid(), unix.Getegid())
	}
	// Must fail from here: regaining root after the drop is the escape.
	if err := unix.Setresuid(0, 0, 0); err == nil {
		return fmt.Errorf("isolate jail shim: could regain root after dropping privileges")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("isolate jail shim: no_new_privs: %w", err)
	}
	if len(spec.Seccomp) > 0 {
		if err := installSeccomp(spec.Seccomp); err != nil {
			return err
		}
	}
	env := spec.Env
	if env == nil {
		env = []string{}
	}
	if err := unix.Exec(spec.Argv[0], spec.Argv, env); err != nil {
		return fmt.Errorf("isolate jail shim: exec %s: %w", spec.Argv[0], err)
	}
	return nil // unreachable
}

// installSeccomp loads the classic-BPF program with TSYNC so every thread of
// this (Go, multi-threaded) process is filtered before exec.
func installSeccomp(prog []bpfInsn) error {
	filter := make([]unix.SockFilter, len(prog))
	for i, insn := range prog {
		filter[i] = unix.SockFilter{Code: insn.Code, Jt: insn.Jt, Jf: insn.Jf, K: insn.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return fmt.Errorf("isolate jail shim: seccomp(SET_MODE_FILTER): %w", errno)
	}
	return nil
}
