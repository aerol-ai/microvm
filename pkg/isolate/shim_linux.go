//go:build linux

package isolate

import (
	"fmt"
	"os"

	"github.com/aerol-ai/microvm/pkg/hostproc"
	"golang.org/x/sys/unix"
)

// RunJailShim is the child half of the jail: sandboxd re-exec'd as
// `sandboxd --isolate-jail-exec` with the spec in SB_ISOLATE_JAIL_SPEC. It
// runs as root inside the group's cgroup (the parent cloned it there) and,
// in this order, chroots, changes into the run dir, drops every privilege
// and forbids regaining any (hostproc.DropPrivileges, shared with the WASM
// workers), installs the seccomp filter, and execs workerd.
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
	if spec.Umask != nil {
		unix.Umask(int(*spec.Umask))
	}
	if err := hostproc.DropPrivileges(spec.UID, spec.GID); err != nil {
		return fmt.Errorf("isolate jail shim: %w", err)
	}
	if len(spec.Seccomp) > 0 {
		if err := hostproc.InstallSeccomp(spec.Seccomp); err != nil {
			return fmt.Errorf("isolate jail shim: %w", err)
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
