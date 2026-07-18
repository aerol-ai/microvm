//go:build linux

package isolate

import (
	"fmt"
	"os/exec"
	"syscall"
)

// applyJail confines cmd per j before exec (Linux realization of the driver's
// JailSpec). What is applied here:
//
//   - Privilege drop: the workerd process runs as the unprivileged j.UID/j.GID
//     (NoSetGroups drops supplementary groups too), so a V8/JIT escape lands as
//     a non-root user, not the daemon's root.
//   - Chroot: when j.ChrootDir is set, the process is confined to it. The
//     directory must already be POPULATED (workerd + its shared libs + the run
//     dir mounted in) — that population is the jailer step tracked as a
//     follow-up; until it exists, leave ChrootDir empty and the process runs
//     un-chrooted but still privilege-dropped.
//
// NOT yet applied here (tracked follow-ups, gated behind Require so the runtime
// fails closed rather than over-promising):
//
//   - seccomp: the SeccompAllowlist must be installed as a BPF filter via a
//     PR_SET_NO_NEW_PRIVS + seccomp(2) pre-exec hook, which Go's os/exec cannot
//     express without CGO or a re-exec shim. This is the JIT-aware allowlist the
//     plan budgets as its own subproject.
//   - cgroup: j.CgroupName / j.MemoryLimitMB should back the process with a
//     cgroup v2 limit (SysProcAttr.UseCgroupFD).
//
// IMPORTANT: this path executes only on Linux hosts and has NOT been exercised
// in offline CI (macOS dev/build). It must be validated by the tagged real-host
// integration test before the jail is trusted for untrusted multi-tenant code.
func applyJail(cmd *exec.Cmd, j JailConfig) error {
	if j.UID <= 0 || j.GID <= 0 {
		return fmt.Errorf("isolate jail: refusing to run workerd privileged (uid/gid must be > 0, got %d/%d)", j.UID, j.GID)
	}
	attr := cmd.SysProcAttr
	if attr == nil {
		attr = &syscall.SysProcAttr{}
	}
	attr.Credential = &syscall.Credential{
		Uid:         uint32(j.UID),
		Gid:         uint32(j.GID),
		NoSetGroups: true,
	}
	attr.Setpgid = true
	if j.ChrootDir != "" {
		attr.Chroot = j.ChrootDir
	}
	cmd.SysProcAttr = attr
	return nil
}

// jailRealizable reports whether this platform can realize the jail at all.
// Linux can (privilege drop + chroot today; seccomp + cgroup are follow-ups).
func jailRealizable() bool { return true }
