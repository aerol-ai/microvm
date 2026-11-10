//go:build linux

package isolate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// The jail is realized in two steps, because the run dir is shared between
// the jail and the Go side of the host:
//
//   - prepareJailFS builds the group's file system: it links the chroot
//     from the prepared base (workerd + libs + /dev) and mounts a noexec
//     tmpfs on the two writable dirs, tmp and run. It must run before the
//     host writes its config, its controller and its sockets into run: a
//     tmpfs mounted after them hides them, and workerd then finds no
//     config and exits at once (T14: "workerd control socket not ready
//     within 10s" on every jailed spawn).
//   - applyJail does what needs the process: it creates the group's cgroup
//     with its caps and arranges for the child to be born inside it
//     (UseCgroupFD), resolves the seccomp allowlist into a filter, and
//     rewrites cmd to exec the daemon binary in shim mode with the spec in
//     its environment. The shim (shim_linux.go) does what must happen in
//     the child between fork and exec (chroot, chdir, drop to uid/gid,
//     no_new_privs, install the filter) and execs workerd in the chroot.
//
// The returned realized describes what was applied so Stop can tear it down.

// prepareJailFS checks the spec and builds the group's file system.
func prepareJailFS(j JailConfig) (*jailRealized, error) {
	if !runningAsRoot() {
		return nil, errNotRoot
	}
	if j.UID <= 0 || j.GID <= 0 {
		return nil, fmt.Errorf("isolate jail: refusing to run workerd privileged (uid/gid must be > 0, got %d/%d)", j.UID, j.GID)
	}
	if j.ChrootDir == "" || !filepath.IsAbs(j.ChrootDir) {
		return nil, fmt.Errorf("isolate jail: chroot dir %q must be absolute", j.ChrootDir)
	}
	if j.ShimPath == "" || !filepath.IsAbs(j.ShimPath) {
		return nil, fmt.Errorf("isolate jail: shim path %q must be absolute (the daemon binary)", j.ShimPath)
	}
	if _, err := os.Stat(j.ShimPath); err != nil {
		return nil, fmt.Errorf("isolate jail: shim binary: %w", err)
	}
	chrootBase := filepath.Dir(j.ChrootDir)
	if err := linkGroupJail(chrootBase, j.ChrootDir, j.UID, j.GID); err != nil {
		return nil, err
	}
	realized := &jailRealized{chrootBase: chrootBase, chrootDir: j.ChrootDir}
	for _, dir := range []string{filepath.Join(j.ChrootDir, "tmp"), filepath.Join(j.ChrootDir, JailRunDirName)} {
		if err := mountNoexecTmpfs(dir, j.UID, j.GID); err != nil {
			_ = realized.teardown()
			return nil, err
		}
		realized.noexecMounts = append(realized.noexecMounts, dir)
	}
	return realized, nil
}

// applyJail realizes the process half of j for the workerd process cmd
// describes, before Start. realized is what prepareJailFS returned.
func applyJail(cmd *exec.Cmd, j JailConfig, workerdArgs []string, realized *jailRealized) error {
	if realized == nil {
		return fmt.Errorf("isolate jail: file system not prepared")
	}
	cg := cgroupFS{root: j.CgroupRoot}
	if cg.root == "" {
		cg.root = DefaultCgroupRoot
	}
	cgDir, err := cg.ensure(j.CgroupName, j.CPUQuota, j.MemoryLimitMB, j.PidsMax)
	if err != nil {
		return err
	}
	realized.cgroup, realized.cgroupDir = cg, cgDir
	cgFD, err := syscall.Open(cgDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("isolate jail: open cgroup %s: %w", cgDir, err)
	}
	realized.cgroupFD = cgFD

	var prog []bpfInsn
	if j.SeccompMode != SeccompOff {
		prog, realized.unknownSyscalls, err = buildSeccompProgram(seccompAuditArch(), seccompSyscallTable(), j.SeccompAllow, j.SeccompArgRules, j.SeccompMode)
		if err != nil {
			return err
		}
	}
	spec := jailShimSpec{
		Chroot:  j.ChrootDir,
		Cwd:     "/" + JailRunDirName,
		UID:     j.UID,
		GID:     j.GID,
		Argv:    append([]string{JailWorkerdPath}, workerdArgs...),
		Env:     []string{"HOME=/" + JailRunDirName, "TMPDIR=/tmp"},
		Seccomp: prog,
	}
	encoded, err := encodeJailShimSpec(spec)
	if err != nil {
		return err
	}
	cmd.Path = j.ShimPath
	cmd.Args = []string{j.ShimPath, JailShimFlag}
	cmd.Env = []string{jailShimSpecEnv + "=" + encoded}
	cmd.Dir = "" // the shim chdirs inside the chroot; a host path here would be wrong
	attr := cmd.SysProcAttr
	if attr == nil {
		attr = &syscall.SysProcAttr{}
	}
	attr.Setpgid = true
	attr.UseCgroupFD = true
	attr.CgroupFD = cgFD
	attr.Cloneflags = jailCloneflags()
	cmd.SysProcAttr = attr
	return nil
}

// jailCloneflags gives each group its own PID namespace. Isolate groups
// share the jail uid; without this, kill/tkill/tgkill (or kill -1) from one
// tenant's workerd can signal every other tenant's. Inside the namespace
// those calls can only address this process.
func jailCloneflags() uintptr { return syscall.CLONE_NEWPID }

// jailRealizable reports whether this host can realize the jail. Linux is
// not enough: applyJail needs root (chroot, cgroup, mknod, setuid). A
// non-root daemon that reported realizable=true would boot green and then
// fail every isolate create.
func jailRealizable() bool { return runningAsRoot() }
