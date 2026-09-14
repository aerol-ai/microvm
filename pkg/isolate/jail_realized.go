package isolate

import (
	"errors"
	"syscall"
)

// jailRealized is what applyJail set up for one group process and what Stop
// must undo once the process is gone.
type jailRealized struct {
	chrootBase string
	chrootDir  string
	cgroup     cgroupFS
	cgroupDir  string
	cgroupFD   int
	// unknownSyscalls are allowlist names this architecture lacks; logged
	// once at spawn so a typo is visible.
	unknownSyscalls []string
	// noexecMounts are tmpfs mounts on the group's writable dirs (tmp, run).
	// Unmount before removing the chroot.
	noexecMounts []string
}

// closeFD releases the cgroup descriptor the child was cloned into. Call
// after Start; the kernel holds its own reference from then on.
func (r *jailRealized) closeFD() {
	if r == nil || r.cgroupFD <= 0 {
		return
	}
	_ = syscall.Close(r.cgroupFD)
	r.cgroupFD = 0
}

// teardown removes the cgroup and the group's chroot. The cgroup removal
// fails while the process is alive, so callers wait for it first.
func (r *jailRealized) teardown() error {
	if r == nil {
		return nil
	}
	r.closeFD()
	var errs []error
	unmountNoexecMounts(r.noexecMounts)
	r.noexecMounts = nil
	if r.cgroupDir != "" {
		if err := r.cgroup.remove(r.cgroupDir); err != nil {
			errs = append(errs, err)
		}
	}
	if r.chrootDir != "" {
		if err := removeGroupJail(r.chrootBase, r.chrootDir); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// applyCaps changes the running group's cgroup caps (a warm blank host
// claimed by a tenant takes that tenant's caps).
func (r *jailRealized) applyCaps(cpu float64, memMB int) error {
	if r == nil || r.cgroupDir == "" {
		return nil
	}
	return r.cgroup.applyCaps(r.cgroupDir, cpu, memMB)
}
