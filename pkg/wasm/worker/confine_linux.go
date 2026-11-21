//go:build linux

package worker

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// confinementSupported: workers can drop here.
const confinementSupported = true

// applyConfinement drops to c and installs the worker's filter.
func applyConfinement(c Confinement) error {
	if hostproc.SeccompArch() == 0 {
		return fmt.Errorf("wasm worker: no seccomp filter for this architecture")
	}
	prog, unknown, err := hostproc.BuildSeccomp(hostproc.SeccompArch(), hostproc.SyscallTable(), workerSeccompPolicy())
	if err != nil {
		return fmt.Errorf("wasm worker: %w", err)
	}
	// One thread for the drop and the load: no_new_privs, which an
	// unprivileged filter load needs, is set on the calling thread
	// (DropPrivileges), and a goroutine that moved threads in between would
	// load from one without it. TSYNC then gives every thread the filter and
	// no_new_privs.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := hostproc.DropPrivileges(c.UID, c.GID); err != nil {
		return fmt.Errorf("wasm worker: %w", err)
	}
	if err := hostproc.InstallSeccomp(prog); err != nil {
		return fmt.Errorf("wasm worker: %w", err)
	}
	if len(unknown) > 0 {
		// Names this architecture lacks (the legacy x86-64 ones on arm64)
		// cannot be called here, so skipping them narrows nothing.
		slog.Debug("wasm worker: seccomp names absent on this architecture", "names", unknown)
	}
	return nil
}

// setOwnPIDNamespace starts the worker as PID 1 of a new PID namespace:
// it can signal nothing outside it, and no other worker can name it.
// sandboxd still holds it by its pid outside (hostproc.Open).
func setOwnPIDNamespace(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWPID
}
