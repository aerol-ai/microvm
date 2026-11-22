package isolate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// JailLauncher realizes a group's jail and runs its workerd in another
// process: the root helper, in privilege mode split
// (plans/security-gaps-m1-m4.md §3.3, M1 PR 9), where sandboxd has no
// rights. sandboxd keeps the Go side of the host (the bundle server, the
// egress servers, the config) in the group's run folder, which the helper
// makes its own with the jail's group; the helper does the rest of what
// single mode does as root (prepareJailFS, applyJail, the shim) from its
// own settings. A Host with a launcher never touches a chroot, a mount or a
// cgroup itself.
type JailLauncher interface {
	// Prepare makes sure the group's jail exists and answers its run
	// folder on the host.
	Prepare(ctx context.Context, group string) (string, error)
	// Start starts the group's workerd with these limits and holds it.
	Start(ctx context.Context, group string, l Limits) (hostproc.Process, error)
	// SetLimits changes a running group's limits.
	SetLimits(ctx context.Context, group string, l Limits) error
	// Stop makes sure the group's workerd and jail are gone.
	Stop(ctx context.Context, group string) error
	// Open holds a running group's workerd, when it is still the process a
	// record names by pid and start time.
	Open(ctx context.Context, group string, pid int, startTicks uint64) (hostproc.Process, error)
	// Groups lists every group the launcher holds anything for: a running
	// workerd, or a jail or group left behind.
	Groups(ctx context.Context) ([]string, error)
}

// Limits are a group's cgroup limits (JailConfig's CPUQuota, MemoryLimitMB
// and PidsMax). Zero is no limit on that axis.
type Limits struct {
	CPU      float64
	MemoryMB int
	Pids     int
}

// launchedProcess is a launcher's process that knows its start time.
type launchedProcess interface {
	StartTicks() uint64
}

// launcherCallWait bounds a launcher call made where no caller waits on
// it: Stop, a teardown.
var launcherCallWait = time.Minute

// startLaunched is Start for a host whose jail and process the launcher
// realizes: the group's jail first, then the Go side's servers and config
// in its run folder, made readable and dialable by the jail's group, then
// workerd. Any failure leaves nothing behind.
func (h *Host) startLaunched(ctx context.Context) error {
	l, key := h.cfg.Launcher, h.cfg.GroupKey
	run, err := l.Prepare(ctx, key)
	if err != nil {
		return fmt.Errorf("isolate: root helper: prepare group %s: %w", key, err)
	}
	fail := func(err error) error {
		_ = h.stopServers()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), launcherCallWait)
		defer cancel()
		if serr := l.Stop(sctx, key); serr != nil && h.logger != nil {
			h.logger.Warn("isolate: group not removed after a failed start", "group", key, "error", serr)
		}
		return err
	}
	if filepath.Clean(run) != filepath.Clean(h.cfg.RunDir) {
		return fail(fmt.Errorf("isolate: the root helper keeps group %s's run folder at %s, this sandboxd at %s: "+
			"set the same SB_ISOLATE_JAIL_CHROOT_BASE for both", key, run, h.cfg.RunDir))
	}
	for _, s := range append([]string{h.controlSock, h.hostSock, h.egressDenySock}, h.egressSocks...) {
		_ = os.Remove(s)
	}
	if err := h.startBundleServer(); err != nil {
		return fail(err)
	}
	if err := h.startEgressDenyServer(); err != nil {
		return fail(err)
	}
	if err := h.writeConfig(); err != nil {
		return fail(err)
	}
	configPath := filepath.Join(h.cfg.RunDir, "config.capnp")
	if err := h.grantJailAccess(configPath, filepath.Join(h.cfg.RunDir, controllerModuleName), h.hostSock, h.egressDenySock); err != nil {
		return fail(err)
	}
	j := h.cfg.Jail
	proc, err := l.Start(ctx, key, Limits{CPU: j.CPUQuota, MemoryMB: j.MemoryLimitMB, Pids: j.PidsMax})
	if err != nil {
		return fail(fmt.Errorf("isolate: root helper: start group %s: %w", key, err))
	}
	exited := make(chan struct{})
	client := unixHTTPClient(h.controlSock)
	boot, _ := hostBootID()
	h.mu.Lock()
	h.proc = proc
	h.exited = exited
	h.ctrlClient = client
	h.pid, h.bootID = proc.Pid(), boot
	if lp, ok := proc.(launchedProcess); ok {
		h.startTicks = lp.StartTicks()
	}
	h.mu.Unlock()
	go func() {
		<-proc.Done()
		close(exited)
	}()
	if err := h.waitReady(ctx, exited, client); err != nil {
		_ = h.Stop()
		return err
	}
	h.started.Store(true)
	h.writeRecord()
	return nil
}

// stopLaunched has the launcher stop a group's workerd and remove its jail.
// The launcher waits for the exit itself, so a helper that cannot be
// reached fails the stop instead of hanging it on an exit that never comes.
func (h *Host) stopLaunched(proc hostproc.Process) error {
	ctx, cancel := context.WithTimeout(context.Background(), launcherCallWait)
	defer cancel()
	err := h.cfg.Launcher.Stop(ctx, h.cfg.GroupKey)
	if proc != nil {
		_ = proc.Close()
	}
	if err != nil {
		return fmt.Errorf("isolate: root helper: stop group %s: %w", h.cfg.GroupKey, err)
	}
	return nil
}

// shareWithJail is grantJailAccess when the agent is not root: the run
// folder is the agent's and the jail group's (the launcher made it so,
// mode 2770), so what the agent makes in it is the jail group's already.
// The group may read the config and dial the sockets; the folder itself is
// left as the launcher made it.
func (h *Host) shareWithJail(paths ...string) error {
	for _, p := range paths {
		if p == "" || filepath.Clean(p) == filepath.Clean(h.cfg.RunDir) {
			continue
		}
		st, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("isolate: jail access %s: %w", p, err)
		}
		mode := os.FileMode(0o640)
		switch {
		case st.Mode()&os.ModeSocket != 0:
			mode = 0o660
		case !st.Mode().IsRegular():
			continue
		}
		if err := os.Chmod(p, mode); err != nil {
			return fmt.Errorf("isolate: jail access %s: %w", p, err)
		}
	}
	return nil
}
