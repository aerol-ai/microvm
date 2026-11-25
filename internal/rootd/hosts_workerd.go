package rootd

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/isolate"
)

// workerdHosts are the V8-isolate group hosts (kind workerd): workerd in
// the jail single mode builds (pkg/isolate RootJail), from the helper's own
// settings. The agent names the group; the helper links its chroot from
// its own base tree, mounts its two writable folders (the run folder the
// agent's, with the jail's group), starts the shim (the helper's own
// binary) in the group's cgroup with the group's limits, and the shim
// chroots, drops to the jail user and installs the helper's filter before
// it runs workerd.
type workerdHosts struct {
	jail isolate.RootJail
	// pidsMax bounds every group's pids: a group whose limit is unset, or
	// set higher, gets this one. The filter lets workerd make threads, and
	// a group with no pids limit could use up the node's.
	pidsMax uint32
	logPath string

	baseMu sync.Mutex
	based  bool
	// prepareBase and checkBase stand in for the kernel in tests.
	prepareBase func() error
	checkBase   func(string) error

	// maxJails bounds the jails at once: a broken agent could otherwise
	// name new groups without end, each two mounts in the node's table.
	// making holds the groups whose jail is being made, which their
	// folder may not show yet; jailsMu orders the count with them.
	maxJails int
	jailsMu  sync.Mutex
	making   map[string]bool
	// groups lists the jails there are (the jail's Groups); tests stand
	// one in.
	groups func() ([]string, error)
}

func newWorkerdHosts(c *WorkerdHostsConfig, logPath string) *workerdHosts {
	w := &workerdHosts{jail: c.Jail, pidsMax: c.PidsMax, logPath: logPath, maxJails: c.MaxJails, making: map[string]bool{}}
	w.groups = w.jail.Groups
	w.prepareBase = w.jail.PrepareBase
	w.checkBase = func(dir string) error {
		fd, err := openFolder(dir)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}
	return w
}

// ensureBase checks the chroot base is the helper's alone and builds the
// shared tree, once per helper: a new helper picks up a new workerd.
func (w *workerdHosts) ensureBase() error {
	w.baseMu.Lock()
	defer w.baseMu.Unlock()
	if w.based {
		return nil
	}
	if err := w.checkBase(w.jail.ChrootBase); err != nil {
		return fmt.Errorf("root helper: V8 jail chroot base %s: %w", w.jail.ChrootBase, err)
	}
	if err := w.prepareBase(); err != nil {
		return fmt.Errorf("root helper: V8 jail base tree: %w", err)
	}
	w.based = true
	return nil
}

func (w *workerdHosts) prepare(id string, running bool, _ *rootdpb.PrepareHostRequest) (*rootdpb.PrepareHostResponse, error) {
	if running {
		// A group that still runs keeps its jail; one whose jail is not
		// whole is not torn down under it.
		if !w.jail.Prepared(id) {
			return nil, &fileError{code: codes.FailedPrecondition,
				msg: fmt.Sprintf("root helper: V8 group %s runs but its jail is not whole; stop it first", id)}
		}
		return &rootdpb.PrepareHostResponse{RunDir: w.jail.RunDir(id)}, nil
	}
	if err := w.ensureBase(); err != nil {
		return nil, err
	}
	done, err := w.reserveJail(id)
	if err != nil {
		return nil, err
	}
	defer done()
	// A jail whose workerd is gone is made again, never reused: its run
	// folder may hold what that workerd left there.
	if err := w.jail.Teardown(id); err != nil {
		return nil, err
	}
	run, err := w.jail.Prepare(id)
	if err != nil {
		return nil, err
	}
	return &rootdpb.PrepareHostResponse{RunDir: run}, nil
}

// reserveJail makes room for id's jail under maxJails, counting every
// other jail there is or is being made: those of running groups, the warm
// pool's, and any a stopped group left. id's own jail, if there is one,
// is made again in its place and adds none. A full node is refused
// ResourceExhausted with no refusal reason: a limit, not a broken
// request, so the agent answers its caller to retry (or place the sandbox
// elsewhere) once a group stops. done ends the reservation once the jail
// is on disk, or is not.
func (w *workerdHosts) reserveJail(id string) (done func(), err error) {
	w.jailsMu.Lock()
	defer w.jailsMu.Unlock()
	have, err := w.groups()
	if err != nil {
		return nil, fmt.Errorf("root helper: list the V8 jails: %w", err)
	}
	others := map[string]bool{}
	for _, g := range have {
		others[g] = true
	}
	for g := range w.making {
		others[g] = true
	}
	delete(others, id)
	if len(others) >= w.maxJails {
		return nil, &fileError{code: codes.ResourceExhausted, msg: fmt.Sprintf(
			"root helper: this node keeps %d V8 jails, its limit (SB_ROOTD_ISOLATE_MAX_JAILS=%d); one is freed when a V8 group stops",
			len(others), w.maxJails)}
	}
	w.making[id] = true
	return func() {
		w.jailsMu.Lock()
		delete(w.making, id)
		w.jailsMu.Unlock()
	}, nil
}

func (w *workerdHosts) command(_ context.Context, id string, _ *rootdpb.SpawnHostRequest) (*exec.Cmd, func(), error) {
	if !w.jail.Prepared(id) {
		return nil, nil, &fileError{code: codes.FailedPrecondition,
			msg: fmt.Sprintf("root helper: V8 group %s has no jail; PrepareHost first", id)}
	}
	cmd, err := w.jail.Command(id)
	if err != nil {
		return nil, nil, err
	}
	out, err := hostLog(w.logPath)
	if err != nil {
		return nil, nil, fmt.Errorf("root helper: hosts' log %s: %w", w.logPath, err)
	}
	cmd.Stdout, cmd.Stderr = out, out
	return cmd, func() { _ = out.Close() }, nil
}

func (w *workerdHosts) socket(string) string { return "" }

func (w *workerdHosts) limits(l rootpolicy.HostLimits) (rootpolicy.HostLimits, bool) {
	if l.Pids == 0 || l.Pids > w.pidsMax {
		l.Pids = w.pidsMax
	}
	return l, true
}

// started: the agent waits for workerd itself, on its control socket.
func (w *workerdHosts) started(context.Context, *exec.Cmd) error { return nil }

func (w *workerdHosts) teardown(id string) error { return w.jail.Teardown(id) }

func (w *workerdHosts) present() ([]string, error) { return w.jail.Groups() }
