// Package mounts owns the host-side lifecycle of per-sandbox external-storage
// mounts. Mount tools (mountpoint-s3, sshfs, mount.nfs, rclone) run on the
// host in a sandboxd-owned directory tree at /var/lib/sandboxd/mounts/<id>/<i>/
// and are bind-mounted into the target container. Cross-tenant isolation is
// enforced by the kernel's mount namespace: containers cannot see other
// containers' bind sources.
package mounts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// Config controls the manager's filesystem layout and timeouts.
type Config struct {
	RootDir     string        // /var/lib/sandboxd/mounts
	CredDir     string        // /run/sandboxd
	WaitTimeout time.Duration // how long to wait for a mount to become ready
}

// Manager owns mount processes for every active sandbox.
type Manager struct {
	logger      *slog.Logger
	rootDir     string
	credDir     string
	waitTimeout time.Duration
	adapters    map[models.MountType]adapters.Adapter

	// mu guards state, mounting and sweeping, which together say who owns
	// rootDir/<id>; see claimOrphan for the rule.
	mu       sync.Mutex
	state    map[string][]*mountState // sandboxID -> per-index states
	mounting map[string]int           // sandboxID -> MountAll calls in flight
	sweeping map[string]chan struct{} // sandboxID -> closed when Sweep is done with it

	closeCh chan struct{}
}

type mountState struct {
	sandboxID  string
	index      int
	spec       models.MountSpec
	hostPath   string
	plan       adapters.Plan
	cmd        *exec.Cmd
	output     *capturedOutput // captured stdout+stderr of the FUSE mount tool
	exit       *procExit       // cmd's exit; superviseExit waits on it
	startedAt  time.Time
	restarts   int
	lastCrash  time.Time
	supervised bool
	disabled   bool // true after we've given up restarting
}

// New constructs a Manager. The root and cred directories are created with
// mode 0700 if they don't already exist. Returns an error if either path is
// not absolute.
func New(logger *slog.Logger, cfg Config) (*Manager, error) {
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	if !filepath.IsAbs(cfg.RootDir) {
		return nil, fmt.Errorf("mounts root must be absolute: %q", cfg.RootDir)
	}
	if !filepath.IsAbs(cfg.CredDir) {
		return nil, fmt.Errorf("credentials dir must be absolute: %q", cfg.CredDir)
	}
	if cfg.WaitTimeout <= 0 {
		cfg.WaitTimeout = 30 * time.Second
	}
	if err := os.MkdirAll(cfg.RootDir, 0o700); err != nil {
		return nil, fmt.Errorf("create mounts root: %w", err)
	}
	if err := os.MkdirAll(cfg.CredDir, 0o700); err != nil {
		return nil, fmt.Errorf("create credentials dir: %w", err)
	}

	return &Manager{
		logger:      logger,
		rootDir:     cfg.RootDir,
		credDir:     cfg.CredDir,
		waitTimeout: cfg.WaitTimeout,
		adapters:    adapters.Adapters(),
		state:       make(map[string][]*mountState),
		mounting:    make(map[string]int),
		sweeping:    make(map[string]chan struct{}),
		closeCh:     make(chan struct{}),
	}, nil
}

// Close stops the supervisor. Existing mounts are left in place so an
// orderly sandboxd restart can re-establish them.
func (m *Manager) Close() {
	select {
	case <-m.closeCh:
	default:
		close(m.closeCh)
	}
}

// MountAll mounts every spec for a sandbox. On any failure already-mounted
// entries are torn down before returning.
func (m *Manager) MountAll(ctx context.Context, sandboxID string, mounts []models.MountSpec) ([]ContainerBind, error) {
	if len(mounts) == 0 {
		return nil, nil
	}
	// sandboxID is a path component for every host dir and bind below. Validate
	// it here as well as at the create entry: the mount manager must be
	// self-protecting so a '..' id can never escape rootDir (host-dir creation,
	// bind source, or the rollback RemoveAll).
	if err := models.ValidateSandboxID(sandboxID); err != nil {
		return nil, fmt.Errorf("mount: %w", err)
	}
	// Own rootDir/<id> before creating it, and until state holds the mounts
	// (the deferred release runs after the store below), so Sweep never sees
	// this directory unowned.
	release, err := m.beginMount(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("mount: %w", err)
	}
	defer release()
	if err := os.MkdirAll(filepath.Join(m.rootDir, sandboxID), 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox mount dir: %w", err)
	}

	binds := make([]ContainerBind, 0, len(mounts))
	established := make([]*mountState, 0, len(mounts))

	for i, spec := range mounts {
		state, bind, err := m.mountOne(ctx, sandboxID, i, spec)
		if err != nil {
			// Roll back everything we just established for this sandbox.
			for _, s := range established {
				_ = m.tearDownState(s)
			}
			_ = os.RemoveAll(filepath.Join(m.rootDir, sandboxID))
			return nil, fmt.Errorf("mount %d (%s): %w", i, spec.Type, err)
		}
		established = append(established, state)
		binds = append(binds, bind)
	}

	m.mu.Lock()
	m.state[sandboxID] = established
	m.mu.Unlock()
	return binds, nil
}

// UnmountAll tears down every mount for a sandbox. Always best-effort.
func (m *Manager) UnmountAll(sandboxID string) error {
	m.mu.Lock()
	states := m.state[sandboxID]
	delete(m.state, sandboxID)
	m.mu.Unlock()

	var firstErr error
	for _, s := range states {
		if err := m.tearDownState(s); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := os.RemoveAll(filepath.Join(m.rootDir, sandboxID)); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// HostBindsFor returns the binds the docker client should add to the create
// request for a sandbox whose mounts are already established.
func (m *Manager) HostBindsFor(sandboxID string) []ContainerBind {
	m.mu.Lock()
	defer m.mu.Unlock()
	states := m.state[sandboxID]
	binds := make([]ContainerBind, 0, len(states))
	for _, s := range states {
		binds = append(binds, ContainerBind{
			HostPath:      s.hostPath,
			ContainerPath: s.spec.Target,
			ReadOnly:      s.spec.ReadOnly,
		})
	}
	return binds
}

// Sweep removes per-sandbox mount directories under RootDir that are not in
// keep. For each orphan it best-effort:
//   - finds any FUSE process whose argv mentions the orphan path and SIGKILLs it
//   - umount(s) every mountpoint under the orphan dir, lazily if needed
//   - removes the orphan directory tree
//
// Called at the end of every reconcile pass (at startup and on the periodic
// ticker), after the reconciler has computed the set of sandboxes that should
// still exist. A crash mid-MountAll can leave a FUSE process attached to a
// directory whose sandbox row is gone or whose container never came up;
// without this sweep those mounts pile up forever. Directories the manager
// owns in-process (tracked, or with a MountAll in flight) are never swept.
func (m *Manager) Sweep(keep map[string]struct{}) {
	entries, err := os.ReadDir(m.rootDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			m.logger.Warn("mounts sweep: read root failed", "root", m.rootDir, "error", err)
		}
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if _, ok := keep[id]; ok {
			continue
		}
		done, mountInFlight := m.claimOrphan(id)
		if done == nil {
			if mountInFlight {
				m.logger.Info("mounts sweep: skipping, mount in progress", "sandbox_id", id)
			}
			continue
		}
		path := filepath.Join(m.rootDir, id)
		m.logger.Info("mounts sweep: removing orphan", "sandbox_id", id, "path", path)
		m.cleanupOrphanDir(path)
		m.releaseOrphan(id, done)
	}
}

// claimOrphan claims rootDir/<id> for Sweep to remove. It returns nil when
// someone else owns the directory; mountInFlight then says whether that owner
// is a MountAll still running.
//
// Ownership rule: rootDir/<id>, and every mount tool whose argv names a path
// in it, belongs to exactly one of
//   - the MountAll calls in flight for id (mounting), from before the first
//     one creates the directory until the last one returns;
//   - the tracked mounts (state), from MountAll's success until UnmountAll;
//   - a Sweep that claimed id (sweeping), until the directory is gone.
//
// Each is checked and taken under mu, and Sweep claims one id right before
// cleaning it, not from a snapshot taken earlier. So a sweep that finds a
// mount in flight skips it, and a mount that finds a sweep in progress waits
// for it (beginMount) instead of building a directory the sweep then deletes.
// Before this, the claim was a tracked-only snapshot and state was written
// only once every mount was ready, so the periodic reconcile sweep took a
// mount still waiting for mount-s3 for an orphan: it SIGKILLed the tool,
// removed the directory, and the create waited out the full 30s mount
// timeout (UC-84).
func (m *Manager) claimOrphan(id string) (done chan struct{}, mountInFlight bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mounting[id] > 0 {
		return nil, true
	}
	if _, tracked := m.state[id]; tracked {
		return nil, false
	}
	if _, swept := m.sweeping[id]; swept {
		return nil, false // a concurrent Sweep already has it
	}
	done = make(chan struct{})
	m.sweeping[id] = done
	return done, false
}

// releaseOrphan ends Sweep's claim on id and wakes any MountAll waiting for it.
func (m *Manager) releaseOrphan(id string, done chan struct{}) {
	m.mu.Lock()
	delete(m.sweeping, id)
	m.mu.Unlock()
	close(done)
}

// beginMount marks a MountAll of id as in flight until the returned release
// is called. If Sweep is removing id's directory it waits for that to finish
// first: a create retried with the id of a genuine orphan then mounts into a
// clean directory rather than one the sweep is still deleting. The wait is
// one directory's cleanup, and it ends early if ctx is cancelled.
func (m *Manager) beginMount(ctx context.Context, id string) (release func(), err error) {
	m.mu.Lock()
	for {
		done, swept := m.sweeping[id]
		if !swept {
			break
		}
		m.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		m.mu.Lock()
	}
	m.mounting[id]++
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.mounting[id]--; m.mounting[id] <= 0 {
			delete(m.mounting, id)
		}
	}, nil
}

// cleanupOrphanDir kills FUSE processes attached to anything under dir,
// unmounts every leaf, and removes the tree. Best-effort; logs failures.
func (m *Manager) cleanupOrphanDir(dir string) {
	killFUSEProcessesFor(m.logger, dir)
	unmountTree(m.logger, dir)
	if err := os.RemoveAll(dir); err != nil {
		m.logger.Warn("mounts sweep: remove failed", "path", dir, "error", err)
	}
}

// Reestablish ensures a sandbox's mounts are running, mounting any that are
// missing. Called by the reconciler at startup and periodically. It mounts
// only through MountAll, so its mounts are owned against Sweep the same way.
func (m *Manager) Reestablish(ctx context.Context, sandboxID string, mounts []models.MountSpec) error {
	m.mu.Lock()
	already, present := m.state[sandboxID]
	m.mu.Unlock()
	if present && len(already) == len(mounts) {
		// Already tracked. We trust the supervisor to keep them alive.
		return nil
	}
	// Drop any partial state and re-mount everything cleanly.
	if present {
		_ = m.UnmountAll(sandboxID)
	}
	_, err := m.MountAll(ctx, sandboxID, mounts)
	return err
}

// mountOne performs the per-mount work: resolve adapter, write credentials,
// spawn the process (or run a kernel mount), wait for readiness.
func (m *Manager) mountOne(ctx context.Context, sandboxID string, index int, spec models.MountSpec) (*mountState, ContainerBind, error) {
	adapter, ok := m.adapters[spec.Type]
	if !ok {
		return nil, ContainerBind{}, fmt.Errorf("no adapter for type %q", spec.Type)
	}

	hostPath := filepath.Join(m.rootDir, sandboxID, fmt.Sprintf("%d", index))
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		return nil, ContainerBind{}, fmt.Errorf("create host path: %w", err)
	}

	plan, err := adapter.Build(sandboxID, index, spec, hostPath, m.credDir)
	if err != nil {
		return nil, ContainerBind{}, err
	}

	if plan.CredFile != "" {
		if err := writeCredFile(plan.CredFile, plan.CredBody); err != nil {
			return nil, ContainerBind{}, err
		}
	}

	state := &mountState{
		sandboxID: sandboxID,
		index:     index,
		spec:      spec,
		hostPath:  hostPath,
		plan:      plan,
		startedAt: time.Now().UTC(),
	}

	if plan.IsKernelMount {
		// Run the mount command synchronously and wait for it to exit. A
		// non-zero exit means mount failed.
		cmd := exec.CommandContext(ctx, plan.Argv[0], plan.Argv[1:]...)
		if len(plan.Env) > 0 {
			cmd.Env = append(os.Environ(), plan.Env...)
		}
		out, runErr := cmd.CombinedOutput()
		if runErr != nil {
			m.cleanupCred(plan)
			return nil, ContainerBind{}, fmt.Errorf("kernel mount failed: %w (%s)", runErr, string(out))
		}
		// Done; nothing to supervise.
		bind := ContainerBind{HostPath: hostPath, ContainerPath: spec.Target, ReadOnly: spec.ReadOnly}
		return state, bind, nil
	}

	// User-space FUSE: spawn and supervise. stdout+stderr are captured so a
	// mount that never becomes ready surfaces the tool's own error instead of a
	// bare "timed out waiting for mount" (cluster-hetero UC-81..84).
	cmd, out, exit, err := spawnMountProcess(plan)
	if err != nil {
		m.cleanupCred(plan)
		return nil, ContainerBind{}, fmt.Errorf("spawn mount tool: %w", err)
	}
	state.cmd = cmd
	state.output = out
	state.exit = exit

	if err := waitForMountProbe(hostPath, m.waitTimeout, exit.done); err != nil {
		err = mountWaitError(err, exit, out) // before killMount, so the exit status is the tool's own
		_ = killMount(cmd)
		m.cleanupCred(plan)
		return nil, ContainerBind{}, err
	}

	if plan.UnlinkCred && plan.CredFile != "" {
		_ = os.Remove(plan.CredFile)
	}

	state.supervised = true
	go m.superviseExit(state)

	bind := ContainerBind{HostPath: hostPath, ContainerPath: spec.Target, ReadOnly: spec.ReadOnly}
	return state, bind, nil
}

// superviseExit waits for the mount process to exit and either restarts it
// once or marks the mount disabled if it crashes a second time within 30s.
func (m *Manager) superviseExit(state *mountState) {
	if state.exit == nil {
		return // no process to supervise
	}
	<-state.exit.done
	err := state.exit.err

	m.mu.Lock()
	defer m.mu.Unlock()

	// Was this mount removed (UnmountAll)?
	current := m.state[state.sandboxID]
	stillTracked := false
	for _, s := range current {
		if s == state {
			stillTracked = true
			break
		}
	}
	if !stillTracked {
		return
	}
	if state.disabled {
		return
	}

	now := time.Now().UTC()
	withinWindow := !state.lastCrash.IsZero() && now.Sub(state.lastCrash) < 30*time.Second
	state.restarts++
	state.lastCrash = now

	m.logger.Warn("mount process exited",
		"sandbox_id", state.sandboxID,
		"index", state.index,
		"type", string(state.spec.Type),
		"error", err,
		"output", state.output.String(),
		"restarts", state.restarts,
		"within_30s", withinWindow,
	)

	if withinWindow {
		// Two crashes in 30s — give up.
		state.disabled = true
		_ = unmountPath(state.hostPath)
		return
	}

	// Best-effort restart. Re-create cred file if needed.
	if state.plan.CredFile != "" {
		_ = writeCredFile(state.plan.CredFile, state.plan.CredBody)
	}
	cmd, out, exit, err := spawnMountProcess(state.plan)
	if err != nil {
		state.disabled = true
		m.logger.Warn("mount restart spawn failed", "sandbox_id", state.sandboxID, "index", state.index, "error", err)
		return
	}
	state.cmd = cmd
	state.output = out
	state.exit = exit

	go m.superviseExit(state)
}

// tearDownState kills/unmounts a single mount. Always best-effort.
func (m *Manager) tearDownState(s *mountState) error {
	if s.plan.IsKernelMount {
		_ = unmountPath(s.hostPath)
	} else {
		if s.cmd != nil {
			_ = killMount(s.cmd)
		}
		_ = unmountPath(s.hostPath)
	}
	if s.plan.CredFile != "" {
		_ = os.Remove(s.plan.CredFile)
	}
	return nil
}

func (m *Manager) cleanupCred(plan adapters.Plan) {
	if plan.CredFile != "" {
		_ = os.Remove(plan.CredFile)
	}
}

// writeCredFile writes data to path with mode 0600, creating it atomically
// (no other process can read partial contents).
func writeCredFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open cred file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write cred file: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

// waitForMountProbe is the mount-readiness probe mountOne uses. Tests may
// replace it to avoid requiring a real FUSE/kernel mount in unit tests.
var waitForMountProbe = waitForMount

// errMountToolExited and errMountPathRemoved end the readiness wait early.
// Every FUSE tool here runs in the foreground (mount-s3 --foreground,
// sshfs -f, rclone mount), so a tool that has exited is not mounting anything,
// and a mount path that is gone cannot become a mount. Waiting out the timeout
// on either only hides the cause behind "timed out" (UC-84 waited 30s for a
// tool the sweep had already killed).
var (
	errMountToolExited  = errors.New("mount tool exited before the mount was ready")
	errMountPathRemoved = errors.New("mount path was removed while waiting for the mount")
)

// waitForMount polls until the host path appears mounted (its underlying
// device differs from the parent dir's). It fails fast once exited is closed
// (the mount tool is gone) or the path no longer exists, and times out after
// timeout for a tool that is alive but slow. A nil exited never fires.
func waitForMount(hostPath string, timeout time.Duration, exited <-chan struct{}) error {
	parent := filepath.Dir(hostPath)
	parentStat, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("stat parent: %w", err)
	}
	parentSys, _ := parentStat.Sys().(*syscall.Stat_t)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	poll := time.NewTicker(200 * time.Millisecond)
	defer poll.Stop()
	for {
		st, err := os.Stat(hostPath)
		switch {
		case err == nil:
			sys, _ := st.Sys().(*syscall.Stat_t)
			if parentSys != nil && sys != nil && sys.Dev != parentSys.Dev {
				return nil
			}
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%w: %s", errMountPathRemoved, hostPath)
		}
		select {
		case <-exited:
			return fmt.Errorf("%w at %s", errMountToolExited, hostPath)
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for mount at %s", hostPath)
		case <-poll.C:
		}
	}
}

// killMount sends SIGTERM to the process group, waits briefly, then SIGKILL.
func killMount(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		pgid = cmd.Process.Pid
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
	}
	return nil
}

// unmountPath calls /bin/umount, then a lazy umount as a fallback. Best-effort.
func unmountPath(path string) error {
	if err := runUmount(path); err == nil {
		return nil
	}
	return runLazyUmount(path)
}

var (
	runUmount     = func(path string) error { return exec.Command("umount", path).Run() }
	runLazyUmount = func(path string) error { return exec.Command("umount", "-l", path).Run() }
)
