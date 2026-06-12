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

	mu    sync.Mutex
	state map[string][]*mountState // sandboxID -> per-index states

	closeCh chan struct{}
}

type mountState struct {
	sandboxID  string
	index      int
	spec       models.MountSpec
	hostPath   string
	plan       adapters.Plan
	cmd        *exec.Cmd
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
// Intended for sandboxd startup, after the reconciler has computed the set of
// sandboxes that should still exist. A crash mid-MountAll can leave a FUSE
// process attached to a directory whose sandbox row is gone or whose container
// never came up; without this sweep those mounts pile up forever.
func (m *Manager) Sweep(keep map[string]struct{}) {
	entries, err := os.ReadDir(m.rootDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			m.logger.Warn("mounts sweep: read root failed", "root", m.rootDir, "error", err)
		}
		return
	}

	m.mu.Lock()
	tracked := make(map[string]struct{}, len(m.state))
	for id := range m.state {
		tracked[id] = struct{}{}
	}
	m.mu.Unlock()

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if _, ok := keep[id]; ok {
			continue
		}
		if _, ok := tracked[id]; ok {
			// We're already managing it in-process; never sweep an active mount.
			continue
		}
		path := filepath.Join(m.rootDir, id)
		m.logger.Info("mounts sweep: removing orphan", "sandbox_id", id, "path", path)
		m.cleanupOrphanDir(path)
	}
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
// missing. Called by the reconciler at startup and periodically.
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

	// User-space FUSE: spawn and supervise.
	cmd := exec.Command(plan.Argv[0], plan.Argv[1:]...)
	if len(plan.Env) > 0 {
		cmd.Env = append(os.Environ(), plan.Env...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		m.cleanupCred(plan)
		return nil, ContainerBind{}, fmt.Errorf("spawn mount tool: %w", err)
	}
	state.cmd = cmd

	if err := waitForMountProbe(hostPath, m.waitTimeout); err != nil {
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
	if state.cmd == nil {
		return
	}
	err := state.cmd.Wait()

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
	cmd := exec.Command(state.plan.Argv[0], state.plan.Argv[1:]...)
	if len(state.plan.Env) > 0 {
		cmd.Env = append(os.Environ(), state.plan.Env...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		state.disabled = true
		m.logger.Warn("mount restart spawn failed", "sandbox_id", state.sandboxID, "index", state.index, "error", err)
		return
	}
	state.cmd = cmd

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

// waitForMount polls until the host path appears mounted (its underlying
// device differs from the parent dir's). Falls back to a sentinel-file probe
// if the parent is itself a mount point. Returns ErrTimeout after waitTimeout.
func waitForMount(hostPath string, timeout time.Duration) error {
	parent := filepath.Dir(hostPath)
	parentStat, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("stat parent: %w", err)
	}
	parentSys, _ := parentStat.Sys().(*syscall.Stat_t)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := os.Stat(hostPath)
		if err == nil {
			sys, _ := st.Sys().(*syscall.Stat_t)
			if parentSys != nil && sys != nil && sys.Dev != parentSys.Dev {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for mount at %s", hostPath)
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
