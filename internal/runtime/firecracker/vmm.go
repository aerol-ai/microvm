package firecracker

// vmm.go owns one Firecracker process's lifecycle on the host:
//
//   - layout per-sandbox runtime state under <RunDir>/<sandbox-id>/
//   - spawn the firecracker binary pointed at a per-sandbox API socket
//   - wait for the API socket to bind (the only signal that the VMM is
//     ready to take REST calls)
//   - shut down cleanly: SIGTERM to the process group, fall through to
//     SIGKILL after a grace period
//   - capture a bounded stderr/stdout tail for post-mortem logging
//
// What lives here vs. driver.go: driver.go owns the *runtime.Runtime*
// surface (Create/Start/Destroy/...). vmm.go is one layer below — it knows
// about exec.Cmd, sockets, and signals, but nothing about sandboxes,
// snapshots, models.*, or REST verbs. The driver wires vmm to
// pkg/firecracker.Client (the REST layer), pkg/network/tap (when that
// lands), and the store.
//
// The jailer wrap is intentionally not here yet. Phase 1 spawns
// firecracker directly so the process-management seam is testable on a
// dev box without root. When jailer lands (separate file: jailer.go), it
// will replace v.cfg.FirecrackerBinary with v.cfg.JailerBinary and prepend
// the jailer args; the rest of this file does not change.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// defaultSocketWait is the wall-clock deadline WaitSocket falls back to
// when the caller does not pass one. Firecracker binds its API socket
// well under 100 ms on a healthy host; the generous ceiling here accounts
// for jailer chroot setup (file copies into the jail) which lands in a
// follow-up.
const defaultSocketWait = 5 * time.Second

// stderrTailCap caps how many bytes of the firecracker process's combined
// stdout+stderr we hold in memory for post-mortem reporting. A few KiB
// covers the boot-time fault messages we actually need to surface; past
// that, the on-disk firecracker.log (when configured) is authoritative
// and we don't want to grow unboundedly on a chatty VMM.
const stderrTailCap = 16 << 10 // 16 KiB

// vmm is a single Firecracker process's host-side handle. Unexported on
// purpose: only Driver creates one, and the driver mediates all access.
// Concurrency: Start is not safe to call twice; everything after Start
// (WaitSocket, Pid, Shutdown, Kill, Wait, StderrTail) is goroutine-safe.
type vmm struct {
	sandboxID string
	runDir    string // <Config.RunDir>/<sandbox-id>
	apiSocket string // <runDir>/api.sock
	logPath   string // <runDir>/firecracker.log (passed via PutLogger when set)

	cfg    Config
	logger *slog.Logger

	startMu sync.Mutex
	started bool

	cmd     *exec.Cmd
	stderr  *cappedBuffer
	waitCh  chan struct{} // closed when cmd.Wait returns
	waitErr error         // populated before waitCh closes
}

// newVMM lays out the per-sandbox runtime directory and constructs the
// handle. The directory is created here so the caller can write artifacts
// (jailer chroot stub files, future overlay paths) before Start spawns the
// process. The handle is not started until Start is called.
//
// sandboxID is validated to avoid path-injection into RunDir — a malformed
// ID could otherwise be used to write outside the per-host run directory.
// We restrict to the same character set the rest of the daemon uses for
// sandbox IDs (alphanumeric + dash + underscore).
func newVMM(cfg Config, sandboxID string, logger *slog.Logger) (*vmm, error) {
	if cfg.FirecrackerBinary == "" {
		return nil, errors.New("vmm: FirecrackerBinary not configured")
	}
	// RunDir is only consulted in direct-spawn mode; jailer mode roots
	// the per-sandbox tree under JailerChrootBase instead (see jailer.go).
	// Requiring RunDir unconditionally would force operators on production
	// hosts to set a flag they never read.
	if !cfg.UseJailer && cfg.RunDir == "" {
		return nil, errors.New("vmm: RunDir not configured")
	}
	if err := validateSandboxID(sandboxID); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	runDir := filepath.Join(cfg.RunDir, sandboxID)
	v := &vmm{
		sandboxID: sandboxID,
		runDir:    runDir,
		apiSocket: filepath.Join(runDir, "api.sock"),
		logPath:   filepath.Join(runDir, "firecracker.log"),
		cfg:       cfg,
		logger:    logger,
	}
	if err := v.applyJailerLayout(); err != nil {
		return nil, err
	}
	return v, nil
}

// validateSandboxID enforces the same shape the rest of the daemon uses
// (alphanumeric, dash, underscore). The check exists because sandboxID
// flows into a filesystem path; a malformed value could escape RunDir.
// Mirror the regex used elsewhere with a hand-written loop to avoid the
// regexp import for a check this small.
func validateSandboxID(id string) error {
	if id == "" {
		return errors.New("vmm: sandbox ID is empty")
	}
	if len(id) > 128 {
		return fmt.Errorf("vmm: sandbox ID exceeds 128 chars (%d)", len(id))
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return fmt.Errorf("vmm: invalid character %q in sandbox ID %q", r, id)
		}
	}
	return nil
}

// APISocket returns the host path of this VMM's API socket. Used by the
// driver to construct a *firecracker.Client.
func (v *vmm) APISocket() string { return v.apiSocket }

// RunDir returns the per-sandbox state directory.
func (v *vmm) RunDir() string { return v.runDir }

// Start spawns the firecracker process and returns once exec succeeds
// (it does not wait for the API socket — WaitSocket is the next step).
// Idempotent only in the sense that a second Start returns an error;
// recovery from a failed Start is via Cleanup + a fresh vmm.
func (v *vmm) Start(ctx context.Context) error {
	v.startMu.Lock()
	defer v.startMu.Unlock()
	if v.started {
		return errors.New("vmm: Start called twice")
	}

	if err := os.MkdirAll(v.runDir, 0o755); err != nil {
		return fmt.Errorf("vmm: mkdir %s: %w", v.runDir, err)
	}
	// Firecracker refuses to bind if the socket file already exists. A
	// stale socket from a crash-restart is the common case here; remove
	// best-effort and let the bind error speak if removal failed for any
	// other reason.
	_ = os.Remove(v.apiSocket)

	// Spawn directly or via jailer. The argv shape differs (jailer wraps
	// the firecracker invocation with chroot/cgroup/drop-priv flags) but
	// every later step — WaitSocket, Shutdown, capped stderr — is
	// identical because both spawns land an exec.Cmd we own.
	binary, args := v.cfg.FirecrackerBinary, v.buildArgs()
	if v.cfg.UseJailer {
		binary = v.cfg.JailerBinary
		args = v.jailerArgv()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The VMM outlives the request that created it. Use ctx only as a
	// pre-spawn cancellation check; tying the child to CommandContext
	// would SIGKILL Firecracker as soon as the HTTP create request
	// completes.
	cmd := exec.Command(binary, args...)
	cmd.Dir = v.runDir
	v.stderr = newCappedBuffer(stderrTailCap)
	// Merge stdout + stderr into one capped buffer. Firecracker writes its
	// boot diagnostics to stderr; some operator-visible messages (and the
	// guest kernel's early-init lines, when the kernel is configured to
	// log to the VMM stdio) land on stdout. One buffer is enough for
	// post-mortem context.
	cmd.Stdout = v.stderr
	cmd.Stderr = v.stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("vmm: spawn %s: %w", v.cfg.FirecrackerBinary, err)
	}
	v.cmd = cmd
	v.waitCh = make(chan struct{})
	v.started = true

	go func() {
		v.waitErr = cmd.Wait()
		attrs := []any{
			"sandbox_id", v.sandboxID,
			"pid", cmd.Process.Pid,
			"run_dir", v.runDir,
			"stderr_tail", v.stderr.String(),
		}
		if v.waitErr != nil {
			logger := v.logger
			if logger == nil {
				logger = slog.Default()
			}
			logger.Warn("firecracker vmm process exited", append(attrs, "error", v.waitErr)...)
		} else {
			logger := v.logger
			if logger == nil {
				logger = slog.Default()
			}
			logger.Info("firecracker vmm process exited", attrs...)
		}
		close(v.waitCh)
	}()
	return nil
}

// buildArgs returns the argv for the firecracker process. Kept separate
// so tests can assert the shape without spawning anything, and so the
// jailer wrap (when it lands) can rebuild the argv with the jailer
// prefix without duplicating socket-path logic.
func (v *vmm) buildArgs() []string {
	return []string{"--api-sock", v.apiSocket}
}

// WaitSocket polls for the API socket file to appear, returning as soon as
// it does. If the firecracker process exits before the socket appears,
// WaitSocket returns the captured stderr tail so the caller has something
// to surface to the operator. A zero timeout means defaultSocketWait.
//
// Why poll rather than inotify: the file appears within milliseconds on a
// healthy boot; a 20 ms poll is cheaper than wiring inotify and works the
// same on Linux and macOS for the dev path.
func (v *vmm) WaitSocket(ctx context.Context, timeout time.Duration) error {
	if !v.started {
		return errors.New("vmm: WaitSocket called before Start")
	}
	if timeout <= 0 {
		timeout = defaultSocketWait
	}
	deadline := time.Now().Add(timeout)
	for {
		// Check process exit BEFORE the Stat. Under heavy parallelism
		// (lots of subprocess tests running concurrently) the goroutine
		// that closes waitCh can race the deadline check below; without
		// this non-blocking probe the select could fall through to the
		// 20 ms timer, the deadline could trip on the next iteration,
		// and we'd misreport a clean "process exited" as a timeout.
		select {
		case <-v.waitCh:
			return fmt.Errorf("vmm: firecracker exited before API socket bound: %w (stderr tail: %s)",
				v.waitErr, v.stderr.String())
		default:
		}
		if _, err := os.Stat(v.apiSocket); err == nil {
			return nil
		}
		select {
		case <-v.waitCh:
			return fmt.Errorf("vmm: firecracker exited before API socket bound: %w (stderr tail: %s)",
				v.waitErr, v.stderr.String())
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("vmm: API socket %s did not appear within %s", v.apiSocket, timeout)
		}
	}
}

// Pid returns the firecracker process's PID, or 0 if it has not been
// started or has already exited.
func (v *vmm) Pid() int {
	if v.cmd == nil || v.cmd.Process == nil {
		return 0
	}
	return v.cmd.Process.Pid
}

// Wait blocks until the firecracker process exits and returns its exit
// error (nil for a clean exit). Safe to call from multiple goroutines.
func (v *vmm) Wait() error {
	if !v.started {
		return errors.New("vmm: Wait called before Start")
	}
	<-v.waitCh
	return v.waitErr
}

// Shutdown signals SIGTERM to the firecracker process group, waits up to
// grace for it to exit cleanly, then escalates to SIGKILL. Mirrors
// pkg/mounts.killMount for consistency with the rest of the daemon's
// process supervision. Idempotent: calling Shutdown on an already-exited
// VMM is a no-op.
func (v *vmm) Shutdown(ctx context.Context, grace time.Duration) error {
	if v.cmd == nil || v.cmd.Process == nil {
		return nil
	}
	// Already exited?
	select {
	case <-v.waitCh:
		return nil
	default:
	}

	pgid, err := syscall.Getpgid(v.cmd.Process.Pid)
	if err != nil {
		// Getpgid races with the child's exit on some kernels; fall back
		// to signaling the process directly. We swallow the signal error
		// because the only failure mode is "already exited", which is the
		// outcome we want anyway.
		pgid = v.cmd.Process.Pid
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)

	if grace <= 0 {
		grace = 3 * time.Second
	}
	select {
	case <-v.waitCh:
		return nil
	case <-time.After(grace):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-v.waitCh
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Kill is the no-grace SIGKILL path. Used by the driver's Destroy when the
// caller has already decided the VMM is unrecoverable. Idempotent.
func (v *vmm) Kill() error {
	if v.cmd == nil || v.cmd.Process == nil {
		return nil
	}
	select {
	case <-v.waitCh:
		return nil
	default:
	}
	pgid, err := syscall.Getpgid(v.cmd.Process.Pid)
	if err != nil {
		pgid = v.cmd.Process.Pid
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	<-v.waitCh
	return nil
}

// StderrTail returns the captured stdout+stderr tail. Safe to call at any
// time; before Start it returns the empty string. Useful for log lines
// that surface a "VMM died" condition with the last 16 KiB the process
// emitted.
func (v *vmm) StderrTail() string {
	if v.stderr == nil {
		return ""
	}
	return v.stderr.String()
}

// Cleanup removes the per-sandbox run directory. The driver calls this
// from Destroy after the VMM has exited and the per-sandbox TAP/IP/CID
// have been released. Best-effort: a stale directory does not impact
// correctness, only disk usage.
func (v *vmm) Cleanup() error {
	if v.runDir == "" {
		return nil
	}
	// Defense in depth: validateSandboxID should already prevent path
	// injection, but a bug elsewhere should never cause RemoveAll on a
	// path outside whichever configured root owns this VMM. The owning
	// root depends on jailer mode — direct mode roots at Config.RunDir,
	// jailer mode roots at Config.JailerChrootBase.
	root := v.cfg.RunDir
	if v.cfg.UseJailer {
		root = v.cfg.JailerChrootBase
	}
	if !strings.HasPrefix(v.runDir, root) {
		return fmt.Errorf("vmm: refusing to clean up path outside %q: %s", root, v.runDir)
	}
	return os.RemoveAll(v.runDir)
}

// cappedBuffer is a goroutine-safe io.Writer that retains at most cap
// bytes from the start of the stream (head-keep). Head-keep beats
// tail-keep here: the most useful diagnostic from a Firecracker process
// that fails to boot is the *first* error line, not the last
// (subsequent output is often noise from a flailing kernel). Once full,
// further writes are reported as accepted (so the caller's exec.Cmd does
// not block on a backed-up pipe) but dropped.
type cappedBuffer struct {
	mu    sync.Mutex
	cap   int
	buf   []byte
	dropd int
}

func newCappedBuffer(cap int) *cappedBuffer { return &cappedBuffer{cap: cap} }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) >= b.cap {
		b.dropd += len(p)
		return len(p), nil
	}
	take := len(p)
	if len(b.buf)+take > b.cap {
		take = b.cap - len(b.buf)
		b.dropd += len(p) - take
	}
	b.buf = append(b.buf, p[:take]...)
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dropd == 0 {
		return string(b.buf)
	}
	return fmt.Sprintf("%s\n[... %d more bytes dropped ...]", string(b.buf), b.dropd)
}
