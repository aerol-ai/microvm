package supervisor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/rootfolder"
	"github.com/aerol-ai/microvm/internal/rootswap"
)

// The root helper's swap (plans/security-gaps-m1-m4.md §3.3 "Upgrades",
// eng review D4, outside review O3 and O6). The supervisor stays fixed in
// the runtime image; the helper ships with every release, in the agent's
// image, which stages it in a folder the agent writes. HelperKeeper runs
// it as a child:
//
//	staged ──► copied (root's folder) ──► verified (the copy) ──► old drained ──► new serving
//	                                                                   │               │
//	                                                                   └── new failed ─┴─► old again
//
// Trigger: the staged folder is looked at on a tick. The agent cannot
// signal the supervisor (another container, another user, and after M1 no
// shared process namespace), and the folder is the one channel the plan
// gives it. A set is judged only once it stayed the same for a whole tick,
// so one caught halfway through staging is never judged, and each set is
// judged once, so a refused one is logged once.
//
// Handover: the supervisor owns the listening socket and passes it to each
// helper. To swap, it verifies the new helper while the old one serves,
// then stops the old one (SIGTERM: stop accepting, finish every call in
// flight, end the event subscriptions; the helper's own deadline cuts the
// rest) and waits for it to exit, killing it after KillAfter. The helper's
// exit is not the end of what it started: a CNI plugin, and the IPAM plugin
// that one runs, outlive a helper that crashed or was killed, or that cut
// the call they ran for. So every helper runs in a cgroup of its own
// (HelperGroup), and a helper has stopped only once that group is empty:
// the keeper kills whatever is left in it and waits until the kernel says
// it holds no process. Only then does the new one start, on the same
// socket. The two, and all each started, never run at once, so a late
// call from the old helper cannot undo the new one's work for a sandbox
// (D11's per-sandbox order holds across the swap), and no part of a call
// the agent sends again to the new helper (internal/rootclient retrySafe)
// can run after it. An agent that connects meanwhile waits in the socket's
// backlog; one whose call was cut tries it again. A group that will not
// empty is logged as an error and tried again with a growing wait: no
// helper starts beside what is left.
//
// Rollback: a new helper that exits, or does not say it serves within
// ReadyWait, is stopped and the old copy runs again; that staged helper is
// tried again only after RetryFailed. A helper that dies after it served
// is started again from the same copy, with a growing wait; what it left
// in its group is killed at once. Sandboxes never depend on the helper
// being up: none is its child.
type HelperKeeper struct {
	// StageDir is the agent's staged folder; BinDir is the supervisor's
	// own, for verified copies.
	StageDir, BinDir string
	// Socket and SocketGID make the helpers' socket (rootfolder.Listen),
	// once, before the first helper starts.
	Socket    string
	SocketGID int
	// Keys are the release keys built into the runtime image.
	Keys []ed25519.PublicKey
	// Start runs the helper copy at bin with env, and files as its
	// descriptors 3 and up, in Group's cgroup.
	Start func(bin string, env []string, files []*os.File) (Child, error)
	// Group is the cgroup every helper runs in. No helper starts until it
	// is empty; nil only in tests that have none.
	Group HelperGroup
	// Env is every helper's environment; the handover's names are added.
	Env []string
	Log *slog.Logger

	// Tick paces the look at the staged folder. ReadyWait bounds a new
	// helper's start; KillAfter an old one's drain, past the helper's own
	// deadline. RetryFailed is how long a staged helper that failed to
	// start waits before it is tried again. Restarts after a crash wait
	// MinBackoff, doubling to MaxBackoff, back to MinBackoff after a run
	// of HealthyAfter.
	Tick, ReadyWait, KillAfter, RetryFailed time.Duration
	MinBackoff, MaxBackoff, HealthyAfter    time.Duration

	cur      *rootswap.Installed // the copy that runs, or ran last
	child    Child               // its process; nil while none runs
	started  time.Time
	sock     *os.File    // the listening socket every helper is handed
	sockInfo os.FileInfo // the socket file, removed when the keeper stops
	// Looking at the staged folder: the set seen last, the one judged
	// last, and a staged helper that failed to start and when to try it
	// again. lastErr keeps an error that repeats every tick to one line.
	seen, judged string
	failedSHA    string
	retryAt      time.Time
	lastErr      string
}

// Child is a helper process the supervisor started.
type Child interface {
	// Signal sends sig to the process, and never to one that took its pid
	// after it exited.
	Signal(sig syscall.Signal) error
	// Done is closed once the process has exited: the process alone, not
	// what it started (HelperGroup).
	Done() <-chan struct{}
}

// Helper keeper defaults. The helper drains for up to 5 s on SIGTERM
// (cmd/aerolvm-rootd), so KillAfter leaves it that and as much again.
const (
	helperReadyWait   = 30 * time.Second
	helperKillAfter   = 10 * time.Second
	helperRetryFailed = 5 * time.Minute
)

// helperTick paces the look at the staged folder: a swap begins within
// two ticks of the agent staging a release. Tests shorten it.
var helperTick = 2 * time.Second

func (h *HelperKeeper) defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&h.Tick, helperTick)
	set(&h.ReadyWait, helperReadyWait)
	set(&h.KillAfter, helperKillAfter)
	set(&h.RetryFailed, helperRetryFailed)
	set(&h.MinBackoff, time.Second)
	set(&h.MaxBackoff, 30*time.Second)
	set(&h.HealthyAfter, time.Minute)
}

// Run keeps a verified helper running, and swaps in each newer one the
// agent stages, until ctx ends; then it drains the helper and removes the
// socket.
func (h *HelperKeeper) Run(ctx context.Context) {
	h.defaults()
	// Copies a supervisor before this one left: none of them runs.
	if err := rootswap.Sweep(h.BinDir); err != nil {
		h.Log.Warn("supervisor: could not clear old root helper copies", "dir", h.BinDir, "error", err)
	}
	tick := time.NewTicker(h.Tick)
	defer tick.Stop()
	var restart <-chan time.Time
	backoff := h.MinBackoff
	for {
		if h.cur != nil && h.child == nil && restart == nil {
			restart = time.After(backoff)
			backoff = min(backoff*2, h.MaxBackoff)
		}
		var exited <-chan struct{}
		if h.child != nil {
			exited = h.child.Done()
		}
		select {
		case <-ctx.Done():
			if h.child != nil {
				h.stop(h.child)
			}
			h.closeGroup()
			h.closeSocket()
			return
		case <-exited:
			if time.Since(h.started) >= h.HealthyAfter {
				backoff = h.MinBackoff
			}
			h.Log.Warn("supervisor: the root helper exited; sandboxes keep running; starting it again",
				"version", h.cur.Manifest.Version, "in", backoff)
			h.child = nil
			// What it started may still run, with no helper to answer
			// for it: kill it now, not after the restart's wait.
			h.clear(ctx)
		case <-restart:
			restart = nil
			if h.child == nil {
				h.child = h.startServing(ctx, h.cur)
			}
		case <-tick.C:
			if next := h.look(); next != nil {
				restart = nil
				backoff = h.MinBackoff
				h.swap(ctx, next)
			}
		}
	}
}

// look judges the staged set once it has stayed the same for a tick, and
// installs a verified copy of a helper to run. nil: nothing to do.
func (h *HelperKeeper) look() *rootswap.Installed {
	fp, err := rootswap.Fingerprint(h.StageDir)
	if err != nil {
		h.once("supervisor: cannot read the staged root helper folder", err)
		return nil
	}
	if fp != h.seen {
		h.seen = fp // changed since the last tick: let it settle
		return nil
	}
	if fp == h.judged {
		return nil
	}
	h.judged = fp
	m, err := rootswap.ReadStaged(h.StageDir, h.Keys)
	if err != nil {
		h.refused(err, nil)
		return nil
	}
	var running *rootswap.Manifest
	if h.cur != nil {
		running = &h.cur.Manifest
		if m == *running {
			return nil // what runs already
		}
	}
	if m.SHA256 == h.failedSHA && time.Now().Before(h.retryAt) {
		h.judged = "" // look again once the wait is over
		return nil
	}
	if err := rootswap.CheckNewer(m, running); err != nil {
		h.refused(err, &m)
		return nil
	}
	inst, err := rootswap.Install(h.StageDir, h.BinDir, m)
	if err != nil {
		h.refused(err, &m)
		return nil
	}
	h.lastErr = ""
	return inst
}

// refused logs a staged helper root will not run. A refusal other than an
// older release (an agent rolled back stages one) means a broken build or
// a broken agent. The line is root's own, in the runtime container's log,
// where the agent cannot reach it.
func (h *HelperKeeper) refused(err error, m *rootswap.Manifest) {
	reason := rootswap.ReasonOf(err)
	if reason == "" {
		// Root's own folder failed, not the staged helper: try again on
		// the next tick, and say so once.
		h.judged = ""
		h.once("supervisor: could not check the staged root helper", err)
		return
	}
	args := []any{"reason", reason, "error", err}
	if m != nil {
		args = append(args, "version", m.Version, "api", m.API)
	}
	if reason == rootswap.ReasonOlder {
		h.Log.Warn("supervisor: kept the running root helper; the staged one is older", args...)
		return
	}
	h.Log.Error("supervisor: refused the staged root helper", args...)
}

func (h *HelperKeeper) once(msg string, err error) {
	if err.Error() != h.lastErr {
		h.lastErr = err.Error()
		h.Log.Warn(msg, "dir", h.StageDir, "error", err)
	}
}

// swap moves to next: the helper that runs is stopped, and it and all it
// started have exited, before next starts (exclusive handover). With a
// helper to go back to, next must say it serves within ReadyWait, or the
// old copy runs again.
func (h *HelperKeeper) swap(ctx context.Context, next *rootswap.Installed) {
	prev := h.cur
	if prev == nil {
		h.cur, h.child = next, h.startServing(ctx, next)
		return
	}
	if h.child != nil {
		h.Log.Info("supervisor: swapping the root helper", "from", prev.Manifest.Version, "to", next.Manifest.Version)
		h.stop(h.child)
		h.child = nil
	}
	child, ready, err := h.start(ctx, next)
	if err == nil {
		err = h.waitReady(ctx, child, ready)
	}
	if err == nil || ctx.Err() != nil {
		h.cur, h.child = next, child
		if prev.Path != next.Path {
			_ = prev.Remove()
		}
		if err == nil {
			h.Log.Info("supervisor: the root helper serves", "version", next.Manifest.Version, "copy", next.Path)
		}
		return
	}
	if child != nil {
		h.stop(child)
		// A helper that said it serves, however late, has taken calls
		// from the backlog and told the agent what it offers. Going back
		// to the older copy now would take calls away from an agent that
		// has used them, so the newer copy is kept and started again.
		if ready.served(h.ReadyWait) {
			h.Log.Warn("supervisor: the new root helper served late and was stopped; starting it again, not the old one",
				"version", next.Manifest.Version, "old", prev.Manifest.Version, "error", err)
			h.cur = next
			if prev.Path != next.Path {
				_ = prev.Remove()
			}
			h.child = h.startServing(ctx, next)
			return
		}
	}
	h.Log.Error("supervisor: the new root helper did not start; the old one runs again",
		"version", next.Manifest.Version, "old", prev.Manifest.Version, "error", err, "retry_in", h.RetryFailed)
	h.failedSHA, h.retryAt = next.Manifest.SHA256, time.Now().Add(h.RetryFailed)
	h.judged = ""
	if prev.Path != next.Path {
		_ = next.Remove()
	}
	h.child = h.startServing(ctx, prev)
}

// startServing starts inst and logs when it serves. nil: it did not start;
// Run starts it again after a wait.
func (h *HelperKeeper) startServing(ctx context.Context, inst *rootswap.Installed) Child {
	child, ready, err := h.start(ctx, inst)
	if err != nil {
		if ctx.Err() == nil {
			h.Log.Error("supervisor: could not start the root helper", "version", inst.Manifest.Version, "error", err)
		}
		return nil
	}
	go func() {
		<-ready.done
		if ready.ok {
			h.Log.Info("supervisor: the root helper serves", "version", inst.Manifest.Version, "copy", inst.Path)
		}
	}()
	return child
}

// readyPipe is a helper's ready pipe, read once: done closes when the
// helper wrote its byte (ok) or the pipe closed without it. Unlike a
// channel's single value, every reader sees the outcome.
type readyPipe struct {
	done chan struct{}
	ok   bool // set before done closes
}

// served says whether the helper wrote its byte, waiting up to wait for
// the outcome. Called once the helper has exited, when its end of the
// pipe is closed and the outcome follows at once.
func (r *readyPipe) served(wait time.Duration) bool {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-r.done:
		return r.ok
	case <-t.C:
		return false
	}
}

// start runs inst with the socket and a ready pipe, which tells once the
// helper writes its byte or the pipe closes without it. It is the one
// place a helper starts, so it is where the group is checked empty: on a
// swap, a rollback, a restart after a crash and the first start alike.
func (h *HelperKeeper) start(ctx context.Context, inst *rootswap.Installed) (Child, *readyPipe, error) {
	if !h.clear(ctx) {
		return nil, nil, ctx.Err()
	}
	if h.sock == nil {
		ln, fi, err := rootfolder.Listen(h.Socket, h.SocketGID)
		if err != nil {
			return nil, nil, fmt.Errorf("the helper's socket: %w", err)
		}
		f, err := ln.File()
		_ = ln.Close() // the file is a copy; the socket stays
		if err != nil {
			return nil, nil, fmt.Errorf("the helper's socket: %w", err)
		}
		h.sock, h.sockInfo = f, fi
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	env := append(slices.Clone(h.Env), rootswap.HandoverEnv()...)
	child, err := h.Start(inst.Path, env, []*os.File{h.sock, w})
	_ = w.Close() // the helper holds its own end
	if err != nil {
		_ = r.Close()
		return nil, nil, err
	}
	h.started = time.Now()
	ready := &readyPipe{done: make(chan struct{})}
	go func() {
		defer r.Close()
		var b [1]byte
		n, _ := r.Read(b[:])
		ready.ok = n == 1
		close(ready.done)
	}()
	h.Log.Info("supervisor: started the root helper", "version", inst.Manifest.Version, "api", inst.Manifest.API, "copy", inst.Path)
	return child, ready, nil
}

// waitReady waits for a new helper to say it serves. A byte that lands as
// the wait runs out still counts: select picks at random among ready
// cases, and the helper serves from the moment it writes it.
func (h *HelperKeeper) waitReady(ctx context.Context, child Child, ready *readyPipe) error {
	timer := time.NewTimer(h.ReadyWait)
	defer timer.Stop()
	select {
	case <-ready.done:
		if ready.ok {
			return nil
		}
		return errors.New("it exited before it served")
	case <-child.Done():
		return errors.New("it exited before it served")
	case <-timer.C:
		select {
		case <-ready.done:
			if ready.ok {
				return nil
			}
		default:
		}
		return fmt.Errorf("it did not serve within %v", h.ReadyWait)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stop drains a helper and waits until it has exited, killing it after
// KillAfter. It never returns while the helper runs: the next one must
// not serve beside it. What the helper started may still run; start
// empties the group before the next one.
func (h *HelperKeeper) stop(c Child) {
	_ = c.Signal(syscall.SIGTERM)
	timer := time.NewTimer(h.KillAfter)
	defer timer.Stop()
	select {
	case <-c.Done():
		return
	case <-timer.C:
	}
	h.Log.Warn("supervisor: the root helper did not stop in time; killing it", "after", h.KillAfter)
	_ = c.Signal(syscall.SIGKILL)
	<-c.Done()
}

// clear returns once the helpers' group is empty (HelperGroup.Empty): no
// helper may start while anything the last one started still runs. A
// group that will not empty is an error, logged on every try, and tried
// again with a growing wait. false: ctx ended first.
func (h *HelperKeeper) clear(ctx context.Context) bool {
	if h.Group == nil {
		return true
	}
	wait := h.MinBackoff
	for {
		err := h.Group.Empty()
		if err == nil {
			return true
		}
		h.Log.Error("supervisor: the root helper's cgroup still holds what the last helper started; no helper starts beside it; trying again",
			"error", err, "in", wait)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
		wait = min(wait*2, h.MaxBackoff)
	}
}

// closeGroup empties the helpers' group as the supervisor stops, with one
// bounded try, and removes it.
func (h *HelperKeeper) closeGroup() {
	if h.Group == nil {
		return
	}
	if err := h.Group.Empty(); err != nil {
		h.Log.Error("supervisor: could not empty the root helper's cgroup as it stops", "error", err)
		return
	}
	if err := h.Group.Remove(); err != nil {
		h.Log.Warn("supervisor: could not remove the root helper's cgroup", "error", err)
	}
}

// closeSocket closes the supervisor's copy and removes the socket file,
// if it is still the one made here.
func (h *HelperKeeper) closeSocket() {
	if h.sock == nil {
		return
	}
	_ = h.sock.Close()
	if cur, err := os.Lstat(h.Socket); err == nil && os.SameFile(cur, h.sockInfo) {
		_ = os.Remove(h.Socket)
	}
	h.sock = nil
}

// Root helper defaults: the helper's own (internal/rootd); the copies go
// in the supervisor's folder in the runtime container, which the agent's
// container cannot reach.
const (
	defaultRootdSocket      = "/run/aerolvm-rootd/sock/root.sock"
	defaultRootdSocketGroup = "aerolvm"
	defaultRootdBinDir      = "/var/lib/aerolvm-supervisor/rootd"
)

// newHelperKeeper checks the helper's settings before the supervisor
// touches the machine. A runtime image without a release key cannot run
// any helper, so asking it to is an error, not a quiet no-op.
func newHelperKeeper(s Settings, keys func() ([]ed25519.PublicKey, error), log *slog.Logger) (*HelperKeeper, error) {
	for _, p := range []struct{ name, path string }{
		{"SB_ROOTD_STAGE_DIR", s.RootdStageDir}, {"SB_ROOTD_BIN_DIR", s.RootdBinDir}, {"SB_ROOTD_SOCKET", s.RootdSocket},
	} {
		if !filepath.IsAbs(p.path) || filepath.Clean(p.path) != p.path || p.path == "/" {
			return nil, fmt.Errorf("%s=%q: want a clean absolute path", p.name, p.path)
		}
	}
	// The staged folder is the agent's: anything of root's below it could
	// be renamed away by the agent.
	for _, p := range []struct{ name, path string }{{"SB_ROOTD_BIN_DIR", s.RootdBinDir}, {"SB_ROOTD_SOCKET", filepath.Dir(s.RootdSocket)}} {
		if p.path == s.RootdStageDir || strings.HasPrefix(p.path, s.RootdStageDir+"/") || strings.HasPrefix(s.RootdStageDir, p.path+"/") {
			return nil, fmt.Errorf("%s %s and SB_ROOTD_STAGE_DIR %s overlap; the staged folder is the agent's", p.name, p.path, s.RootdStageDir)
		}
	}
	gid, err := lookupGroup(s.RootdSocketGroup)
	if err != nil {
		return nil, fmt.Errorf("SB_ROOTD_SOCKET_GROUP: %w", err)
	}
	k, err := keys()
	if err != nil {
		return nil, err
	}
	if len(k) == 0 {
		return nil, errors.New("SB_ROOTD_STAGE_DIR is set, but this runtime image has no release key to check a root helper with")
	}
	return &HelperKeeper{StageDir: s.RootdStageDir, BinDir: s.RootdBinDir, Socket: s.RootdSocket, SocketGID: gid, Keys: k, Log: log}, nil
}

// lookupGroup takes a gid or a group name, as the helper's own config does.
func lookupGroup(s string) (int, error) {
	if n, err := strconv.ParseUint(s, 10, 31); err == nil {
		return int(n), nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(g.Gid, 10, 31)
	if err != nil {
		return 0, fmt.Errorf("group %s has gid %q", s, g.Gid)
	}
	return int(n), nil
}

// helperEnv is the helper's environment: the supervisor's own, which the
// operator set and only root can change, with the cgroup parent the
// supervisor worked out. The helper's gate checks every sandbox's cgroup
// against it, and the copy the agent reads sits in a folder every
// container in the pod can write (review L6). Handover names left in the
// supervisor's own environment are dropped; each start adds fresh ones.
func helperEnv(environ []string, cgroupParent string) []string {
	drop := []string{"SB_CONTAINERD_CGROUP_PARENT=", rootswap.ListenFDEnv + "=", rootswap.ReadyFDEnv + "="}
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		if !slices.ContainsFunc(drop, func(p string) bool { return strings.HasPrefix(kv, p) }) {
			out = append(out, kv)
		}
	}
	return append(out, "SB_CONTAINERD_CGROUP_PARENT="+cgroupParent)
}
