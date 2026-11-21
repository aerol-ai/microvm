package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// Spawner starts a worker subprocess bound to socketPath. Production wiring uses
// `sandboxd --wasm-worker <socket>`; tests inject a subprocess of this test binary.
type Spawner func(ctx context.Context, socketPath string) (*exec.Cmd, error)

// The flags a worker process is started with. FindWorkers reads them back
// off a running worker's command line at boot.
const (
	WorkerFlag       = "--wasm-worker"
	ResidentHostFlag = "--wasm-resident-host"
)

// DefaultSpawner runs the current executable in worker mode. Requires main to
// delegate --wasm-worker to worker.RunCLI (wired from cmd/sandboxd in Phase 1).
func DefaultSpawner(ctx context.Context, socketPath string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, WorkerFlag, socketPath)
	cmd.Env = workerEnvironment(ctx)
	// The worker writes where sandboxd does (the journal), never to a pipe
	// sandboxd reads: a worker that outlives sandboxd would get SIGPIPE on
	// its next write to a pipe whose reader is gone. Where that is a socket
	// the supervisor gives the worker a stream of its own at the start
	// (hostproc.OwnOutput): a shared one a worker could shut down for
	// sandboxd too.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

// workerLogIdentifier is what the journal names workers' lines with.
const workerLogIdentifier = "sandboxd-wasm-worker"

// DefaultResidentSpawner runs the current executable as a resident-module host
// (--wasm-resident-host → RunCLIResident): one process compiles a module once
// and hosts many isolated sandbox instances. Used by the driver's resident-host
// supervisor when SB_WASM_RESIDENT_HOST_ENABLED is set.
func DefaultResidentSpawner(ctx context.Context, socketPath string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, ResidentHostFlag, socketPath)
	cmd.Env = workerEnvironment(ctx)
	// As DefaultSpawner's.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

// workerEnvironment is an allowlist. A worker does not need the daemon PAT,
// encryption/KMS credentials, registry credentials, or the audit master key.
// Nor the node-wide compile cache (AEROL_WASM_COMPILE_CACHE_DIR): a worker
// gets its owner's cache from ctx (WithCompileCache), or none.
func workerEnvironment(ctx context.Context) []string {
	allowed := map[string]struct{}{
		"PATH": {}, "TMPDIR": {}, "LANG": {}, "LC_ALL": {}, "TZ": {},
		"SSL_CERT_FILE": {}, "SSL_CERT_DIR": {}, "LD_LIBRARY_PATH": {},
		"AEROL_WASM_ENGINE":    {},
		ListenFallbackEnv:      {},
		"SB_AUDIT_INGEST_PORT": {}, "SB_AUDIT_SPILL_DIR": {},
		"SB_EGRESS_ATTRIBUTION_ENABLED": {}, "SB_NODE_ID": {},
		"SB_EGRESS_OPERATOR_FILE": {},
		// The node ports host-mediated sandboxes may reach (node guard).
		egresspolicy.NodePortsEnv: {},
		// The private-range default and the node's extra deny floor and
		// private ranges (C24): a worker without them would let a WASM
		// sandbox reach what the host firewall keeps every container
		// sandbox from.
		egresspolicy.BlockPrivateEnv: {}, egresspolicy.DenyFloorEnv: {}, egresspolicy.PrivateRangesEnv: {},
		// The deny-floor file, which the worker watches (review R4).
		egresspolicy.FloorFileEnv: {},
	}
	out := make([]string, 0, len(allowed))
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, ok := allowed[name]; ok {
			out = append(out, entry)
		}
	}
	if dir := compileCacheFrom(ctx); dir != "" {
		out = append(out, cacheDirEnv+"="+dir)
	}
	return out
}

// Slot tracks one sandbox worker subprocess.
type Slot struct {
	SandboxID  string
	SocketPath string
	spawnCount atomic.Int32
}

// Supervisor owns worker subprocesses for WASM sandboxes. A worker crash kills
// only that subprocess; the supervisor respawns the slot while sandboxd keeps running.
//
// A worker outlives sandboxd when the supervisor has a cgroup (SetCgroup):
// it starts there, outside sandboxd's unit, and the next sandboxd takes it
// over with Adopt instead of starting a new one.
type Supervisor struct {
	spawn Spawner

	mu     sync.Mutex
	cgroup *hostproc.Cgroup
	slots  map[string]*slotState
}

type slotState struct {
	sandboxID  string
	socketPath string
	// spec is what the slot's worker was started with (its cache, its
	// spill folder, whether it stays root): a respawn after a crash keeps
	// it.
	spec spawnSpec
	cmd  *exec.Cmd
	// proc is a worker a previous sandboxd started and this one adopted.
	// It has no cmd: it is waited on and signalled through its pidfd.
	proc       hostproc.Process
	spawnCount int
	done       chan struct{}
	// quarantined: the worker broke the protocol (reaper.go). It was killed
	// and is not restarted; the slot refuses Ensure until Stop.
	quarantined bool
	// ready closes once the worker said it serves; readyR is the pipe it
	// says so on (ready.go). Both nil for an adopted worker.
	ready  chan struct{}
	readyR *os.File
}

// closeReady ends the slot's ready watcher, if it still waits.
func (st *slotState) closeReady() {
	if st.readyR != nil {
		_ = st.readyR.Close()
	}
}

// alive reports whether the slot's worker is still running.
func (st *slotState) alive() bool {
	if st == nil || (st.proc == nil && (st.cmd == nil || st.cmd.Process == nil)) {
		return false
	}
	select {
	case <-st.done:
		return false
	default:
		return true
	}
}

// NewSupervisor constructs a supervisor. spawn must be non-nil.
func NewSupervisor(spawn Spawner) *Supervisor {
	if spawn == nil {
		spawn = DefaultSpawner
	}
	s := &Supervisor{
		spawn: spawn,
		slots: make(map[string]*slotState),
	}
	registerSupervisor(s)
	return s
}

// SetCgroup makes every later worker start in cg, outside sandboxd's unit,
// so a sandboxd restart does not stop it. Nil keeps workers in place.
func (s *Supervisor) SetCgroup(cg *hostproc.Cgroup) {
	s.mu.Lock()
	s.cgroup = cg
	s.mu.Unlock()
}

// Survives reports whether workers this supervisor starts outlive sandboxd.
func (s *Supervisor) Survives() bool {
	s.mu.Lock()
	cg := s.cgroup
	s.mu.Unlock()
	return cg != nil && cg.Active()
}

// Ensure starts (or restarts) the worker for sandboxID at socketPath.
func (s *Supervisor) Ensure(ctx context.Context, sandboxID, socketPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if st, ok := s.slots[sandboxID]; ok {
		if st.quarantined {
			return workerQuarantinedSlot(st.socketPath)
		}
		if st.alive() {
			return nil
		}
	}
	// No worker, or it crashed: start one.
	return s.startLocked(ctx, sandboxID, socketPath)
}

// workerQuarantinedSlot is the error a quarantined slot answers with.
func workerQuarantinedSlot(path string) error {
	if err := workerQuarantined(path); err != nil {
		return err
	}
	return ErrWorkerQuarantined
}

func (s *Supervisor) startLocked(ctx context.Context, sandboxID, socketPath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := workerQuarantined(socketPath); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	spawnCtx := context.WithoutCancel(ctx)
	// Output of the worker's own where sandboxd's is a socket (the
	// journal): sandboxd's copies of it close once the start is done.
	var opened []*os.File
	defer func() { closeFiles(opened) }()
	// A ready pipe per command built (a cgroup start may build twice): the
	// started one's read end is kept, every other end closes after the
	// start (ready.go).
	type readyPipe struct {
		cmd  *exec.Cmd
		r, w *os.File
	}
	var pipes []readyPipe
	build := func() (*exec.Cmd, error) {
		cmd, err := s.spawn(spawnCtx, socketPath)
		if err != nil {
			return nil, err
		}
		opened = append(opened, hostproc.OwnOutput(cmd, workerLogIdentifier)...)
		// Without a pipe the worker is found by the poll, as before.
		if r, w, err := attachReadyPipe(cmd); err == nil {
			pipes = append(pipes, readyPipe{cmd: cmd, r: r, w: w})
		}
		return cmd, nil
	}
	var cmd *exec.Cmd
	var err error
	if s.cgroup != nil {
		cmd, err = s.cgroup.Start(build)
	} else if cmd, err = build(); err == nil {
		err = cmd.Start()
	}
	var readyR *os.File
	for _, p := range pipes {
		_ = p.w.Close()
		if err == nil && p.cmd == cmd {
			readyR = p.r
		} else {
			_ = p.r.Close()
		}
	}
	if err != nil {
		return err
	}
	st := &slotState{
		sandboxID:  sandboxID,
		socketPath: socketPath,
		spec:       specFrom(ctx),
		cmd:        cmd,
		done:       make(chan struct{}),
	}
	if readyR != nil {
		st.readyR, st.ready = readyR, make(chan struct{})
		go watchReady(readyR, st.ready)
	}
	if prev, ok := s.slots[sandboxID]; ok {
		st.spawnCount = prev.spawnCount + 1
	} else {
		st.spawnCount = 1
	}
	s.slots[sandboxID] = st
	go s.watch(st)
	return nil
}

func (s *Supervisor) watch(st *slotState) {
	_ = st.cmd.Wait()
	st.closeReady()
	close(st.done)
	s.exited(st)
}

// watchAdopted is watch for an adopted worker: its exit comes from its
// pidfd, and init reaps it.
func (s *Supervisor) watchAdopted(st *slotState) {
	<-st.proc.Done()
	_ = st.proc.Close()
	close(st.done)
	s.exited(st)
}

// exited respawns a slot whose worker ended while it was still wanted.
func (s *Supervisor) exited(st *slotState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.slots[st.sandboxID]
	if !ok || cur != st || st.quarantined {
		return
	}
	// Auto-respawn once after a crash — enough for D10; Phase 2 adds durability policy.
	_ = s.startLocked(withSpec(context.Background(), st.spec), st.sandboxID, st.socketPath)
}

// Adopt takes over a running worker a previous sandboxd started (found at
// boot by FindWorkers), as if this supervisor had started it: Ensure finds
// it alive, Stop ends it, and a crash respawns it. It counts as the slot's
// first spawn. A slot that already has a live worker keeps it and Adopt
// returns false; proc is then still the caller's.
func (s *Supervisor) Adopt(sandboxID, socketPath string, proc hostproc.Process) bool {
	if proc == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.slots[sandboxID]; ok && (st.alive() || st.quarantined) {
		return false
	}
	st := &slotState{
		sandboxID:  sandboxID,
		socketPath: socketPath,
		proc:       proc,
		spawnCount: 1,
		done:       make(chan struct{}),
	}
	s.slots[sandboxID] = st
	go s.watchAdopted(st)
	return true
}

// Ready is closed once the worker for sandboxID says it serves (ready.go):
// a hint to ping it now. nil when there is no such signal to wait for (no
// slot, or a worker adopted from a previous sandboxd), and never closed
// for a worker that does not say so: callers keep polling either way.
func (s *Supervisor) Ready(sandboxID string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.slots[sandboxID]; ok && st.ready != nil {
		return st.ready
	}
	return nil
}

// SpawnCount returns how many times the worker for sandboxID has been started.
func (s *Supervisor) SpawnCount(sandboxID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.slots[sandboxID]
	if !ok {
		return 0
	}
	return st.spawnCount
}

// Stop terminates the worker for sandboxID. It also ends a quarantine:
// the next Ensure starts a new worker.
func (s *Supervisor) Stop(sandboxID string) error {
	s.mu.Lock()
	st, ok := s.slots[sandboxID]
	if ok {
		delete(s.slots, sandboxID)
	}
	s.mu.Unlock()
	if !ok {
		return nil
	}
	defer quarantined.Delete(st.socketPath)
	st.closeReady()
	if st.proc != nil {
		if err := st.proc.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, hostproc.ErrGone) {
			return err
		}
		<-st.done
		st.removeSpill()
		return nil
	}
	if st.cmd == nil || st.cmd.Process == nil {
		return nil
	}
	// Already gone (a quarantine killed it): wait for its watch all the same.
	if err := st.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	<-st.done
	st.removeSpill()
	return nil
}

// quarantine kills the worker at path, if this supervisor runs it, and
// keeps its slot down: no restart after the kill, and Ensure refuses it
// until Stop (reaper.go). It does not wait for the exit.
func (s *Supervisor) quarantine(path string) {
	s.mu.Lock()
	var hit []*slotState
	for _, st := range s.slots {
		if st.socketPath == path {
			st.quarantined = true
			hit = append(hit, st)
		}
	}
	s.mu.Unlock()
	for _, st := range hit {
		switch {
		case st.proc != nil:
			_ = st.proc.Signal(syscall.SIGKILL)
		case st.cmd != nil && st.cmd.Process != nil:
			_ = st.cmd.Process.Kill()
		}
	}
}

// removeSpill removes the stopped worker's own spill folder, so warm-pool
// slots and resident hosts do not each leave one behind. An adopted
// worker's spec is not known: its folder is the one named for its socket
// (a warm slot's, a resident host's); a sandbox's own is removed with the
// sandbox.
func (st *slotState) removeSpill() {
	if !st.spec.rootOnly {
		RemoveSpillFolder(spillLabel(st.spec, st.socketPath))
	}
}

// RunCLI is the `--wasm-worker <socket>` entrypoint shared by sandboxd and tests.
func RunCLI(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: --wasm-worker <socket-path>")
	}
	return runWorker(args[0], &Server{})
}
