package worker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// adoptedProc is a worker process a test controls: it exits when killed.
type adoptedProc struct {
	pid    int
	mu     sync.Mutex
	done   chan struct{}
	closed bool
	sigs   []syscall.Signal
	sigErr error
}

func newAdoptedProc(pid int) *adoptedProc { return &adoptedProc{pid: pid, done: make(chan struct{})} }

func (p *adoptedProc) Pid() int { return p.pid }
func (p *adoptedProc) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sigs = append(p.sigs, sig)
	if p.sigErr != nil {
		return p.sigErr
	}
	if sig == syscall.SIGKILL {
		p.exitLocked()
	}
	return nil
}
func (p *adoptedProc) exitLocked() {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}
func (p *adoptedProc) exit() {
	p.mu.Lock()
	p.exitLocked()
	p.mu.Unlock()
}
func (p *adoptedProc) Done() <-chan struct{} { return p.done }
func (p *adoptedProc) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}

// TestSupervisorAdoptsARunningWorker: an adopted worker is alive to Ensure
// (no second worker), counts as one spawn, and Stop ends it by its pidfd.
func TestSupervisorAdoptsARunningWorker(t *testing.T) {
	var spawned int
	s := NewSupervisor(func(ctx context.Context, sock string) (*exec.Cmd, error) {
		spawned++
		return exec.CommandContext(ctx, "sleep", "10"), nil
	})
	if s.Adopt("sb-1", "/tmp/a.sock", nil) {
		t.Fatal("adopted a nil process")
	}
	proc := newAdoptedProc(4242)
	if !s.Adopt("sb-1", "/tmp/a.sock", proc) {
		t.Fatal("Adopt refused a free slot")
	}
	if err := s.Ensure(context.Background(), "sb-1", "/tmp/a.sock"); err != nil {
		t.Fatal(err)
	}
	if spawned != 0 || s.SpawnCount("sb-1") != 1 {
		t.Fatalf("spawned %d, spawn count %d; want the adopted worker kept", spawned, s.SpawnCount("sb-1"))
	}
	// A second adopt of a live slot is refused: the first worker stays.
	if s.Adopt("sb-1", "/tmp/a.sock", newAdoptedProc(1)) {
		t.Fatal("Adopt replaced a live worker")
	}
	if err := s.Stop("sb-1"); err != nil {
		t.Fatal(err)
	}
	if len(proc.sigs) != 1 || proc.sigs[0] != syscall.SIGKILL {
		t.Fatalf("signals = %v, want SIGKILL", proc.sigs)
	}
	if spawned != 0 {
		t.Fatalf("Stop respawned the worker (%d spawns)", spawned)
	}
}

// TestSupervisorRespawnsACrashedAdoptedWorker: an adopted worker that dies
// while still wanted is replaced, like a child that crashes.
func TestSupervisorRespawnsACrashedAdoptedWorker(t *testing.T) {
	respawned := make(chan string, 1)
	s := NewSupervisor(func(ctx context.Context, sock string) (*exec.Cmd, error) {
		respawned <- sock
		return exec.CommandContext(ctx, "sleep", "10"), nil
	})
	proc := newAdoptedProc(77)
	sock := filepath.Join(t.TempDir(), "w.sock")
	s.Adopt("sb-2", sock, proc)
	proc.exit()
	select {
	case got := <-respawned:
		if got != sock {
			t.Fatalf("respawned on %q, want %q", got, sock)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("crashed adopted worker was not respawned")
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.SpawnCount("sb-2") != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.SpawnCount("sb-2") != 2 {
		t.Fatalf("spawn count = %d, want 2", s.SpawnCount("sb-2"))
	}
	proc.mu.Lock()
	closed := proc.closed
	proc.mu.Unlock()
	if !closed {
		t.Fatal("the dead worker's pidfd was not released")
	}
	_ = s.Stop("sb-2")
}

// TestSupervisorStopAdoptedSignalError: a kill that fails for another
// reason than "gone" is reported; "gone" is not an error.
func TestSupervisorStopAdoptedSignalError(t *testing.T) {
	s := NewSupervisor(mockSpawnerSleep)
	proc := newAdoptedProc(5)
	proc.sigErr = errors.New("operation not permitted")
	s.Adopt("sb-3", "/tmp/c.sock", proc)
	if err := s.Stop("sb-3"); err == nil {
		t.Fatal("Stop hid a failed kill")
	}
	gone := newAdoptedProc(6)
	gone.sigErr = hostproc.ErrGone
	s.Adopt("sb-4", "/tmp/d.sock", gone)
	gone.exit()
	if err := s.Stop("sb-4"); err != nil {
		t.Fatalf("Stop of a gone worker = %v", err)
	}
}

// TestSupervisorStartsInItsCgroup: with a cgroup set, a worker starts
// through it; Survives says whether workers outlive sandboxd.
func TestSupervisorStartsInItsCgroup(t *testing.T) {
	s := NewSupervisor(mockSpawnerSleep)
	if s.Survives() {
		t.Fatal("survives without a cgroup")
	}
	cg := hostproc.NewCgroup(nil, t.TempDir(), "aerolvm-wasm", "WASM workers")
	s.SetCgroup(cg)
	// A temp dir is no cgroup v2 root: the cgroup turns itself off and the
	// worker starts in place, as before.
	if err := s.Ensure(context.Background(), "sb-5", "/tmp/e.sock"); err != nil {
		t.Fatal(err)
	}
	if s.Survives() {
		t.Fatal("survives with a cgroup that is off")
	}
	if s.SpawnCount("sb-5") != 1 {
		t.Fatalf("spawn count = %d", s.SpawnCount("sb-5"))
	}
	_ = s.Stop("sb-5")
	// A failing build is reported through the cgroup path too.
	bad := NewSupervisor(func(context.Context, string) (*exec.Cmd, error) { return nil, errors.New("no binary") })
	bad.SetCgroup(cg)
	if err := bad.Ensure(context.Background(), "sb-6", "/tmp/f.sock"); err == nil {
		t.Fatal("Ensure hid a failed build")
	}
}

// TestFindWorkers reads modes and sockets off command lines and holds each
// process; processes that are gone are left out, and a non-worker is a
// stray with no socket.
func TestFindWorkers(t *testing.T) {
	root := t.TempDir()
	cgDir := filepath.Join(root, "aerolvm-wasm")
	if err := os.MkdirAll(cgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte("10\n11\n12\n13\n14\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmdlines := map[int][]string{
		10: {"/usr/local/bin/sandboxd", WorkerFlag, "/run/sandboxd/wasm/sb-a/worker.sock"},
		11: {"/usr/local/bin/sandboxd", ResidentHostFlag, "/run/sandboxd/wasm/resident/abc-256mb.sock"},
		12: {"/bin/sh"},
		// 13 has no cmdline (exited); 14 cannot be opened.
		14: {"/usr/local/bin/sandboxd", WorkerFlag, "/run/x.sock"},
	}
	oldCmd, oldOpen := workerCmdline, openWorkerPID
	t.Cleanup(func() { workerCmdline, openWorkerPID = oldCmd, oldOpen })
	workerCmdline = func(pid int) ([]string, error) {
		if argv, ok := cmdlines[pid]; ok {
			return argv, nil
		}
		return nil, os.ErrNotExist
	}
	openWorkerPID = func(pid int) (hostproc.Process, error) {
		if pid == 14 {
			return nil, hostproc.ErrGone
		}
		return newAdoptedProc(pid), nil
	}
	found, err := FindWorkers(hostproc.NewCgroup(nil, root, "aerolvm-wasm", "WASM workers"))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 {
		t.Fatalf("found %d, want 3: %+v", len(found), found)
	}
	byPID := map[int]FoundWorker{}
	for _, f := range found {
		byPID[f.PID] = f
	}
	if w := byPID[10]; w.Resident || w.Socket != "/run/sandboxd/wasm/sb-a/worker.sock" || w.Proc == nil {
		t.Fatalf("per-sandbox worker = %+v", w)
	}
	if w := byPID[11]; !w.Resident || w.Socket != "/run/sandboxd/wasm/resident/abc-256mb.sock" {
		t.Fatalf("resident host = %+v", w)
	}
	if w := byPID[12]; w.Socket != "" || w.Proc == nil {
		t.Fatalf("stray = %+v", w)
	}
	// An unreadable cgroup is an error, not an empty list.
	if err := os.Remove(filepath.Join(cgDir, "cgroup.procs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cgDir, "cgroup.procs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := FindWorkers(hostproc.NewCgroup(nil, root, "aerolvm-wasm", "WASM workers")); err == nil {
		t.Fatal("unreadable cgroup listed")
	}
}

// TestSlotAlive covers the liveness rule Ensure and Adopt share.
func TestSlotAlive(t *testing.T) {
	var none *slotState
	if none.alive() {
		t.Fatal("nil slot alive")
	}
	if (&slotState{done: make(chan struct{})}).alive() {
		t.Fatal("slot with no process alive")
	}
	ended := &slotState{proc: newAdoptedProc(1), done: make(chan struct{})}
	close(ended.done)
	if ended.alive() {
		t.Fatal("ended slot alive")
	}
	// Stop of a slot with no process is a no-op.
	s := NewSupervisor(mockSpawnerSleep)
	s.slots["empty"] = &slotState{done: make(chan struct{})}
	if err := s.Stop("empty"); err != nil {
		t.Fatal(err)
	}
}
