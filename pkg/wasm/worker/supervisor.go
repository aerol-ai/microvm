package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
)

// Spawner starts a worker subprocess bound to socketPath. Production wiring uses
// `sandboxd --wasm-worker <socket>`; tests inject a subprocess of this test binary.
type Spawner func(ctx context.Context, socketPath string) (*exec.Cmd, error)

// DefaultSpawner runs the current executable in worker mode. Requires main to
// delegate --wasm-worker to worker.RunCLI (wired from cmd/sandboxd in Phase 1).
func DefaultSpawner(ctx context.Context, socketPath string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, "--wasm-worker", socketPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

// Slot tracks one sandbox worker subprocess.
type Slot struct {
	SandboxID  string
	SocketPath string
	spawnCount atomic.Int32
}

// Supervisor owns worker subprocesses for WASM sandboxes. A worker crash kills
// only that subprocess; the supervisor respawns the slot while sandboxd keeps running.
type Supervisor struct {
	spawn Spawner

	mu    sync.Mutex
	slots map[string]*slotState
}

type slotState struct {
	sandboxID  string
	socketPath string
	cmd        *exec.Cmd
	spawnCount int
	done       chan struct{}
}

// NewSupervisor constructs a supervisor. spawn must be non-nil.
func NewSupervisor(spawn Spawner) *Supervisor {
	if spawn == nil {
		spawn = DefaultSpawner
	}
	return &Supervisor{
		spawn: spawn,
		slots: make(map[string]*slotState),
	}
}

// Ensure starts (or restarts) the worker for sandboxID at socketPath.
func (s *Supervisor) Ensure(ctx context.Context, sandboxID, socketPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.slots[sandboxID]
	if ok && st.cmd != nil && st.cmd.Process != nil {
		select {
		case <-st.done:
			// crashed — fall through to respawn
		default:
			return nil
		}
	}
	return s.startLocked(ctx, sandboxID, socketPath)
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
	_ = os.Remove(socketPath)
	cmd, err := s.spawn(context.WithoutCancel(ctx), socketPath)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	st := &slotState{
		sandboxID:  sandboxID,
		socketPath: socketPath,
		cmd:        cmd,
		done:       make(chan struct{}),
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
	err := st.cmd.Wait()
	close(st.done)

	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.slots[st.sandboxID]
	if !ok || cur != st {
		return
	}
	// Auto-respawn once after a crash — enough for D10; Phase 2 adds durability policy.
	_ = err
	_ = s.startLocked(context.Background(), st.sandboxID, st.socketPath)
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

// Stop terminates the worker for sandboxID.
func (s *Supervisor) Stop(sandboxID string) error {
	s.mu.Lock()
	st, ok := s.slots[sandboxID]
	if ok {
		delete(s.slots, sandboxID)
	}
	s.mu.Unlock()
	if !ok || st.cmd == nil || st.cmd.Process == nil {
		return nil
	}
	if err := st.cmd.Process.Kill(); err != nil {
		return err
	}
	<-st.done
	return nil
}

// RunCLI is the `--wasm-worker <socket>` entrypoint shared by sandboxd and tests.
func RunCLI(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: --wasm-worker <socket-path>")
	}
	return ServeSocketPath(args[0])
}
