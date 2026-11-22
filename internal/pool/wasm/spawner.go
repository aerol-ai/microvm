package wasm

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// Spawner warms a worker subprocess with a module already compiled (LoadModule done).
type Spawner interface {
	Warm(ctx context.Context, slotID, socketPath, modulePath string, memoryMB int) error
	Shutdown(slotID string) error
}

// SupervisorSpawner uses the shared worker.Supervisor to own pool slot processes.
type SupervisorSpawner struct {
	Supervisor *worker.Supervisor
	PingWait   time.Duration
	MemoryMB   int
	// CompileCache, when set, names the compile cache for the worker of the
	// slot whose folder it is given (the WASM driver's SlotCompileCache).
	// Without one the worker compiles every module from scratch.
	CompileCache func(slotDir string) string
}

// NewSupervisorSpawner constructs a spawner backed by worker.Supervisor.
func NewSupervisorSpawner(sup *worker.Supervisor) *SupervisorSpawner {
	return &SupervisorSpawner{
		Supervisor: sup,
		PingWait:   5 * time.Second,
	}
}

// Warm starts (or reuses) a worker at socketPath and loads modulePath.
func (s *SupervisorSpawner) Warm(ctx context.Context, slotID, socketPath, modulePath string, memoryMB int) error {
	if s == nil || s.Supervisor == nil {
		return fmt.Errorf("wasm pool spawner: supervisor not configured")
	}
	if memoryMB <= 0 {
		memoryMB = s.MemoryMB
	}
	if s.CompileCache != nil {
		if dir := s.CompileCache(filepath.Dir(socketPath)); dir != "" {
			ctx = worker.WithCompileCache(ctx, dir)
		}
	}
	if err := s.Supervisor.Ensure(ctx, slotID, socketPath); err != nil {
		return fmt.Errorf("ensure worker: %w", err)
	}
	client := worker.NewClient(socketPath)
	deadline := time.Now().Add(s.PingWait)
	// The worker's ready signal wakes the wait early, once; it is polled as
	// before when it does not signal (worker.Supervisor.Ready).
	ready := s.Supervisor.Ready(slotID)
	attempt := 0
	for {
		if err := client.Ping(slotID); err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("worker not ready at %s", socketPath)
		}
		if worker.ReadyPollSleepOr(ctx, attempt, ready) {
			ready = nil
		}
		attempt++
	}
	if _, err := client.LoadModule(slotID, modulePath, memoryMB); err != nil {
		_ = s.Supervisor.Stop(slotID)
		return fmt.Errorf("load module: %w", err)
	}
	return nil
}

// Shutdown stops the worker subprocess for slotID.
func (s *SupervisorSpawner) Shutdown(slotID string) error {
	if s == nil || s.Supervisor == nil {
		return nil
	}
	return s.Supervisor.Stop(slotID)
}
