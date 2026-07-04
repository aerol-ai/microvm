package wasm

import (
	"context"
	"fmt"
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
	if err := s.Supervisor.Ensure(ctx, slotID, socketPath); err != nil {
		return fmt.Errorf("ensure worker: %w", err)
	}
	client := worker.NewClient(socketPath)
	deadline := time.Now().Add(s.PingWait)
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
		worker.ReadyPollSleep(ctx, attempt)
		attempt++
	}
	if err := client.LoadModule(slotID, modulePath, memoryMB); err != nil {
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
