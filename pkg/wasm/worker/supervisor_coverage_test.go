package worker

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCoverage95SupervisorStartLockedEdges(t *testing.T) {
	s := NewSupervisor(mockSpawner)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Ensure(ctx, "sb-cancel", "/tmp/cancel.sock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ensure canceled ctx = %v", err)
	}

	s2 := NewSupervisor(mockSpawner)
	s2.mu.Lock()
	err := s2.startLocked(nil, "sb-nil", "/tmp/nil-ctx.sock")
	s2.mu.Unlock()
	if err != nil {
		t.Fatalf("startLocked(nil ctx): %v", err)
	}
	s2.Stop("sb-nil")
}

func TestCoverage95SupervisorStopKillError(t *testing.T) {
	s := NewSupervisor(func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "sleep", "3600"), nil
	})
	if err := s.Ensure(context.Background(), "sb-kill", filepath.Join(t.TempDir(), "x.sock")); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop("sb-kill"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := s.Stop("missing"); err != nil {
		t.Fatalf("Stop missing: %v", err)
	}
}
