package worker

import (
	"errors"

	"context"
	"os/exec"
	"testing"
	"time"
)

func mockSpawner(ctx context.Context, socketPath string) (*exec.Cmd, error) {
	// a simple command that runs and exits
	return exec.CommandContext(ctx, "echo", "mock"), nil
}

func mockSpawnerSleep(ctx context.Context, socketPath string) (*exec.Cmd, error) {
	// a simple command that sleeps, so we can test kill/stop
	return exec.CommandContext(ctx, "sleep", "10"), nil
}

func TestNewSupervisor(t *testing.T) {
	// With default
	s := NewSupervisor(nil)
	if s == nil {
		t.Fatal("expected supervisor")
	}

	// With mock
	s = NewSupervisor(mockSpawner)
	if s == nil {
		t.Fatal("expected supervisor")
	}
}

func TestSupervisor_EnsureAndStop(t *testing.T) {
	s := NewSupervisor(mockSpawnerSleep)
	ctx := context.Background()
	sb := "sb-1"

	// Ensure starts the process
	err := s.Ensure(ctx, sb, "/tmp/dummy.sock")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	count := s.SpawnCount(sb)
	if count != 1 {
		t.Fatalf("expected 1 spawn, got %d", count)
	}

	// Ensure again does not spawn if it's already running
	err = s.Ensure(ctx, sb, "/tmp/dummy.sock")
	if err != nil {
		t.Fatalf("Ensure again: %v", err)
	}

	count = s.SpawnCount(sb)
	if count != 1 {
		t.Fatalf("expected 1 spawn, got %d", count)
	}

	// Stop kills it
	err = s.Stop(sb)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}

	count = s.SpawnCount(sb)
	if count != 0 {
		t.Fatalf("expected 0 spawn after stop, got %d", count)
	}

	// Stop again is no-op
	err = s.Stop(sb)
	if err != nil {
		t.Fatalf("Stop again: %v", err)
	}
}

func TestSupervisor_Respawn(t *testing.T) {
	s := NewSupervisor(mockSpawner)
	ctx := context.Background()
	sb := "sb-2"

	err := s.Ensure(ctx, sb, "/tmp/dummy2.sock")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for s.SpawnCount(sb) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if count := s.SpawnCount(sb); count < 2 {
		t.Fatalf("expected it to respawn, got count %d", count)
	}

	s.Stop(sb)
}

func TestDefaultSpawner(t *testing.T) {
	cmd, err := DefaultSpawner(context.Background(), "/tmp/test.sock")
	if err != nil {
		t.Fatalf("DefaultSpawner: %v", err)
	}
	if cmd == nil {
		t.Fatal("expected cmd")
	}
}

func TestDefaultResidentSpawner(t *testing.T) {
	cmd, err := DefaultResidentSpawner(context.Background(), "/tmp/test-resident.sock")
	if err != nil {
		t.Fatalf("DefaultResidentSpawner: %v", err)
	}
	if cmd == nil {
		t.Fatal("expected cmd")
	}
}

func TestRunCLI(t *testing.T) {
	// wrong args
	err := RunCLI([]string{})
	if err == nil {
		t.Fatal("expected error on empty args")
	}

	// this should try to serve on invalid path and error out fast
	err = RunCLI([]string{"/invalid/path/that/does/not/exist.sock"})
	if err == nil {
		t.Fatal("expected error on invalid socket path")
	}
}

func TestSupervisor_StartErrors(t *testing.T) {
	s := NewSupervisor(func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		return nil, errors.New("mock spawn error")
	})

	err := s.Ensure(context.Background(), "sb", "socket")
	if err == nil {
		t.Error("expected spawn error")
	}

	s2 := NewSupervisor(func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "nonexistent-command-1234"), nil
	})

	err = s2.Ensure(context.Background(), "sb", "socket")
	if err == nil {
		t.Error("expected start error")
	}
}
