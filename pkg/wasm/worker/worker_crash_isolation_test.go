package worker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const workerTestEnv = "AEROL_WASM_WORKER_TEST_CHILD"

// TestWorkerCrashIsolation is the D10 release gate (plans/wasm-runtime.md §11):
// a panic inside a worker host function must not take down the supervisor process
// (stand-in for sandboxd). Only the affected worker is recreated.
func TestWorkerCrashIsolation(t *testing.T) {
	if os.Getenv(workerTestEnv) == "1" {
		_ = ServeSocketPath(os.Getenv("AEROL_WASM_WORKER_SOCKET"))
		os.Exit(0)
	}

	dir := t.TempDir()
	socketPath := filepath.Join(dir, "worker.sock")
	sandboxID := "sb-crash-test"

	spawner := func(ctx context.Context, sock string) (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkerCrashIsolation$")
		cmd.Env = append(os.Environ(),
			workerTestEnv+"=1",
			"AEROL_WASM_WORKER_SOCKET="+sock,
		)
		return cmd, nil
	}

	sup := NewSupervisor(spawner)
	if err := sup.Ensure(context.Background(), sandboxID, socketPath); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client := NewClient(socketPath)
		if err := client.Ping(sandboxID); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	client := NewClient(socketPath)
	_ = client.TriggerPanic(sandboxID)

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sup.SpawnCount(sandboxID) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := sup.SpawnCount(sandboxID); got < 2 {
		t.Fatalf("expected worker respawn (spawn count >= 2), got %d", got)
	}

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.Ping(sandboxID); err == nil {
			t.Cleanup(func() { _ = sup.Stop(sandboxID) })
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("respawned worker did not answer HealthPing")
}
