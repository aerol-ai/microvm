package wasm

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// spawnInProcessServer is a worker.Spawner that, instead of forking a subprocess,
// starts an in-process worker.Server listening on socketPath. It returns a dummy
// "sleep ∞" exec.Cmd that keeps the supervisor's slot alive (so Ensure succeeds).
func spawnInProcessServer(t *testing.T) worker.Spawner {
	t.Helper()
	return func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		// The supervisor already removed the socket; start a fresh listener.
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			return nil, err
		}
		srv := &worker.Server{}
		go func() {
			for {
				conn, ln_err := ln.Accept()
				if ln_err != nil {
					return
				}
				go func(c net.Conn) { _ = srv.Serve(c) }(conn)
			}
		}()
		t.Cleanup(func() { ln.Close() })
		// Return a long-running cmd so the supervisor slot stays "alive".
		return exec.CommandContext(ctx, "sleep", "60"), nil
	}
}

// errSpawnFail is a sentinel error for the broken spawner above.
var errSpawnFail = errSpawnError("broken spawner")

type errSpawnError string

func (e errSpawnError) Error() string { return string(e) }

// TestSupervisorSpawnerWarmEnsureError verifies that Warm returns an error
// wrapping the Supervisor.Ensure failure.
func TestSupervisorSpawnerWarmEnsureError(t *testing.T) {
	brokenSpawn := func(_ context.Context, _ string) (*exec.Cmd, error) {
		return nil, errSpawnFail
	}
	sup := worker.NewSupervisor(brokenSpawn)
	ss := NewSupervisorSpawner(sup)

	err := ss.Warm(context.Background(), "slot1", "/tmp/nonexistent.sock", "/mod.wasm")
	if err == nil {
		t.Fatal("expected error from Warm when Ensure fails")
	}
}

// TestSupervisorSpawnerWarmContextCancel verifies that Warm returns the
// context error when the context is cancelled during the Ping loop.
func TestSupervisorSpawnerWarmContextCancel(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "w.sock")

	// A spawner that just sleeps — no one serves the socket.
	sup := worker.NewSupervisor(func(ctx context.Context, _ string) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "sleep", "10"), nil
	})
	ss := NewSupervisorSpawner(sup)
	ss.PingWait = 50 * time.Millisecond // very short deadline

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := ss.Warm(ctx, "slot1", socketPath, "/mod.wasm")
	if err == nil {
		t.Fatal("expected error (timeout) from Warm")
	}
	_ = sup.Stop("slot1")
}

// TestSupervisorSpawnerWarmCtxDoneInSelect specifically hits the
// `case <-ctx.Done()` select branch in the Ping loop by using a very long
// PingWait (so the deadline-expired branch never triggers) while the ctx
// itself is cancelled quickly after Ensure succeeds.
func TestSupervisorSpawnerWarmCtxDoneInSelect(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "wd.sock")

	sup := worker.NewSupervisor(func(ctx context.Context, _ string) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "sleep", "10"), nil
	})
	ss := NewSupervisorSpawner(sup)
	ss.PingWait = 60 * time.Second // deadline will never be reached

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	err := ss.Warm(ctx, "slot-ctx", socketPath, "/mod.wasm")
	if err == nil {
		t.Fatal("expected ctx cancellation error from Warm")
	}
	_ = sup.Stop("slot-ctx")
}

// TestSupervisorSpawnerWarmLoadModuleError verifies the path where Ensure and
// Ping succeed but LoadModule returns an error (triggers Stop).
func TestSupervisorSpawnerWarmLoadModuleError(t *testing.T) {
	// macOS Unix socket paths are limited to ~104 chars; use a fixed short path.
	socketPath := filepath.Join(os.TempDir(), "pool_lm_err.sock")
	t.Cleanup(func() { os.Remove(socketPath) })

	// Use an in-process spawner so Ping will succeed.
	sup := worker.NewSupervisor(spawnInProcessServer(t))
	ss := NewSupervisorSpawner(sup)
	ss.PingWait = 3 * time.Second

	// Pass a nonexistent module path — the server's LoadModule handler will
	// fail to open the file and return MsgError.
	err := ss.Warm(context.Background(), "slot-lm", socketPath, "/nonexistent/module.wasm")
	if err == nil {
		t.Fatal("expected LoadModule error from Warm")
	}
}

// TestSupervisorSpawnerWarmSuccess verifies the full happy path of Warm:
// Ensure succeeds, Ping succeeds, and LoadModule succeeds.
func TestSupervisorSpawnerWarmSuccess(t *testing.T) {
	// We need a real WASM module to load. Use Go's testdata or create a minimal
	// no-op WAT blob compiled inline.
	//
	// Minimal valid WASM module (magic + version only — empty module body).
	wasmBytes := []byte{
		0x00, 0x61, 0x73, 0x6d, // magic: \0asm
		0x01, 0x00, 0x00, 0x00, // version: 1
	}
	modFile := filepath.Join(t.TempDir(), "noop.wasm")
	if err := os.WriteFile(modFile, wasmBytes, 0o600); err != nil {
		t.Fatalf("write wasm: %v", err)
	}

	// macOS Unix socket paths are limited to ~104 chars.
	socketPath := filepath.Join(os.TempDir(), "pool_warm_ok.sock")
	t.Cleanup(func() { os.Remove(socketPath) })

	sup := worker.NewSupervisor(spawnInProcessServer(t))
	ss := NewSupervisorSpawner(sup)
	ss.PingWait = 3 * time.Second

	err := ss.Warm(context.Background(), "slot-ok", socketPath, modFile)
	if err != nil {
		t.Fatalf("Warm happy path: %v", err)
	}
	_ = sup.Stop("slot-ok")
}

// TestSupervisorSpawnerShutdownWithSupervisor verifies the happy-path Shutdown
// via a real Supervisor.
func TestSupervisorSpawnerShutdownWithSupervisor(t *testing.T) {
	sup := worker.NewSupervisor(func(ctx context.Context, _ string) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "sleep", "10"), nil
	})
	if err := sup.Ensure(context.Background(), "slot-shut", "/tmp/shut2.sock"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	ss := NewSupervisorSpawner(sup)
	if err := ss.Shutdown("slot-shut"); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
