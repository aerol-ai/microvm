package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestDriverWorkerCrashIsolation is the D10 release gate at the driver layer:
// a panic inside a worker host function must not take down the driver (stand-in
// for sandboxd). Subprocess respawn is covered by pkg/wasm/worker
// TestWorkerCrashIsolation; here we verify Create/Inspect keep working after a
// worker connection panic.
func TestDriverWorkerCrashIsolation(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	// sun_path is capped at 104 bytes on macOS — keep worker.sock under /tmp.
	runDir := filepath.Join(os.TempDir(), "aerol-wasm-d10")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatalf("mkdir runDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	sup := newInProcessSupervisor()
	d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(sup)

	const sandboxID = "sb-driver-crash"
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, sandboxID, "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = d.Destroy(context.Background(), &models.Sandbox{ID: sandboxID}) })

	inst, err := d.instance(sandboxID)
	if err != nil {
		t.Fatalf("instance: %v", err)
	}

	client := worker.NewClient(inst.socketPath)
	_ = client.TriggerPanic(sandboxID)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.Ping(sandboxID); err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := client.Ping(sandboxID); err != nil {
		t.Fatalf("ping after worker panic: %v", err)
	}

	state, err := d.Inspect(context.Background(), sandboxID)
	if err != nil {
		t.Fatalf("Inspect after worker crash: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("Inspect state = %+v, want started", state)
	}
}
