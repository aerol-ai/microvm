package wasm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func writeCov97Snap(t *testing.T, dir, entry, gen string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := wasmengine.WriteSnapshotDir(dir, wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			Entrypoint:      entry,
			CloneGeneration: gen,
		},
	}); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
}

type cov97ResolveFail struct{}

func (cov97ResolveFail) Resolve(context.Context, string) (*wasmmod.ResolvedModule, error) {
	return nil, fmt.Errorf("resolve broke")
}

type cov97CapFail struct{ recordingWorkerClient }

func (cov97CapFail) SetCapability(string, wasmengine.Capabilities) error {
	return errors.New("caps")
}

type cov97PingFail struct{ recordingWorkerClient }

func (cov97PingFail) Ping(string) error { return errors.New("worker down") }

type cov97CorruptRestore struct{ recordingWorkerClient }

func (c *cov97CorruptRestore) Restore(string, string, wasmengine.Capabilities) error {
	return models.ErrSnapshotCorrupt
}

func TestCoverage97RehydrateBranches(t *testing.T) {
	t.Run("corrupt snapshot", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
		_, err := d.RehydrateSandbox(context.Background(), &models.Sandbox{ID: "sb-bad", CheckpointPath: dir}, nil)
		if err == nil {
			t.Fatal("corrupt snapshot was accepted")
		}
	})

	t.Run("generation fence", func(t *testing.T) {
		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
		dir := filepath.Join(t.TempDir(), "snap")
		writeCov97Snap(t, dir, "_start", "gen-a")
		_, err := d.RehydrateSandbox(context.Background(), &models.Sandbox{
			ID: "sb-fence", CheckpointPath: dir, CloneGeneration: "gen-b",
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "generation") {
			t.Fatalf("fence = %v", err)
		}
	})

	t.Run("resolve failure", func(t *testing.T) {
		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
		d.SetModuleResolver(cov97ResolveFail{})
		dir := filepath.Join(t.TempDir(), "snap")
		writeCov97Snap(t, dir, "_start", "gen")
		_, err := d.RehydrateSandbox(context.Background(), &models.Sandbox{
			ID: "sb-res", CheckpointPath: dir, CloneGeneration: "gen", ModuleRef: "demo.wasm",
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "resolve") {
			t.Fatalf("resolve = %v", err)
		}
	})

	t.Run("empty digest and worker not ready", func(t *testing.T) {
		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
		d.SetModuleResolver(fakeResolver{path: filepath.Join(t.TempDir(), "m.wasm"), digest: "dig"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		d.SetWorkerClientFactory(func(string) WorkerClient { return &cov97PingFail{} })
		dir := filepath.Join(t.TempDir(), "snap")
		writeCov97Snap(t, dir, "_start", "gen")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := d.RehydrateSandbox(ctx, &models.Sandbox{
			ID: "sb-wait", CheckpointPath: dir, CloneGeneration: "gen", ModuleRef: "demo.wasm",
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "worker not ready") {
			t.Fatalf("wait = %v", err)
		}
	})

	t.Run("workdir is a file", func(t *testing.T) {
		runFile := filepath.Join(t.TempDir(), "run-file")
		if err := os.WriteFile(runFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		d := New(Config{ModulesDir: t.TempDir(), RunDir: runFile, DefaultMemoryMB: 64}, nil)
		d.SetModuleResolver(fakeResolver{path: filepath.Join(t.TempDir(), "m.wasm"), digest: "dig"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		dir := filepath.Join(t.TempDir(), "snap")
		writeCov97Snap(t, dir, "_start", "gen")
		_, err := d.RehydrateSandbox(context.Background(), &models.Sandbox{
			ID: "sb-mkdir", CheckpointPath: dir, CloneGeneration: "gen", ModuleRef: "demo.wasm", ModuleDigest: "dig",
		}, nil)
		if err == nil {
			t.Fatal("mkdir of a file parent succeeded")
		}
	})

	t.Run("defaults and empty entrypoint", func(t *testing.T) {
		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
		mod := filepath.Join(t.TempDir(), "m.wasm")
		d.SetModuleResolver(fakeResolver{path: mod, digest: "dig"})
		d.SetWorkerSupervisor(&spawnCountSupervisor{count: 4})
		d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
		dir := filepath.Join(t.TempDir(), "snap")
		writeCov97Snap(t, dir, "", "gen")
		state, err := d.RehydrateSandbox(context.Background(), &models.Sandbox{
			ID: "sb-ok", CheckpointPath: dir, CloneGeneration: "gen", ModuleRef: "demo.wasm", ModuleDigest: "dig",
		}, nil)
		if err != nil {
			t.Fatalf("rehydrate = %v", err)
		}
		if state == nil || state.Status != models.SandboxStatusStarted {
			t.Fatalf("state = %+v", state)
		}
	})

	t.Run("audit capability", func(t *testing.T) {
		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
		d.SetModuleResolver(fakeResolver{path: filepath.Join(t.TempDir(), "m.wasm"), digest: "dig"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
		d.SetAuditCapabilityIssuer(func(string) (string, string, error) {
			return "", "", errors.New("issuer down")
		})
		dir := filepath.Join(t.TempDir(), "snap")
		writeCov97Snap(t, dir, "_start", "gen")
		_, err := d.RehydrateSandbox(context.Background(), &models.Sandbox{
			ID: "sb-audit", CheckpointPath: dir, CloneGeneration: "gen", ModuleRef: "demo.wasm", ModuleDigest: "dig",
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "audit") {
			t.Fatalf("audit = %v", err)
		}
	})

	t.Run("create mkdir and audit failure", func(t *testing.T) {
		runFile := filepath.Join(t.TempDir(), "run-file")
		if err := os.WriteFile(runFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		blocked := New(Config{ModulesDir: t.TempDir(), RunDir: runFile, DefaultMemoryMB: 64}, nil)
		blocked.SetModuleResolver(fakeResolver{path: filepath.Join(t.TempDir(), "m.wasm"), digest: "dig"})
		blocked.SetWorkerSupervisor(&fakeSupervisor{})
		if _, err := blocked.Create(context.Background(), models.CreateSandboxRequest{ModuleRef: "demo.wasm"}, "sb-mkdir", "", nil); err == nil {
			t.Fatal("create mkdir succeeded")
		}
		if _, err := blocked.StartSandbox(context.Background(), &models.Sandbox{ID: "sb-start", ModuleRef: "demo.wasm", ModuleDigest: "dig"}, nil); err == nil {
			t.Fatal("start mkdir succeeded")
		}

		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 32}, nil)
		d.SetModuleResolver(fakeResolver{path: filepath.Join(t.TempDir(), "m.wasm"), digest: "dig"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
		d.SetAuditCapabilityIssuer(func(string) (string, string, error) {
			return "", "", errors.New("issuer down")
		})
		if _, err := d.Create(context.Background(), models.CreateSandboxRequest{ModuleRef: "demo.wasm"}, "sb-audit", "", nil); err == nil || !strings.Contains(err.Error(), "audit") {
			t.Fatalf("create audit = %v", err)
		}
		if _, err := d.StartSandbox(context.Background(), &models.Sandbox{ID: "sb-cold", ModuleRef: "demo.wasm", ModuleDigest: "dig"}, nil); err == nil || !strings.Contains(err.Error(), "audit") {
			t.Fatalf("start audit = %v", err)
		}
	})

	t.Run("resize capability failure", func(t *testing.T) {
		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 32}, nil)
		d.SetModuleResolver(fakeResolver{path: filepath.Join(t.TempDir(), "m.wasm"), digest: "dig"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		d.SetWorkerClientFactory(func(string) WorkerClient { return &cov97CapFail{} })
		if _, err := d.Create(context.Background(), models.CreateSandboxRequest{ModuleRef: "demo.wasm", MemoryMB: 64}, "sb-live", "", nil); err != nil {
			t.Fatalf("create = %v", err)
		}
		if err := d.Resize(context.Background(), "sb-live", models.ResizeSandboxRequest{MemoryMB: 128}); err == nil || !strings.Contains(err.Error(), "caps") {
			t.Fatalf("resize = %v", err)
		}
	})

	t.Run("corrupt restore", func(t *testing.T) {
		d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
		d.SetModuleResolver(fakeResolver{path: filepath.Join(t.TempDir(), "m.wasm"), digest: "dig"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		d.SetWorkerClientFactory(func(string) WorkerClient { return &cov97CorruptRestore{} })
		dir := filepath.Join(t.TempDir(), "snap")
		writeCov97Snap(t, dir, "_start", "gen")
		_, err := d.RehydrateSandbox(context.Background(), &models.Sandbox{
			ID: "sb-corrupt", CheckpointPath: dir, CloneGeneration: "gen", ModuleRef: "demo.wasm", ModuleDigest: "dig",
		}, nil)
		if !errors.Is(err, models.ErrSnapshotCorrupt) {
			t.Fatalf("restore = %v", err)
		}
	})
}
