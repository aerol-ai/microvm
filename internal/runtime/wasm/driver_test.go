package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

type fakeResolver struct {
	path   string
	digest string
}

func (f fakeResolver) Resolve(_ context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	return &wasmmod.ResolvedModule{Ref: ref, Path: f.path, Digest: f.digest, SizeBytes: 1}, nil
}

type fakeSupervisor struct {
	ensureCalls int
	stopCalls   int
}

func (f *fakeSupervisor) Ensure(context.Context, string, string) error {
	f.ensureCalls++
	return nil
}

func (f *fakeSupervisor) Stop(string) error {
	f.stopCalls++
	return nil
}

type recordingWorkerClient struct {
	loadPath string
	stopped  bool
}

func (c *recordingWorkerClient) Ping(string) error { return nil }
func (c *recordingWorkerClient) LoadModule(_, path string) error {
	c.loadPath = path
	return nil
}
func (c *recordingWorkerClient) Instantiate(string, wasmengine.Capabilities) error { return nil }
func (c *recordingWorkerClient) Invoke(string, string) error                       { return nil }
func (c *recordingWorkerClient) Exec(string, wasmengine.Capabilities, string) (wasmengine.RunResult, error) {
	return wasmengine.RunResult{}, nil
}
func (c *recordingWorkerClient) StopInstance(string) error {
	c.stopped = true
	return nil
}

func TestDestroyNilSandboxIsNoop(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	if err := d.Destroy(context.Background(), nil); err != nil {
		t.Fatalf("Destroy(nil): %v", err)
	}
}

func TestListManagedEmptyOK(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	got, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %d", len(got))
	}
}

func TestInspectUnknownSandboxReturnsNil(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	state, err := d.Inspect(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if state != nil {
		t.Fatalf("expected nil state, got %+v", state)
	}
}

func TestPingRequiresModulesDir(t *testing.T) {
	d := New(Config{}, nil)
	if err := d.Ping(context.Background()); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("Ping without modules dir: %v", err)
	}
}

func TestNotImplementedMethods(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	ctx := context.Background()
	if _, err := d.CreateSnapshot(ctx, "id", "img"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if err := d.Resize(ctx, "id", models.ResizeSandboxRequest{}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("Resize: %v", err)
	}
	if err := d.RemoveImage(ctx, "img"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("RemoveImage: %v", err)
	}
}

func TestCreateColdPathWithFakeWorker(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	runDir := filepath.Join(dir, "run")

	sup := &fakeSupervisor{}
	client := &recordingWorkerClient{}
	d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(sup)
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })

	state, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "demo.wasm",
	}, "sb-1", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q", state.Status)
	}
	if state.ContainerIP != wasmLoopbackIP {
		t.Fatalf("container ip = %q", state.ContainerIP)
	}
	if state.ModuleDigest != "deadbeef" {
		t.Fatalf("digest = %q", state.ModuleDigest)
	}
	if client.loadPath != modPath {
		t.Fatalf("load path = %q", client.loadPath)
	}
	if sup.ensureCalls != 1 {
		t.Fatalf("ensure calls = %d", sup.ensureCalls)
	}

	if err := d.Stop(context.Background(), "sb-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !client.stopped {
		t.Fatal("expected stop instance")
	}

	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-1"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if sup.stopCalls != 1 {
		t.Fatalf("supervisor stop calls = %d", sup.stopCalls)
	}
	if _, err := os.Stat(filepath.Join(runDir, "sb-1")); !os.IsNotExist(err) {
		t.Fatalf("expected sandbox dir removed, stat err=%v", err)
	}
}
