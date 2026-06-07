package wasm

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
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
func (c *recordingWorkerClient) Checkpoint(string, string, wasmengine.SnapshotConfig) error {
	return nil
}
func (c *recordingWorkerClient) Restore(string, string, wasmengine.Capabilities) error { return nil }
func (c *recordingWorkerClient) SetCapability(string, wasmengine.Capabilities) error   { return nil }
func (c *recordingWorkerClient) NetstatsTick(string) (int64, int64, error)             { return 0, 0, nil }
func (c *recordingWorkerClient) SetNetworkBlocks(string, bool, bool) error             { return nil }
func (c *recordingWorkerClient) SetListenPort(string, int, string) error               { return nil }
func (c *recordingWorkerClient) ProxyHTTP(string, int, http.ResponseWriter, *http.Request) error {
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
	if _, err := d.CreateSnapshot(ctx, "id", "img"); err == nil {
		t.Fatal("CreateSnapshot on missing sandbox expected error")
	}
	if err := d.Resize(ctx, "missing", models.ResizeSandboxRequest{CPU: 2.0}); err == nil {
		t.Fatal("Resize on missing sandbox expected error")
	}
}

type fakeWarmPool struct {
	slot *wasmpool.Slot
}

func (p *fakeWarmPool) NoteModule(string, string) {}

func (p *fakeWarmPool) Acquire(_ context.Context, _, _ string) (*wasmpool.Slot, error) {
	if p.slot == nil {
		return nil, wasmpool.ErrNoSlot
	}
	s := p.slot
	p.slot = nil
	return s, nil
}

func TestCreateWarmPathSkipsEnsureAndLoad(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	runDir := filepath.Join(dir, "run")
	warmSock := filepath.Join(dir, "warm.sock")

	sup := &fakeSupervisor{}
	client := &recordingWorkerClient{}
	d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(sup)
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	d.SetWarmPool(&fakeWarmPool{slot: &wasmpool.Slot{
		ID:           "pool-1",
		ModuleDigest: "deadbeef",
		ModulePath:   modPath,
		SocketPath:   warmSock,
		WorkerKey:    "pool-1",
	}})

	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-warm", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sup.ensureCalls != 0 {
		t.Fatalf("ensure calls = %d, want 0 on warm hit", sup.ensureCalls)
	}
	if client.loadPath != "" {
		t.Fatalf("load path = %q, want empty on warm hit", client.loadPath)
	}
	inst, err := d.instance("sb-warm")
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	if inst.workerKey != "pool-1" || !inst.fromWarmPool {
		t.Fatalf("workerKey=%q fromWarm=%v", inst.workerKey, inst.fromWarmPool)
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

func TestResizeUpdatesInstanceLimits(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	runDir := filepath.Join(dir, "run")

	d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })

	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-rz", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.Resize(context.Background(), "sb-rz", models.ResizeSandboxRequest{CPU: 4.0, MemoryMB: 512}); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	inst, err := d.instance("sb-rz")
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	if inst.cpu != 4.0 || inst.memoryMB != 512 {
		t.Fatalf("limits cpu=%v mem=%d", inst.cpu, inst.memoryMB)
	}
}

func TestEnsureHTTPListenerOnDriver(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	dial, err := d.EnsureHTTPListener(context.Background(), "sb-net", 8080)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}
	if dial == "" {
		t.Fatal("expected dial address")
	}
	d.ReleaseHTTPListener("sb-net", 8080)
}
