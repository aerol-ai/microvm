package wasm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

type execWorkerClient struct {
	recordingWorkerClient
	run     wasmengine.RunResult
	execErr error
}

func (c *execWorkerClient) Exec(_ string, _ wasmengine.Capabilities, _ string) (wasmengine.RunResult, error) {
	return c.run, c.execErr
}

type checkpointFailClient struct {
	recordingWorkerClient
}

func (c *checkpointFailClient) Checkpoint(context.Context, string, string, wasmengine.SnapshotConfig) error {
	return fmt.Errorf("checkpoint failed")
}

type netstatsWorkerClient struct {
	recordingWorkerClient
	in, out int64
	err     error
}

func (c *netstatsWorkerClient) NetstatsTick(string) (int64, int64, error) {
	return c.in, c.out, c.err
}

type invokeWorkerClient struct {
	recordingWorkerClient
	invokeCh chan string
}

func (c *invokeWorkerClient) Invoke(_ string, export string) error {
	if c.invokeCh != nil {
		c.invokeCh <- export
	}
	return nil
}

func (c *invokeWorkerClient) ResolvedListenPort(string) (int, error) {
	return 19081, nil
}

type failInstantiateClient struct {
	recordingWorkerClient
}

func (c *failInstantiateClient) Instantiate(string, wasmengine.Capabilities) error {
	return fmt.Errorf("instantiate failed")
}

type failLoadClient struct {
	recordingWorkerClient
}

func (c *failLoadClient) LoadModule(string, string, int) (wasmengine.LoadTimings, error) {
	return wasmengine.LoadTimings{}, fmt.Errorf("load failed")
}

type failEnsureSupervisor struct {
	fakeSupervisor
}

func (failEnsureSupervisor) Ensure(context.Context, string, string) error {
	return fmt.Errorf("ensure failed")
}

type errWarmPool struct{}

func (errWarmPool) NoteModule(string, string) {}

func (errWarmPool) Acquire(context.Context, string, string, int) (*wasmpool.Slot, error) {
	return nil, fmt.Errorf("warm pool broken")
}

type warmPoolDropperFake struct {
	fakeWarmPool
	dropped []string
}

func (p *warmPoolDropperFake) DropModule(digest string) {
	p.dropped = append(p.dropped, digest)
}

type fakeStateKV struct{}

func (fakeStateKV) Get(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, nil
}
func (fakeStateKV) Set(context.Context, string, string, []byte) error { return nil }
func (fakeStateKV) Delete(context.Context, string, string) error      { return nil }
func (fakeStateKV) ListKeys(context.Context, string) ([]string, error) {
	return nil, nil
}

func TestPingFullyWired(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetModuleResolver(fakeResolver{})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	if err := d.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestCreateValidationErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	base := New(Config{RunDir: dir, ModulesDir: dir}, nil)

	d := New(Config{RunDir: dir, ModulesDir: dir}, nil)
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "x"}, "sb", "", nil); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("no resolver: %v", err)
	}

	d = New(Config{RunDir: dir, ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "x"}, "sb", "", nil); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("no supervisor: %v", err)
	}

	d = New(Config{ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "x"}, "sb", "", nil); err == nil || !strings.Contains(err.Error(), "run dir") {
		t.Fatalf("no run dir: %v", err)
	}

	d = base
	d.SetModuleResolver(fakeResolver{})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{}, "sb", "", nil); err == nil || !strings.Contains(err.Error(), "module_ref") {
		t.Fatalf("empty ref: %v", err)
	}

	d.SetWarmPool(errWarmPool{})
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-warm-err", "", nil); err == nil || !strings.Contains(err.Error(), "warm pool") {
		t.Fatalf("warm pool error: %v", err)
	}
}

type resolveErrResolver struct{}

func (resolveErrResolver) Resolve(context.Context, string) (*wasmmod.ResolvedModule, error) {
	return nil, fmt.Errorf("resolve failed")
}

func TestCreateWorkerFailuresRunCleanup(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	ctx := context.Background()
	req := models.CreateSandboxRequest{Image: "demo.wasm"}

	t.Run("ensure", func(t *testing.T) {
		sup := &failEnsureSupervisor{}
		d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
		d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
		d.SetWorkerSupervisor(sup)
		d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
		if _, err := d.Create(ctx, req, "sb-ensure-fail", "", nil); err == nil || !strings.Contains(err.Error(), "start worker") {
			t.Fatalf("ensure fail: %v", err)
		}
		if _, err := d.instance("sb-ensure-fail"); err == nil {
			t.Fatal("instance should be cleaned up")
		}
	})

	t.Run("load", func(t *testing.T) {
		d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
		d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		d.SetWorkerClientFactory(func(string) WorkerClient { return &failLoadClient{} })
		if _, err := d.Create(ctx, req, "sb-load-fail", "", nil); err == nil || !strings.Contains(err.Error(), "load module") {
			t.Fatalf("load fail: %v", err)
		}
	})

	t.Run("instantiate", func(t *testing.T) {
		d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
		d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		d.SetWorkerClientFactory(func(string) WorkerClient { return &failInstantiateClient{} })
		if _, err := d.Create(ctx, req, "sb-inst-fail", "", nil); err == nil || !strings.Contains(err.Error(), "instantiate") {
			t.Fatalf("instantiate fail: %v", err)
		}
	})
}

func TestCreateResolveError(t *testing.T) {
	d := New(Config{RunDir: t.TempDir(), ModulesDir: t.TempDir()}, nil)
	d.SetModuleResolver(resolveErrResolver{})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "x"}, "sb", "", nil); err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("resolve error: %v", err)
	}
}

func TestExecSandbox(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	d := New(Config{RunDir: runDir, ModulesDir: dir, DefaultWallTimeout: time.Minute}, nil)
	d.SetWorkerClientFactory(func(string) WorkerClient {
		return &execWorkerClient{
			run: wasmengine.RunResult{
				Stdout:   "out",
				Stderr:   "err",
				ExitCode: 0,
				Usage:    wasmengine.UsageStats{WallDurationMs: 10, Instructions: 100},
			},
		}
	})
	workDir := filepath.Join(runDir, "sb-exec")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.byID["sb-exec"] = &sandboxInstance{
		sandboxID:   "sb-exec",
		socketPath:  filepath.Join(workDir, "worker.sock"),
		workDir:     workDir,
		baseArgs:    []string{"wasm"},
		entryExport: "_start",
		memoryMB:    64,
	}
	d.mu.Unlock()

	result, err := d.execSandbox(context.Background(), "sb-exec", models.ExecRequest{Command: "echo hi"})
	if err != nil {
		t.Fatalf("execSandbox: %v", err)
	}
	if result.Stdout != "out" || result.ExitCode != 0 || result.DurationMS != 10 {
		t.Fatalf("result = %+v", result)
	}

	_, err = d.execSandbox(context.Background(), "missing", models.ExecRequest{})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing sandbox: %v", err)
	}

	d.SetWorkerClientFactory(func(string) WorkerClient {
		return &execWorkerClient{execErr: fmt.Errorf("exec boom")}
	})
	result, err = d.execSandbox(context.Background(), "sb-exec", models.ExecRequest{})
	if err != nil {
		t.Fatalf("execSandbox surfaces worker failure in result, not as error: %v", err)
	}
	if result.ExitCode != 1 || result.Stderr == "" {
		t.Fatalf("error result = %+v", result)
	}

	exec := sandboxExecutor{driver: d, id: "sb-exec"}
	d.SetWorkerClientFactory(func(string) WorkerClient {
		return &execWorkerClient{run: wasmengine.RunResult{ExitCode: 0}}
	})
	if _, err := exec.Exec(httptest.NewRequest(http.MethodPost, "/", nil), models.ExecRequest{}); err != nil {
		t.Fatalf("sandboxExecutor.Exec: %v", err)
	}
}

func TestStartSandboxAndStartIdempotent(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-start-sb")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")

	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	d := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 64}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(sup)

	ctx := context.Background()
	if _, err := d.StartSandbox(ctx, nil, nil); err == nil || !strings.Contains(err.Error(), "nil sandbox") {
		t.Fatalf("nil sandbox: %v", err)
	}
	if _, err := d.StartSandbox(ctx, &models.Sandbox{ID: "sb-no-ref"}, nil); err == nil || !strings.Contains(err.Error(), "module_ref") {
		t.Fatalf("missing ref: %v", err)
	}

	sb := &models.Sandbox{ID: "sb-restart", Image: "demo.wasm", MemoryMB: 64}
	state, err := d.StartSandbox(ctx, sb, nil)
	if err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q", state.Status)
	}
	state2, err := d.Start(ctx, "sb-restart")
	if err != nil || state2.Status != models.SandboxStatusStarted {
		t.Fatalf("idempotent Start: %+v err=%v", state2, err)
	}
}

func TestResizeDiskRejected(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "d"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm", DiskGB: 1}, "sb-disk", "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.Resize(context.Background(), "sb-disk", models.ResizeSandboxRequest{DiskGB: 2}); err == nil || !strings.Contains(err.Error(), "disk resize") {
		t.Fatalf("disk resize: %v", err)
	}
}

func TestCheckpointLiveSandbox(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-live-cp")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	modulesDir := filepath.Join(dir, "modules")
	if err := os.MkdirAll(modulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")

	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	d := New(Config{RunDir: runDir, ModulesDir: modulesDir, DefaultMemoryMB: 64}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(sup)

	ctx := context.Background()
	sandboxID := "sb-live"
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, sandboxID, "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sb := &models.Sandbox{ID: sandboxID, ModuleDigest: "abc"}
	path, gen, err := d.CheckpointLiveSandbox(ctx, sb)
	if err != nil {
		t.Fatalf("CheckpointLiveSandbox: %v", err)
	}
	if path == "" || gen == "" {
		t.Fatalf("path/gen empty: %q %q", path, gen)
	}
	managed, err := d.ListManaged(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(managed) != 1 || managed[sandboxID].Status != models.SandboxStatusStarted {
		t.Fatalf("live checkpoint should keep instance: %+v", managed)
	}
}

func TestCheckpointFailureStopsWorker(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	sup := &fakeSupervisor{}
	d.SetWorkerSupervisor(sup)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &checkpointFailClient{} })

	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-cpfail", "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, _, err := d.CheckpointSandbox(ctx, &models.Sandbox{ID: "sb-cpfail"})
	if err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("expected checkpoint error: %v", err)
	}
	if sup.stopCalls == 0 {
		t.Fatal("expected supervisor stop on checkpoint failure")
	}
	if _, err := d.instance("sb-cpfail"); err == nil {
		t.Fatal("instance should be removed after failed checkpoint")
	}
}

func TestMigrateSandbox(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-migrate")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	modulesDir := filepath.Join(dir, "modules")
	if err := os.MkdirAll(modulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")

	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	d := New(Config{RunDir: runDir, ModulesDir: modulesDir, DefaultMemoryMB: 64}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(sup)

	ctx := context.Background()
	sandboxID := "sb-mig"
	sb := &models.Sandbox{ID: sandboxID, Image: "demo.wasm", ModuleDigest: "abc"}
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, sandboxID, "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, err := d.MigrateSandbox(ctx, nil, "/dest"); err == nil {
		t.Fatal("nil sandbox expected error")
	}
	if _, _, err := d.MigrateSandbox(ctx, sb, ""); err == nil {
		t.Fatal("empty dest expected error")
	}

	dest := filepath.Join(dir, "dest")
	target, gen, err := d.MigrateSandbox(ctx, sb, dest)
	if err != nil {
		t.Fatalf("MigrateSandbox: %v", err)
	}
	if gen == "" || !strings.Contains(target, "mem.snap") {
		t.Fatalf("target=%q gen=%q", target, gen)
	}
	if !wasmengine.DirExists(target) {
		t.Fatalf("missing migrated checkpoint at %s", target)
	}
}

func TestRehydrateAlreadyStarted(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-live-rh", "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	state, err := d.RehydrateSandbox(context.Background(), &models.Sandbox{ID: "sb-live-rh"}, nil)
	if err != nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("Rehydrate started: %+v err=%v", state, err)
	}
}

func TestServeToolboxWithInstance(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	workDir := filepath.Join(runDir, "sb-tool")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
	d.SetStateKV(fakeStateKV{})
	d.mu.Lock()
	d.byID["sb-tool"] = &sandboxInstance{
		sandboxID:  "sb-tool",
		workDir:    workDir,
		durability: models.DurabilityDurable,
		status:     models.SandboxStatusStarted,
	}
	d.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	d.ServeToolbox(req.Context(), "sb-tool", "tok", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("toolbox health status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsFor(t *testing.T) {
	dir := t.TempDir()
	workDir := filepath.Join(dir, "sb-sess")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := New(Config{ModulesDir: dir}, nil)
	inst := &sandboxInstance{sandboxID: "sb-sess", workDir: workDir}
	if _, err := d.sessionsFor(nil); err == nil {
		t.Fatal("nil instance expected error")
	}
	m1, err := d.sessionsFor(inst)
	if err != nil {
		t.Fatalf("sessionsFor: %v", err)
	}
	m2, err := d.sessionsFor(inst)
	if err != nil || m1 != m2 {
		t.Fatalf("expected cached manager: m1=%p m2=%p err=%v", m1, m2, err)
	}
}

func TestSyncGuestListenPorts(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	d := New(Config{RunDir: runDir, ModulesDir: dir}, nil)
	d.waitListenReady = func(string, int) error { return nil }
	invokeCh := make(chan string, 1)
	d.SetWorkerClientFactory(func(string) WorkerClient {
		return &invokeWorkerClient{invokeCh: invokeCh}
	})

	workDir := filepath.Join(runDir, "sb-guest")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inst := &sandboxInstance{
		sandboxID:   "sb-guest",
		socketPath:  filepath.Join(workDir, "worker.sock"),
		workDir:     workDir,
		status:      models.SandboxStatusStarted,
		entryExport: "_start",
	}
	d.mu.Lock()
	d.byID["sb-guest"] = inst
	d.mu.Unlock()

	ctx := context.Background()
	if err := d.SyncGuestListenPorts(ctx, "sb-guest", []int{8080}); err != nil {
		t.Fatalf("SyncGuestListenPorts: %v", err)
	}
	if inst.resolvedListenPort != 19081 {
		t.Fatalf("resolved port = %d", inst.resolvedListenPort)
	}
	select {
	case export := <-invokeCh:
		if export != "_start" {
			t.Fatalf("invoke export = %q", export)
		}
	case <-time.After(time.Second):
		t.Fatal("expected guest invoke")
	}

	if err := d.SyncGuestListenPorts(ctx, "sb-guest", nil); err != nil {
		t.Fatalf("disable listen: %v", err)
	}
	if inst.resolvedListenPort != 0 {
		t.Fatalf("resolved port after disable = %d", inst.resolvedListenPort)
	}

	d.mu.Lock()
	d.byID["sb-stopped"] = &sandboxInstance{sandboxID: "sb-stopped", status: models.SandboxStatusStopped}
	d.mu.Unlock()
	if err := d.SyncGuestListenPorts(ctx, "sb-stopped", []int{80}); err != nil {
		t.Fatalf("stopped sandbox sync: %v", err)
	}
}

func TestStartGuestEntryAsyncDedupes(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	invokeCh := make(chan string, 2)
	client := &invokeWorkerClient{invokeCh: invokeCh}
	inst := &sandboxInstance{sandboxID: "sb", entryExport: "_start"}
	inst.bumpRunGeneration()
	d.startGuestEntryAsync(inst, client)
	d.startGuestEntryAsync(inst, client)
	select {
	case <-invokeCh:
	case <-time.After(time.Second):
		t.Fatal("expected one invoke")
	}
	select {
	case <-invokeCh:
		t.Fatal("expected deduped second invoke")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestGuestHTTPProxy(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	d.mu.Lock()
	d.byID["sb-proxy"] = &sandboxInstance{
		sandboxID:          "sb-proxy",
		socketPath:         "/tmp/fake.sock",
		status:             models.SandboxStatusStarted,
		resolvedListenPort: 19081,
	}
	d.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if err := d.guestHTTPProxy("sb-proxy", 8080, rec, req); err != nil {
		t.Fatalf("guestHTTPProxy: %v", err)
	}

	d.mu.Lock()
	d.byID["sb-down"] = &sandboxInstance{sandboxID: "sb-down", status: models.SandboxStatusStopped}
	d.mu.Unlock()
	if err := d.guestHTTPProxy("sb-down", 8080, rec, req); err == nil {
		t.Fatal("stopped sandbox expected error")
	}
}

func TestWaitGuestListenReadyInvalidPort(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	if err := d.waitGuestListenReady("127.0.0.1", 0); err == nil {
		t.Fatal("port 0 expected error")
	}
}

func TestDriverNetworkPolicyAndNetstats(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient {
		return &netstatsWorkerClient{in: 5, out: 7}
	})
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-netstats", "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	d.SetNetworkBlocks("sb-netstats", true, false)
	d.SetNetworkBlocks("missing", false, true)

	deltas := d.DrainNetworkByteCounters()
	if d := deltas["sb-netstats"]; d.BytesIn != 5 || d.BytesOut != 7 {
		t.Fatalf("netstats = %+v", d)
	}

	d.SetWorkerClientFactory(func(string) WorkerClient {
		return &netstatsWorkerClient{err: fmt.Errorf("tick failed")}
	})
	if got := d.DrainNetworkByteCounters(); got != nil {
		t.Fatalf("tick error should yield nil map, got %+v", got)
	}
}

func TestRemoveImageWarmPoolDropper(t *testing.T) {
	dir := t.TempDir()
	digest := strings.Repeat("b", 64)
	path := filepath.Join(dir, digest)
	if err := os.WriteFile(path, []byte("wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := &warmPoolDropperFake{}
	d := New(Config{ModulesDir: dir, RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(wasmmod.NewResolver(dir))
	d.SetWarmPool(pool)
	if err := d.RemoveImage(context.Background(), digest); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
	if len(pool.dropped) != 1 || pool.dropped[0] != digest {
		t.Fatalf("dropped = %#v", pool.dropped)
	}
}

func TestDestroyWarmPoolInstance(t *testing.T) {
	dir := t.TempDir()
	warmDir := filepath.Join(dir, "warm")
	if err := os.MkdirAll(warmDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(warmDir, "worker.sock")
	if err := os.WriteFile(sock, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sup := &fakeSupervisor{}
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetWorkerSupervisor(sup)
	d.mu.Lock()
	d.byID["sb-warm-destroy"] = &sandboxInstance{
		sandboxID:    "sb-warm-destroy",
		workerKey:    "pool-1",
		socketPath:   sock,
		fromWarmPool: true,
		workDir:      filepath.Join(dir, "run", "sb-warm-destroy"),
	}
	d.mu.Unlock()
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-warm-destroy"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(warmDir); !os.IsNotExist(err) {
		t.Fatalf("warm dir should be removed: %v", err)
	}
	if sup.stopCalls != 1 {
		t.Fatalf("stop calls = %d", sup.stopCalls)
	}
}

func TestNoteWorkerSpawnCountWithoutCounter(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerSupervisor(&fakeSupervisor{})
	inst := &sandboxInstance{sandboxID: "sb", workerKey: "sb"}
	d.noteWorkerSpawnCount(inst)
	if inst.workerSpawnCount != 0 {
		t.Fatalf("spawn count = %d", inst.workerSpawnCount)
	}
}

type flakyPingClient struct {
	recordingWorkerClient
	calls int
}

func (c *flakyPingClient) Ping(string) error {
	c.calls++
	if c.calls < 2 {
		return fmt.Errorf("not ready")
	}
	return nil
}

func TestWaitWorkerRetriesUntilPingSucceeds(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	client := &flakyPingClient{}
	if err := d.waitWorker(context.Background(), client, "sb"); err != nil {
		t.Fatalf("waitWorker: %v", err)
	}
	if client.calls < 2 {
		t.Fatalf("ping calls = %d, want >= 2", client.calls)
	}
}

func TestRuntimeStateNilInstance(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	if d.runtimeState(nil) != nil {
		t.Fatal("nil instance should yield nil state")
	}
}

func TestCreateSnapshotSuccess(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-snap")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	modulesDir := filepath.Join(dir, "modules")
	if err := os.MkdirAll(modulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")
	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	d := New(Config{RunDir: runDir, ModulesDir: modulesDir, DefaultMemoryMB: 64}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(sup)
	ctx := context.Background()
	sandboxID := "sb-snap"
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, sandboxID, "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, err := d.CreateSnapshot(ctx, sandboxID, "")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if path == "" {
		t.Fatal("expected snapshot path")
	}
}

func TestNoteWorkerSpawnCountWithCounter(t *testing.T) {
	sup := &spawnCountingSupervisor{count: 2}
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerSupervisor(sup)
	inst := &sandboxInstance{sandboxID: "sb", workerKey: "sb"}
	d.noteWorkerSpawnCount(inst)
	if inst.workerSpawnCount != 2 {
		t.Fatalf("spawn count = %d", inst.workerSpawnCount)
	}
}

func TestListManagedRecordsInitialSpawnCount(t *testing.T) {
	sup := &spawnCountingSupervisor{count: 1}
	client := &recordingWorkerClient{}
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerSupervisor(sup)
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	d.mu.Lock()
	d.byID["sb-spawn-init"] = &sandboxInstance{
		sandboxID:  "sb-spawn-init",
		socketPath: "/tmp/fake.sock",
		workerKey:  "sb-spawn-init",
		status:     models.SandboxStatusStarted,
	}
	d.mu.Unlock()
	managed, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inst, err := d.instance("sb-spawn-init")
	if err != nil {
		t.Fatal(err)
	}
	if inst.workerSpawnCount != 1 {
		t.Fatalf("workerSpawnCount = %d", inst.workerSpawnCount)
	}
	if managed["sb-spawn-init"].Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q", managed["sb-spawn-init"].Status)
	}
}

func TestResizeLiveMemoryCallsSetCapability(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	capsClient := &recordingWorkerClient{}
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir, DefaultWallTimeout: time.Minute}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return capsClient })
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm", MemoryMB: 64}, "sb-rz-live", "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.Resize(context.Background(), "sb-rz-live", models.ResizeSandboxRequest{MemoryMB: 128}); err != nil {
		t.Fatalf("Resize: %v", err)
	}
}

func TestSyncGuestListenPortFixedPort(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.waitListenReady = func(string, int) error { return nil }
	client := &invokeWorkerClient{invokeCh: make(chan string, 1)}
	inst := &sandboxInstance{sandboxID: "sb-fixed", entryExport: "_start"}
	if err := d.syncGuestListenPort(context.Background(), inst, client, 8080); err != nil {
		t.Fatalf("syncGuestListenPort: %v", err)
	}
	if inst.resolvedListenPort != 8080 {
		t.Fatalf("resolved = %d", inst.resolvedListenPort)
	}
}

func TestStartGuestEntryAsyncNilGuards(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.startGuestEntryAsync(nil, &recordingWorkerClient{})
	d.startGuestEntryAsync(&sandboxInstance{}, nil)
}

func TestRemoveImageEdgeCases(t *testing.T) {
	var d *Driver
	if err := d.RemoveImage(context.Background(), "x"); err == nil {
		t.Fatal("nil driver expected error")
	}
	d = New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir()}, nil)
	if err := d.RemoveImage(context.Background(), "  "); err == nil {
		t.Fatal("empty ref expected error")
	}
	d.SetModuleResolver(wasmmod.NewResolver(t.TempDir()))
	if err := d.RemoveImage(context.Background(), "missing.wasm"); err != nil {
		t.Fatalf("missing module should be idempotent: %v", err)
	}
}

func TestTryAcquireWarmNilPool(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	slot, err := d.tryAcquireWarm(context.Background(), "digest", "/path", 256)
	if err != nil || slot != nil {
		t.Fatalf("nil pool = slot %v err %v", slot, err)
	}
}

func TestDriverEnsureHTTPListenerCreatesNet(t *testing.T) {
	d := &Driver{}
	dial, err := d.EnsureHTTPListener(context.Background(), "sb-new-net", 8800)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}
	if dial == "" || d.net == nil {
		t.Fatalf("dial=%q net=%v", dial, d.net)
	}
}

func TestRehydrateSandboxErrors(t *testing.T) {
	if _, err := (&Driver{}).RehydrateSandbox(context.Background(), nil, nil); err == nil {
		t.Fatal("nil sandbox expected error")
	}

	dir := t.TempDir()
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir, DefaultMemoryMB: 64}, nil)
	d.SetModuleResolver(fakeResolver{path: filepath.Join(dir, "missing.wasm"), digest: "abc"})
	d.SetWorkerSupervisor(&fakeSupervisor{})

	sb := &models.Sandbox{ID: "sb-rh-err", ModuleRef: "demo.wasm"}
	if _, err := d.RehydrateSandbox(context.Background(), sb, nil); !errors.Is(err, wasmengine.ErrEmptySnapshotDir) {
		t.Fatalf("missing checkpoint: %v", err)
	}

	d = New(Config{RunDir: filepath.Join(dir, "run2"), ModulesDir: dir, DefaultMemoryMB: 64}, nil)
	d.SetWorkerSupervisor(&fakeSupervisor{})
	if _, err := d.StartSandbox(context.Background(), &models.Sandbox{ID: "sb", Image: "demo.wasm"}, nil); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("StartSandbox without resolver: %v", err)
	}
}

type failStopClient struct {
	recordingWorkerClient
}

func (failStopClient) StopInstance(string) error {
	return fmt.Errorf("stop failed")
}

func TestStopPropagatesWorkerError(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &failStopClient{} })
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-stop-err", "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.Stop(context.Background(), "sb-stop-err"); err == nil || !strings.Contains(err.Error(), "stop instance") {
		t.Fatalf("Stop: %v", err)
	}
}

func TestPingNotFullyWired(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetModuleResolver(fakeResolver{})
	if err := d.Ping(context.Background()); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("missing supervisor: %v", err)
	}
}

func TestMarkWorkerInstanceStoppedSkipsTerminalStates(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.mu.Lock()
	d.byID["sb-stopped"] = &sandboxInstance{
		sandboxID: "sb-stopped",
		status:    models.SandboxStatusStopped,
	}
	inst := d.byID["sb-stopped"]
	d.mu.Unlock()
	got := d.markWorkerInstanceStopped("sb-stopped", inst)
	if got.status != models.SandboxStatusStopped {
		t.Fatalf("status = %q", got.status)
	}
}

func TestRefreshWorkerInstanceStateViaInstanceLoaded(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &unloadedWorkerClient{} })
	d.mu.Lock()
	d.byID["sb-unloaded"] = &sandboxInstance{
		sandboxID:  "sb-unloaded",
		socketPath: "/tmp/fake.sock",
		status:     models.SandboxStatusStarted,
	}
	d.mu.Unlock()
	state, err := d.Inspect(context.Background(), "sb-unloaded")
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != models.SandboxStatusStopped {
		t.Fatalf("status = %q", state.Status)
	}
}
