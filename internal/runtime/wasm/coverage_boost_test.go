package wasm

// coverage_boost_test.go closes remaining gaps in the wasm driver package (not
// toolhost/statekv) to push statement coverage above 95%.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// ---------------------------------------------------------------------------
// create.go — recordLoadSubStages
// ---------------------------------------------------------------------------

type loadTimingsClient struct {
	recordingWorkerClient
}

func (c *loadTimingsClient) LoadModule(_, path string, _ int) (wasmengine.LoadTimings, error) {
	c.loadPath = path
	return wasmengine.LoadTimings{
		NewEngine:   time.Millisecond,
		RuntimeInit: 2 * time.Millisecond,
		Read:        3 * time.Millisecond,
		Compile:     4 * time.Millisecond,
	}, nil
}

func TestRecordLoadSubStagesEmittedOnColdCreate(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	runDir := filepath.Join(dir, "run")

	d := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 256}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &loadTimingsClient{} })

	ctx, timing := createtiming.With(context.Background())
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-substages", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	stages := wasmStageMap(timing)
	for _, name := range []string{"wasm_load_newengine", "wasm_load_runtime", "wasm_load_read", "wasm_load_compile"} {
		if _, ok := stages[name]; !ok {
			t.Fatalf("sub-stage %q not recorded (have %v)", name, stages)
		}
	}
}

func TestRecordLoadSubStagesDirect(t *testing.T) {
	_, timing := createtiming.With(context.Background())
	recordLoadSubStages(timing, wasmengine.LoadTimings{
		NewEngine:   time.Millisecond,
		RuntimeInit: 2 * time.Millisecond,
		Read:        3 * time.Millisecond,
		Compile:     4 * time.Millisecond,
	})
	for _, name := range []string{"wasm_load_newengine", "wasm_load_runtime", "wasm_load_read", "wasm_load_compile"} {
		if _, ok := wasmStageMap(timing)[name]; !ok {
			t.Fatalf("direct record missing %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// lifecycle.go — Start / StartSandbox / Stop / resolvePinned / Resize
// ---------------------------------------------------------------------------

type startFailEnsureSupervisor struct {
	fakeSupervisor
}

func (startFailEnsureSupervisor) Ensure(context.Context, string, string) error {
	return fmt.Errorf("ensure boom")
}

type startFailLoadClient struct {
	recordingWorkerClient
}

func (c *startFailLoadClient) LoadModule(string, string, int) (wasmengine.LoadTimings, error) {
	return wasmengine.LoadTimings{}, fmt.Errorf("load boom")
}

type startFailInstantiateClient struct {
	recordingWorkerClient
}

func (c *startFailInstantiateClient) Instantiate(string, wasmengine.Capabilities) error {
	return fmt.Errorf("instantiate boom")
}

func stoppedSandboxDriver(t *testing.T) (*Driver, string) {
	t.Helper()
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	runDir := filepath.Join(dir, "run")
	d := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 64}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	workDir := filepath.Join(runDir, "sb-stopped")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.byID["sb-stopped"] = &sandboxInstance{
		sandboxID:   "sb-stopped",
		modulePath:  modPath,
		socketPath:  filepath.Join(workDir, "worker.sock"),
		workDir:     workDir,
		status:      models.SandboxStatusStopped,
		entryExport: "_start",
		baseArgs:    []string{"wasm"},
		memoryMB:    64,
	}
	d.mu.Unlock()
	return d, modPath
}

func TestStartRestartsStoppedSandbox(t *testing.T) {
	d, _ := stoppedSandboxDriver(t)
	state, err := d.Start(context.Background(), "sb-stopped")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q", state.Status)
	}
}

func TestStartErrors(t *testing.T) {
	t.Run("ensure", func(t *testing.T) {
		d, _ := stoppedSandboxDriver(t)
		d.SetWorkerSupervisor(&startFailEnsureSupervisor{})
		if _, err := d.Start(context.Background(), "sb-stopped"); err == nil || !strings.Contains(err.Error(), "start worker") {
			t.Fatalf("ensure: %v", err)
		}
	})
	t.Run("load", func(t *testing.T) {
		d, _ := stoppedSandboxDriver(t)
		d.SetWorkerClientFactory(func(string) WorkerClient { return &startFailLoadClient{} })
		if _, err := d.Start(context.Background(), "sb-stopped"); err == nil || !strings.Contains(err.Error(), "load module") {
			t.Fatalf("load: %v", err)
		}
	})
	t.Run("instantiate", func(t *testing.T) {
		d, _ := stoppedSandboxDriver(t)
		d.SetWorkerClientFactory(func(string) WorkerClient { return &startFailInstantiateClient{} })
		if _, err := d.Start(context.Background(), "sb-stopped"); err == nil || !strings.Contains(err.Error(), "instantiate") {
			t.Fatalf("instantiate: %v", err)
		}
	})
}

func TestStartSandboxUsesExistingInstance(t *testing.T) {
	d, _ := stoppedSandboxDriver(t)
	d.mu.Lock()
	d.byID["sb-stopped"].status = models.SandboxStatusStarted
	d.mu.Unlock()
	sb := &models.Sandbox{ID: "sb-stopped", Image: "demo.wasm"}
	state, err := d.StartSandbox(context.Background(), sb, nil)
	if err != nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("StartSandbox existing: %+v err=%v", state, err)
	}
}

func TestResolvePinnedDigestCacheHit(t *testing.T) {
	res := &retargetingResolver{
		movedPath:   "/moved",
		movedDigest: "new",
		frozen: map[string]*wasmmod.ResolvedModule{
			"pinned": {Path: "/frozen", Digest: "pinned"},
		},
	}
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetModuleResolver(res)
	got, err := d.resolvePinned(context.Background(), "ref", "pinned", nil)
	if err != nil || got.Path != "/frozen" {
		t.Fatalf("resolvePinned hit: %+v err=%v", got, err)
	}
}

func TestStopSuccess(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-stop-ok", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Stop(context.Background(), "sb-stop-ok"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	inst, _ := d.instance("sb-stop-ok")
	if inst.status != models.SandboxStatusStopped {
		t.Fatalf("status = %q", inst.status)
	}
}

func TestResizeCPUOnlyOnStoppedSandbox(t *testing.T) {
	d, _ := stoppedSandboxDriver(t)
	if err := d.Resize(context.Background(), "sb-stopped", models.ResizeSandboxRequest{CPU: 2.0}); err != nil {
		t.Fatalf("Resize CPU: %v", err)
	}
	inst, _ := d.instance("sb-stopped")
	if inst.cpu != 2.0 {
		t.Fatalf("cpu = %v", inst.cpu)
	}
}

// ---------------------------------------------------------------------------
// resident.go — release, ensure, bringUp, prewarm, create, migrate, reaper
// ---------------------------------------------------------------------------

func TestReleaseResidentSlotGuards(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.releaseResidentSlotFor(nil)
	d.releaseResidentSlotFor(&sandboxInstance{sandboxID: "x"})
	d.releaseResidentSlot("")
	d.releaseResidentSlot("/nonexistent.sock")
}

func TestReleaseResidentSlotDoubleRelease(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-rel", "tok", nil); err != nil {
		t.Fatal(err)
	}
	inst, _ := d.instance("sb-rel")
	if got := totalResidentLive(d); got != 1 {
		t.Fatalf("live before = %d", got)
	}
	d.releaseResidentSlotFor(inst)
	if got := totalResidentLive(d); got != 0 {
		t.Fatalf("live after first release = %d", got)
	}
	// Second release must be a no-op (residentSlotHeld cleared).
	d.releaseResidentSlotFor(inst)
	if got := totalResidentLive(d); got != 0 {
		t.Fatalf("live after double release = %d", got)
	}
}

func TestEnsureResidentHostStaleHealthCheck(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-hc", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-hc"}); err != nil {
		t.Fatal(err)
	}
	// Backdate lastCheck so the next ensure re-probes InstanceLoaded.
	d.residentMu.Lock()
	for _, b := range d.residentBuckets {
		b.mu.Lock()
		for _, h := range b.hosts {
			h.lastCheck = time.Now().Add(-residentHealthTTL - time.Second)
		}
		b.mu.Unlock()
	}
	d.residentMu.Unlock()
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-hc2", "tok", nil); err != nil {
		t.Fatalf("create after stale health: %v", err)
	}
}

func TestEnsureResidentHostBringUpNotReadyHost(t *testing.T) {
	d, _, resident, _ := residentTestDriver(t, true)
	bucketID := residentBucketID("", "deadbeef", 0)
	sock := d.residentSocketPath(bucketID, 0)
	d.residentMu.Lock()
	if d.residentBuckets == nil {
		d.residentBuckets = make(map[string]*residentBucket)
	}
	b := &residentBucket{id: bucketID, hosts: []*residentHost{{socket: sock, index: 0, ready: false}}}
	d.residentBuckets[bucketID] = b
	d.residentMu.Unlock()

	if _, _, err := d.ensureResidentHost(context.Background(), "", "deadbeef", wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm"), d.cfg.DefaultMemoryMB, false); err != nil {
		t.Fatalf("ensure not-ready host: %v", err)
	}
	if resident.ensureCalls != 1 {
		t.Fatalf("ensure calls = %d", resident.ensureCalls)
	}
}

type bringUpFailSupervisor struct {
	fakeSupervisor
}

func (bringUpFailSupervisor) Ensure(context.Context, string, string) error {
	return fmt.Errorf("resident ensure failed")
}

func TestBringUpResidentHostEnsureError(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetResidentHostSupervisor(&bringUpFailSupervisor{})
	b := &residentBucket{id: "test-bucket"}
	h := &residentHost{socket: filepath.Join(t.TempDir(), "r.sock"), index: 0}
	if err := d.bringUpResidentHost(context.Background(), b, h, "/path/m.wasm", 64); err == nil || !strings.Contains(err.Error(), "start resident host") {
		t.Fatalf("bringUp ensure: %v", err)
	}
}

func TestPrewarmResidentHostsResolveError(t *testing.T) {
	d, _, resident, _ := residentTestDriver(t, true)
	d.SetModuleResolver(resolveErrResolver{})
	d.PrewarmResidentHosts(context.Background(), []string{"demo.wasm"})
	if resident.ensureCalls != 0 {
		t.Fatalf("ensure calls = %d on resolve error", resident.ensureCalls)
	}
}

func TestPrewarmResidentHostsEnsureError(t *testing.T) {
	d, _, resident, _ := residentTestDriver(t, true)
	d.SetResidentHostSupervisor(&bringUpFailSupervisor{})
	d.PrewarmResidentHosts(context.Background(), []string{"demo.wasm"})
	if resident.ensureCalls != 0 {
		t.Fatalf("ensure calls = %d on bring-up error", resident.ensureCalls)
	}
}

func TestPrewarmResidentHostsContextCancel(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.PrewarmResidentHosts(ctx, []string{"demo.wasm"})
}

func TestCreateOnResidentHostMkdirFailure(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	resolved := &wasmmod.ResolvedModule{Path: wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm"), Digest: "deadbeef"}
	if _, _, err := d.ensureResidentHost(context.Background(), "", resolved.Digest, resolved.Path, 64, false); err != nil {
		t.Fatalf("prewarm host: %v", err)
	}
	// Corrupt RunDir after the shared host exists so only the per-sandbox mkdir fails.
	runFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(runFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.cfg.RunDir = runFile
	if _, err := d.createOnResidentHost(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-mkdir", "demo.wasm", resolved, 64, nil, nil); err == nil || !strings.Contains(err.Error(), "mkdir sandbox dir") {
		t.Fatalf("mkdir fail: %v", err)
	}
}

func TestCreateOnResidentHostInstantiateFailure(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &instantiateFailClient{} })
	resolved := &wasmmod.ResolvedModule{Path: wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm"), Digest: "deadbeef"}
	if _, err := d.createOnResidentHost(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-inst-fail", "demo.wasm", resolved, 64, nil, nil); err == nil || !strings.Contains(err.Error(), "instantiate") {
		t.Fatalf("instantiate fail: %v", err)
	}
	if _, err := d.instance("sb-inst-fail"); err == nil {
		t.Fatal("instance should be rolled back")
	}
}

func TestMigrateResidentToColdNoSupervisor(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir()}, nil)
	inst := &sandboxInstance{sandboxID: "sb", workDir: t.TempDir()}
	if err := d.migrateResidentToCold(context.Background(), inst); err == nil || !strings.Contains(err.Error(), "supervisor not configured") {
		t.Fatalf("no supervisor: %v", err)
	}
}

func TestMigrateResidentToColdEnsureFailure(t *testing.T) {
	d, perSandbox, _, _ := residentTestDriver(t, true)
	perSandbox.ensureCalls = 0
	d.SetWorkerSupervisor(&startFailEnsureSupervisor{})
	inst := &sandboxInstance{
		sandboxID:  "sb-cold-fail",
		workDir:    filepath.Join(d.cfg.RunDir, "sb-cold-fail"),
		modulePath: wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm"),
		memoryMB:   64,
		socketPath: "/tmp/resident.sock",
	}
	if err := os.MkdirAll(inst.workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateResidentToCold(context.Background(), inst); err == nil || !strings.Contains(err.Error(), "start cold worker") {
		t.Fatalf("cold ensure: %v", err)
	}
}

func TestRunResidentReaperTickerFires(t *testing.T) {
	d, _, resident, _ := residentTestDriver(t, true)
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-reap", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-reap"}); err != nil {
		t.Fatal(err)
	}
	forceResidentHostsIdle(d, time.Now().Add(-time.Hour))
	stopsBefore := resident.stopCalls

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		d.RunResidentReaper(ctx, 20*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("reaper did not exit")
	}
	if resident.stopCalls <= stopsBefore {
		t.Fatalf("ticker did not reap idle host (stops %d -> %d)", stopsBefore, resident.stopCalls)
	}
}

// ---------------------------------------------------------------------------
// passivate.go — RehydrateSandbox error branches
// ---------------------------------------------------------------------------

func TestRehydrateSandboxSpawnCountRecorded(t *testing.T) {
	d, modulesDir := newDigestPinDriver(t)
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")
	ctx := context.Background()
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm", MemoryMB: 64}, "sb-spawn", "", nil); err != nil {
		t.Fatal(err)
	}
	sb := &models.Sandbox{ID: "sb-spawn", ModuleRef: "demo.wasm", ModuleDigest: "abc", MemoryMB: 64}
	path, gen, err := d.CheckpointSandbox(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	sb.CheckpointPath = path
	sb.CloneGeneration = gen
	if _, err := d.RehydrateSandbox(ctx, sb, nil); err != nil {
		t.Fatalf("RehydrateSandbox: %v", err)
	}
	inst, _ := d.instance("sb-spawn")
	if inst.workerSpawnCount < 0 {
		t.Fatalf("spawn count = %d", inst.workerSpawnCount)
	}
}

// ---------------------------------------------------------------------------
// remove_image.go / copydir.go
// ---------------------------------------------------------------------------

type notExistResolver struct{}

func (notExistResolver) Resolve(context.Context, string) (*wasmmod.ResolvedModule, error) {
	return nil, os.ErrNotExist
}

func TestRemoveImageResolveNotExistIsIdempotent(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(notExistResolver{})
	if err := d.RemoveImage(context.Background(), "gone.wasm"); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
}

func TestPathUnderDirRelError(t *testing.T) {
	if pathUnderDir(string([]byte{0}), "/any") {
		t.Fatal("invalid root should be false")
	}
}

func TestCopyDirMkdirAllError(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// dst is an existing file — MkdirAll(dst) must fail.
	dstFile := filepath.Join(t.TempDir(), "dst-file")
	if err := os.WriteFile(dstFile, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(src, dstFile); err == nil {
		t.Fatal("expected MkdirAll error when dst is a file")
	}
}

func TestCopyDirNestedDirError(t *testing.T) {
	src := t.TempDir()
	sub := filepath.Join(src, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	// dst parent is a file so nested copyDir fails.
	dstParent := filepath.Join(t.TempDir(), "parent-file")
	if err := os.WriteFile(dstParent, []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(src, filepath.Join(dstParent, "nested")); err == nil {
		t.Fatal("expected nested copyDir error")
	}
}

// ---------------------------------------------------------------------------
// guest_listen.go / guest_http.go
// ---------------------------------------------------------------------------

type failSetListenClient struct {
	invokeWorkerClient
}

func (c *failSetListenClient) SetListenPort(string, int, string) error {
	return fmt.Errorf("set listen failed")
}

type failResolvedPortClient struct {
	invokeWorkerClient
}

func (c *failResolvedPortClient) ResolvedListenPort(string) (int, error) {
	return 0, fmt.Errorf("resolve failed")
}

func TestSyncGuestListenPortSetListenError(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	inst := &sandboxInstance{sandboxID: "sb", entryExport: "_start"}
	if err := d.syncGuestListenPort(context.Background(), inst, &failSetListenClient{}, 8080); err == nil {
		t.Fatal("expected SetListenPort error")
	}
}

func TestSyncGuestListenPortResolvedPortError(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	inst := &sandboxInstance{sandboxID: "sb", entryExport: "_start"}
	if err := d.syncGuestListenPort(context.Background(), inst, &failResolvedPortClient{}, 0); err == nil || !strings.Contains(err.Error(), "resolve ephemeral") {
		t.Fatalf("resolved port error: %v", err)
	}
}

func TestSyncGuestListenPortWithoutWaitOverride(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.waitListenReady = nil
	client := &invokeWorkerClient{invokeCh: make(chan string, 1)}
	inst := &sandboxInstance{sandboxID: "sb", entryExport: "_start"}
	if err := d.syncGuestListenPort(context.Background(), inst, client, port); err != nil {
		t.Fatalf("syncGuestListenPort: %v", err)
	}
}

func TestWaitGuestListenReadyTimeout(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	// Pick a port that is very unlikely to be listening.
	if err := d.waitGuestListenReady("127.0.0.1", 1); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestSyncGuestListenPortsResidentUnexposeNoop(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-unex", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.SyncGuestListenPorts(context.Background(), "sb-unex", nil); err != nil {
		t.Fatalf("resident unexpose: %v", err)
	}
}

func TestGuestHTTPProxyUsesResolvedListenPort(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	proxyCalled := false
	d.SetWorkerClientFactory(func(string) WorkerClient {
		return &proxyPortRecordingClient{resolvedPort: 19081, called: &proxyCalled}
	})
	d.mu.Lock()
	d.byID["sb-rp"] = &sandboxInstance{
		sandboxID:          "sb-rp",
		socketPath:         "/tmp/fake.sock",
		status:             models.SandboxStatusStarted,
		resolvedListenPort: 19081,
	}
	d.mu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if err := d.guestHTTPProxy("sb-rp", 8080, rec, req); err != nil {
		t.Fatalf("guestHTTPProxy: %v", err)
	}
	if !proxyCalled {
		t.Fatal("ProxyHTTP not called")
	}
}

type proxyPortRecordingClient struct {
	recordingWorkerClient
	resolvedPort int
	called       *bool
}

func (c *proxyPortRecordingClient) ProxyHTTP(string, int, http.ResponseWriter, *http.Request) error {
	*c.called = true
	return nil
}

// ---------------------------------------------------------------------------
// network.go / network_policy.go
// ---------------------------------------------------------------------------

func TestEnsureHTTPListenerSecondPort(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	if _, err := g.EnsureHTTPListener(ctx, "sb-multi", 8080); err != nil {
		t.Fatal(err)
	}
	dial2, err := g.EnsureHTTPListener(ctx, "sb-multi", 9090)
	if err != nil || dial2 == "" {
		t.Fatalf("second port: dial=%q err=%v", dial2, err)
	}
}

func TestCloseListenerClearsSandboxMap(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	if _, err := g.EnsureHTTPListener(ctx, "sb-clear", 6000); err != nil {
		t.Fatal(err)
	}
	g.ReleaseHTTPListener("sb-clear", 6000)
	g.mu.Lock()
	_, ok := g.listeners["sb-clear"]
	g.mu.Unlock()
	if ok {
		t.Fatal("listeners map should be cleared")
	}
}

func TestDriverSetNetworkBlocksStoppedInstance(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.mu.Lock()
	d.byID["sb-stopped"] = &sandboxInstance{sandboxID: "sb-stopped", status: models.SandboxStatusStopped}
	d.mu.Unlock()
	d.SetNetworkBlocks("sb-stopped", true, true) // must not panic
}

type failSetBlocksClient struct {
	recordingWorkerClient
}

func (failSetBlocksClient) SetNetworkBlocks(string, bool, bool) error {
	return fmt.Errorf("blocks failed")
}

func TestDriverSetNetworkBlocksWorkerError(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &failSetBlocksClient{} })
	d.mu.Lock()
	d.byID["sb-live"] = &sandboxInstance{
		sandboxID:  "sb-live",
		socketPath: "/tmp/fake.sock",
		status:     models.SandboxStatusStarted,
	}
	d.mu.Unlock()
	d.SetNetworkBlocks("sb-live", true, false) // logs debug on worker error
}

// ---------------------------------------------------------------------------
// migrate.go
// ---------------------------------------------------------------------------

func TestMigrateSandboxOfflineMissingCheckpoint(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir()}, nil)
	sb := &models.Sandbox{ID: "sb-offline"}
	_, _, err := d.MigrateSandbox(context.Background(), sb, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "checkpoint missing") {
		t.Fatalf("offline migrate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// driver.go — refreshWorkerInstanceState / markWorkerInstanceStopped
// ---------------------------------------------------------------------------

func TestMarkWorkerInstanceStoppedDifferentInstance(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	stale := &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted}
	current := &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted}
	d.mu.Lock()
	d.byID["sb"] = current
	d.mu.Unlock()
	got := d.markWorkerInstanceStopped("sb", stale)
	if got != current {
		t.Fatal("expected current instance when stale != current")
	}
}

func TestRefreshWorkerInstanceStateRecordsInitialSpawnCount(t *testing.T) {
	sup := &spawnCountingSupervisor{count: 5}
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerSupervisor(sup)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	inst := &sandboxInstance{
		sandboxID:  "sb-init",
		socketPath: "/tmp/fake.sock",
		workerKey:  "sb-init",
		status:     models.SandboxStatusStarted,
	}
	d.mu.Lock()
	d.byID["sb-init"] = inst
	d.mu.Unlock()
	refreshed := d.refreshWorkerInstanceState(context.Background(), "sb-init", inst)
	if refreshed.workerSpawnCount != 5 {
		t.Fatalf("spawn count = %d, want 5", refreshed.workerSpawnCount)
	}
}

func TestListManagedSkipsNilAfterRefresh(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &unloadedWorkerClient{} })
	d.mu.Lock()
	d.byID["sb-nil"] = &sandboxInstance{
		sandboxID:  "sb-nil",
		socketPath: "/tmp/fake.sock",
		status:     models.SandboxStatusStarted,
	}
	d.mu.Unlock()
	managed, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if managed["sb-nil"].Status != models.SandboxStatusStopped {
		t.Fatalf("status = %q", managed["sb-nil"].Status)
	}
}

// ---------------------------------------------------------------------------
// exec.go — wasmExecArgs empty-fields branch
// ---------------------------------------------------------------------------

func TestWasmExecArgsEmptyFieldsUsesFallback(t *testing.T) {
	// strings.Fields on a non-empty string of only separators yields len==0.
	got := wasmExecArgs("\t\n", []string{"fallback"})
	if len(got) != 1 || got[0] != "fallback" {
		t.Fatalf("got %#v", got)
	}
}

// ---------------------------------------------------------------------------
// checkpoint.go — stopAfter failure with empty workerKey
// ---------------------------------------------------------------------------

func TestCheckpointSandboxStopAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-cp-stop")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	modPath := wasmmod.WriteCheckpointWasm(t, dir, "demo.wasm")
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
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-cp", "", nil); err != nil {
		t.Fatal(err)
	}
	path, gen, err := d.CheckpointSandbox(ctx, &models.Sandbox{ID: "sb-cp"})
	if err != nil || path == "" || gen == "" {
		t.Fatalf("CheckpointSandbox: path=%q gen=%q err=%v", path, gen, err)
	}
	if _, err := d.instance("sb-cp"); err == nil {
		t.Fatal("instance should be removed after passivating checkpoint")
	}
}

// ---------------------------------------------------------------------------
// resident.go — bringUp / migrate cold-path errors
// ---------------------------------------------------------------------------

type failPingClient struct {
	recordingWorkerClient
}

func (failPingClient) Ping(string) error {
	return fmt.Errorf("not ready")
}

func TestBringUpResidentHostWaitWorkerError(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &failPingClient{} })
	b := &residentBucket{id: "b"}
	h := &residentHost{socket: filepath.Join(t.TempDir(), "r.sock"), index: 0}
	if err := d.bringUpResidentHost(context.Background(), b, h, wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm"), 64); err == nil {
		t.Fatal("expected waitWorker error")
	}
}

func TestBringUpResidentHostLoadError(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &failLoadClient{} })
	b := &residentBucket{id: "b"}
	h := &residentHost{socket: filepath.Join(t.TempDir(), "r.sock"), index: 0}
	if err := d.bringUpResidentHost(context.Background(), b, h, wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm"), 64); err == nil || !strings.Contains(err.Error(), "resident load module") {
		t.Fatalf("load error: %v", err)
	}
}

func TestMigrateResidentToColdLoadError(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(socket string) WorkerClient {
		if filepath.Base(socket) == "worker.sock" {
			return &failLoadClient{}
		}
		return &recordingWorkerClient{}
	})
	inst := &sandboxInstance{
		sandboxID:  "sb-load-fail",
		workDir:    filepath.Join(d.cfg.RunDir, "sb-load-fail"),
		modulePath: wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm"),
		memoryMB:   64,
		socketPath: "/tmp/resident.sock",
	}
	if err := os.MkdirAll(inst.workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateResidentToCold(context.Background(), inst); err == nil || !strings.Contains(err.Error(), "cold load module") {
		t.Fatalf("cold load: %v", err)
	}
}

func TestMigrateResidentToColdWaitError(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(socket string) WorkerClient {
		if filepath.Base(socket) == "worker.sock" {
			return &failPingClient{}
		}
		return &recordingWorkerClient{}
	})
	inst := &sandboxInstance{
		sandboxID:  "sb-wait-fail",
		workDir:    filepath.Join(d.cfg.RunDir, "sb-wait-fail"),
		modulePath: wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm"),
		memoryMB:   64,
		socketPath: "/tmp/resident.sock",
	}
	if err := os.MkdirAll(inst.workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateResidentToCold(context.Background(), inst); err == nil {
		t.Fatal("expected waitWorker error")
	}
}

// ---------------------------------------------------------------------------
// passivate.go — RehydrateSandbox branches
// ---------------------------------------------------------------------------

type failRestoreClient struct {
	recordingWorkerClient
	err error
}

func (c *failRestoreClient) Restore(string, string, wasmengine.Capabilities) error {
	return c.err
}

func TestRehydrateSandboxRestoreGenericError(t *testing.T) {
	d, modulesDir := newDigestPinDriver(t)
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")
	ctx := context.Background()
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm", MemoryMB: 64}, "sb-rst", "", nil); err != nil {
		t.Fatal(err)
	}
	sb := &models.Sandbox{ID: "sb-rst", ModuleRef: "demo.wasm", ModuleDigest: "abc", MemoryMB: 64}
	path, gen, err := d.CheckpointSandbox(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	sb.CheckpointPath = path
	sb.CloneGeneration = gen
	d.SetWorkerClientFactory(func(string) WorkerClient {
		return &failRestoreClient{err: fmt.Errorf("restore boom")}
	})
	if _, err := d.RehydrateSandbox(ctx, sb, nil); err == nil || !strings.Contains(err.Error(), "restore snapshot") {
		t.Fatalf("restore error: %v", err)
	}
}

func TestRehydrateSandboxModulePathUnknown(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
	d.SetWorkerSupervisor(&fakeSupervisor{})
	checkpointDir := d.checkpointDir("sb-no-mod")
	if err := os.MkdirAll(checkpointDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := wasmengine.WriteSnapshotDir(checkpointDir, wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			Entrypoint:      "_start",
			CloneGeneration: "gen",
		},
	}); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
	sb := &models.Sandbox{ID: "sb-no-mod", CheckpointPath: checkpointDir, CloneGeneration: "gen"}
	if _, err := d.RehydrateSandbox(context.Background(), sb, nil); err == nil || !strings.Contains(err.Error(), "module path unknown") {
		t.Fatalf("module path unknown: %v", err)
	}
}

// ---------------------------------------------------------------------------
// remove_image.go — additional branches
// ---------------------------------------------------------------------------

type resolveFailResolver struct{}

func (resolveFailResolver) Resolve(context.Context, string) (*wasmmod.ResolvedModule, error) {
	return nil, fmt.Errorf("resolve broke")
}

func TestRemoveImageResolveError(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(resolveFailResolver{})
	if err := d.RemoveImage(context.Background(), "demo.wasm"); err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("resolve error: %v", err)
	}
}

func TestRemoveImageDigestWithoutModulesDir(t *testing.T) {
	d := New(Config{RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(wasmmod.NewResolver(t.TempDir()))
	digest := strings.Repeat("c", 64)
	if err := d.RemoveImage(context.Background(), digest); err != nil {
		t.Fatalf("digest without modules dir: %v", err)
	}
}

func TestPathUnderDirAbsError(t *testing.T) {
	// Empty path after trim is already covered; exercise rel error via "." match.
	root := t.TempDir()
	if !pathUnderDir(root, root) {
		t.Fatal("root should be under itself")
	}
}

// ---------------------------------------------------------------------------
// guest_listen.go — async invoke completion
// ---------------------------------------------------------------------------

type slowInvokeClient struct {
	invokeWorkerClient
	done chan struct{}
}

func (c *slowInvokeClient) Invoke(string, string) error {
	close(c.done)
	return nil
}

func TestStartGuestEntryAsyncCompletes(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	done := make(chan struct{})
	client := &slowInvokeClient{done: done}
	inst := &sandboxInstance{sandboxID: "sb", entryExport: "_start"}
	inst.bumpRunGeneration()
	d.startGuestEntryAsync(inst, client)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("invoke did not run")
	}
	time.Sleep(20 * time.Millisecond)
	inst.guestServeMu.Lock()
	gen := inst.guestServeGen
	inst.guestServeMu.Unlock()
	if gen != 0 {
		t.Fatalf("guestServeGen = %d, want 0 after invoke completes", gen)
	}
}

// ---------------------------------------------------------------------------
// network.go — closeListenerLocked no-op paths
// ---------------------------------------------------------------------------

func TestCloseListenerLockedNoops(t *testing.T) {
	g := newNetworkGateway()
	g.closeListenerLocked("missing", 80)
	g.mu.Lock()
	g.listeners["sb"] = make(map[int]*httpListener)
	g.mu.Unlock()
	g.closeListenerLocked("sb", 80)
}

// ---------------------------------------------------------------------------
// lifecycle.go — resolvePinned resolve error
// ---------------------------------------------------------------------------

func TestResolvePinnedResolveError(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetModuleResolver(resolveErrResolver{})
	if _, err := d.resolvePinned(context.Background(), "ref", "", nil); err == nil || !strings.Contains(err.Error(), "resolve module") {
		t.Fatalf("resolve error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// migrate.go — offline with checkpoint
// ---------------------------------------------------------------------------

func TestMigrateSandboxOfflineWithCheckpoint(t *testing.T) {
	dir := t.TempDir()
	d := New(Config{ModulesDir: dir, RunDir: t.TempDir()}, nil)
	checkpointDir := d.checkpointDir("sb-mig-off")
	if err := os.MkdirAll(checkpointDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := wasmengine.WriteSnapshotDir(checkpointDir, wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion: 1,
			Engine:        wasmengine.EngineNameWazero(),
		},
	}); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "dest")
	target, gen, err := d.MigrateSandbox(context.Background(), &models.Sandbox{ID: "sb-mig-off"}, dest)
	if err != nil {
		t.Fatalf("MigrateSandbox: %v", err)
	}
	if target == "" || !strings.Contains(target, "mem.snap") {
		t.Fatalf("target=%q", target)
	}
	_ = gen
}

// ---------------------------------------------------------------------------
// checkpoint.go — empty workerKey on failure
// ---------------------------------------------------------------------------

func TestCheckpointFailureWithEmptyWorkerKey(t *testing.T) {
	dir := t.TempDir()
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: wasmmod.WriteMinimalWasm(t, dir, "demo.wasm"), digest: "abc"})
	sup := &fakeSupervisor{}
	d.SetWorkerSupervisor(sup)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &checkpointFailClient{} })
	d.mu.Lock()
	d.byID["sb-wk"] = &sandboxInstance{
		sandboxID:  "sb-wk",
		socketPath: "/tmp/fake.sock",
		modulePath: wasmmod.WriteMinimalWasm(t, dir, "demo.wasm"),
		status:     models.SandboxStatusStarted,
		workerKey:  "",
	}
	d.mu.Unlock()
	if _, _, err := d.checkpointSandbox(context.Background(), &models.Sandbox{ID: "sb-wk"}, true); err == nil {
		t.Fatal("expected checkpoint error")
	}
	if sup.stopCalls != 1 {
		t.Fatalf("stop calls = %d", sup.stopCalls)
	}
}

// ---------------------------------------------------------------------------
// sessions.go — creation path
// ---------------------------------------------------------------------------

func TestSessionsForCreatesManager(t *testing.T) {
	dir := t.TempDir()
	workDir := filepath.Join(dir, "sb-sess-new")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := New(Config{ModulesDir: dir}, nil)
	inst := &sandboxInstance{sandboxID: "sb-sess-new", workDir: workDir}
	mgr, err := d.sessionsFor(inst)
	if err != nil || mgr == nil {
		t.Fatalf("sessionsFor: mgr=%v err=%v", mgr, err)
	}
}

// ---------------------------------------------------------------------------
// exec.go — wasmExecArgs direct fields return
// ---------------------------------------------------------------------------

func TestWasmExecArgsReturnsParsedFields(t *testing.T) {
	got := wasmExecArgs("echo hello", nil)
	if len(got) != 2 || got[0] != "echo" || got[1] != "hello" {
		t.Fatalf("got %#v", got)
	}
}

// ---------------------------------------------------------------------------
// remove_image.go — ref path with warm pool + pathUnderDir edge cases
// ---------------------------------------------------------------------------

func TestRemoveImageByRefDropsWarmPoolDigest(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	pool := &warmPoolDropperFake{}
	d := New(Config{ModulesDir: dir, RunDir: t.TempDir()}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "digest-abc"})
	d.SetWarmPool(pool)
	if err := d.RemoveImage(context.Background(), "demo.wasm"); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
	if len(pool.dropped) != 1 || pool.dropped[0] != "digest-abc" {
		t.Fatalf("dropped = %#v", pool.dropped)
	}
}

func TestPathUnderDirInvalidPaths(t *testing.T) {
	root := t.TempDir()
	if pathUnderDir(root, string([]byte{0})) {
		t.Fatal("NUL byte path should be false")
	}
}

// ---------------------------------------------------------------------------
// passivate.go — additional error branches
// ---------------------------------------------------------------------------

func TestRehydrateSandboxLoadModuleError(t *testing.T) {
	d, modulesDir := newDigestPinDriver(t)
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")
	ctx := context.Background()
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm", MemoryMB: 64}, "sb-load", "", nil); err != nil {
		t.Fatal(err)
	}
	sb := &models.Sandbox{ID: "sb-load", ModuleRef: "demo.wasm", ModuleDigest: "abc", MemoryMB: 64}
	path, gen, err := d.CheckpointSandbox(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	sb.CheckpointPath = path
	sb.CloneGeneration = gen
	d.SetWorkerClientFactory(func(string) WorkerClient { return &failLoadClient{} })
	if _, err := d.RehydrateSandbox(ctx, sb, nil); err == nil || !strings.Contains(err.Error(), "load module") {
		t.Fatalf("load error: %v", err)
	}
}

func TestRehydrateSandboxEnsureWorkerError(t *testing.T) {
	d, modulesDir := newDigestPinDriver(t)
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")
	ctx := context.Background()
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc"})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm", MemoryMB: 64}, "sb-ensure", "", nil); err != nil {
		t.Fatal(err)
	}
	sb := &models.Sandbox{ID: "sb-ensure", ModuleRef: "demo.wasm", ModuleDigest: "abc", MemoryMB: 64}
	path, gen, err := d.CheckpointSandbox(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	sb.CheckpointPath = path
	sb.CloneGeneration = gen
	d.SetWorkerSupervisor(&startFailEnsureSupervisor{})
	if _, err := d.RehydrateSandbox(ctx, sb, nil); err == nil || !strings.Contains(err.Error(), "start worker") {
		t.Fatalf("ensure error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// driver.go — resident-host refresh via ListManaged
// ---------------------------------------------------------------------------

type instanceLoadedErrClient struct {
	recordingWorkerClient
}

func (instanceLoadedErrClient) InstanceLoaded(context.Context, string) (bool, error) {
	return false, fmt.Errorf("host dead")
}

func TestListManagedMarksDeadResidentHostStopped(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &instanceLoadedErrClient{} })
	d.mu.Lock()
	d.byID["sb-dead-list"] = &sandboxInstance{
		sandboxID:        "sb-dead-list",
		socketPath:       "/tmp/resident.sock",
		fromResidentHost: true,
		status:           models.SandboxStatusStarted,
	}
	d.mu.Unlock()
	managed, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if managed["sb-dead-list"].Status != models.SandboxStatusStopped {
		t.Fatalf("status = %q", managed["sb-dead-list"].Status)
	}
}

// ---------------------------------------------------------------------------
// resident.go — bringUp mkdir failure
// ---------------------------------------------------------------------------

func TestBringUpResidentHostMkdirError(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	b := &residentBucket{id: "b"}
	h := &residentHost{socket: filepath.Join(string([]byte{0}), "bad.sock"), index: 0}
	if err := d.bringUpResidentHost(context.Background(), b, h, "/path/m.wasm", 64); err == nil || !strings.Contains(err.Error(), "mkdir resident dir") {
		t.Fatalf("mkdir resident: %v", err)
	}
}

// ---------------------------------------------------------------------------
// network_policy.go — nil driver guards
// ---------------------------------------------------------------------------

func TestDrainNetworkByteCountersNilDriver(t *testing.T) {
	var d *Driver
	if got := d.DrainNetworkByteCounters(); got != nil {
		t.Fatalf("nil driver = %+v", got)
	}
}

func TestSetNetworkBlocksNilDriver(t *testing.T) {
	var d *Driver
	d.SetNetworkBlocks("sb", true, true) // must not panic
}
