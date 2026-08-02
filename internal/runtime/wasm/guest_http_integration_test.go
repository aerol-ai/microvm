package wasm

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

type recordingProxyWorkerClient struct {
	recordingWorkerClient
	proxyCalls int
	lastPort   int
}

func (c *recordingProxyWorkerClient) ProxyHTTP(_ string, guestPort int, w http.ResponseWriter, _ *http.Request) error {
	c.proxyCalls++
	c.lastPort = guestPort
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("via-worker"))
	return nil
}

func (c *recordingProxyWorkerClient) SetListenPort(string, int, string) error { return nil }
func (c *recordingProxyWorkerClient) ResolvedListenPort(string) (int, error) {
	return 18080, nil
}

func TestDriverHTTPGatewayInvokesWorkerProxy(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	proxyClient := &recordingProxyWorkerClient{}
	d.newWorkerClient = func(string) WorkerClient { return proxyClient }
	d.mu.Lock()
	d.byID["sb-proxy"] = &sandboxInstance{
		sandboxID:  "sb-proxy",
		socketPath: "/tmp/fake.sock",
		status:     models.SandboxStatusStarted,
	}
	d.mu.Unlock()

	ctx := context.Background()
	dial, err := d.EnsureHTTPListener(ctx, "sb-proxy", 8080)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}
	d.SyncAllowedPorts("sb-proxy", []int{8080})

	resp, err := http.Get("http://" + dial + "/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if string(body) != "via-worker" {
		t.Fatalf("body=%q", body)
	}
	if proxyClient.proxyCalls != 1 || proxyClient.lastPort != 8080 {
		t.Fatalf("proxy calls=%d port=%d", proxyClient.proxyCalls, proxyClient.lastPort)
	}
}

func TestSyncGuestListenPortsUsesLowestPort(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.waitListenReady = func(string, int) error { return nil }
	listenClient := &listenPortRecordingClient{}
	d.newWorkerClient = func(string) WorkerClient { return listenClient }
	d.mu.Lock()
	d.byID["sb-listen"] = &sandboxInstance{
		sandboxID:  "sb-listen",
		socketPath: "/tmp/fake.sock",
		status:     models.SandboxStatusStarted,
	}
	d.mu.Unlock()

	if err := d.SyncGuestListenPorts(context.Background(), "sb-listen", []int{9000, 8080, 8443}); err != nil {
		t.Fatalf("SyncGuestListenPorts: %v", err)
	}
	if listenClient.port != 0 {
		t.Fatalf("listen port = %d, want ephemeral 0", listenClient.port)
	}
	if err := d.SyncGuestListenPorts(context.Background(), "sb-listen", nil); err != nil {
		t.Fatalf("disable listen: %v", err)
	}
	if listenClient.port != wasmengine.WASIListenPortDisabled {
		t.Fatalf("listen port = %d, want disabled", listenClient.port)
	}
}

type listenPortRecordingClient struct {
	recordingWorkerClient
	port int
	host string
}

func (c *listenPortRecordingClient) SetListenPort(_ string, port int, host string) error {
	c.port = port
	c.host = host
	return nil
}

func (c *listenPortRecordingClient) ResolvedListenPort(string) (int, error) {
	return 18080, nil
}

func TestWorkerClientWasip1HTTPBaseline(t *testing.T) {
	absMod := ensureWasip1HTTPWasm(t)

	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-http-baseline")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	driver := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 64}, nil)
	driver.SetWorkerSupervisor(sup)

	ctx := context.Background()
	sandboxID := "sb-baseline"
	workDir := filepath.Join(runDir, sandboxID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(workDir, "worker.sock")
	if err := sup.Ensure(ctx, sandboxID, sock); err != nil {
		t.Fatal(err)
	}
	wc := driver.newWorkerClient(sock)
	if _, err := wc.LoadModule(sandboxID, absMod, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	caps := wasmengine.Capabilities{
		WASIListenPort: 0,
		WASIListenHost: "127.0.0.1",
		Args:           []string{"wasi", "http"},
	}
	if err := wc.Instantiate(sandboxID, caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	go func() { _ = wc.Invoke(sandboxID, "_start") }()
	time.Sleep(200 * time.Millisecond)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "http://guest/", bytes.NewReader([]byte("wazero")))
	if err := wc.ProxyHTTP(sandboxID, 0, rec, req); err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSetListenPortAfterColdInstantiate(t *testing.T) {
	absMod := ensureWasip1HTTPWasm(t)
	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-http-setlisten")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	driver := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 64}, nil)
	driver.SetWorkerSupervisor(sup)
	ctx := context.Background()
	sandboxID := "sb-setlisten"
	workDir := filepath.Join(runDir, sandboxID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(workDir, "worker.sock")
	if err := sup.Ensure(ctx, sandboxID, sock); err != nil {
		t.Fatal(err)
	}
	wc := driver.newWorkerClient(sock)
	if _, err := wc.LoadModule(sandboxID, absMod, 0); err != nil {
		t.Fatal(err)
	}
	cold := wasmengine.Capabilities{
		Args:           []string{"wasi", "http"},
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}
	if err := wc.Instantiate(sandboxID, cold); err != nil {
		t.Fatalf("cold Instantiate: %v", err)
	}
	if err := wc.SetListenPort(sandboxID, 0, "127.0.0.1"); err != nil {
		t.Fatalf("SetListenPort: %v", err)
	}
	go func() { _ = wc.Invoke(sandboxID, "_start") }()
	time.Sleep(300 * time.Millisecond)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "http://guest/", bytes.NewReader([]byte("wazero")))
	if err := wc.ProxyHTTP(sandboxID, 0, rec, req); err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestDriverWasip1HTTPExposeEndToEnd(t *testing.T) {
	absMod := ensureWasip1HTTPWasm(t)

	dir := t.TempDir()
	runDir := filepath.Join(os.TempDir(), "aw-http-e2e")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})

	driver := New(Config{RunDir: runDir, ModulesDir: dir, DefaultMemoryMB: 64}, nil)
	driver.SetModuleResolver(fakeResolver{path: absMod, digest: "wasip1-http"})
	driver.SetWorkerSupervisor(sup)

	ctx := context.Background()
	sandboxID := "sb-http-e2e"
	createReq := models.CreateSandboxRequest{
		Image:            "wasip1-http.wasm",
		ContainerCommand: []string{"wasi", "http"},
	}
	if _, err := driver.Create(ctx, createReq, sandboxID, "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := driver.SyncGuestListenPorts(ctx, sandboxID, []int{8080}); err != nil {
		t.Fatalf("SyncGuestListenPorts: %v", err)
	}
	inst, err := driver.instance(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if inst.resolvedListenPort <= 0 {
		t.Fatalf("resolved listen port = %d", inst.resolvedListenPort)
	}

	driver.SyncAllowedPorts(sandboxID, []int{8080})

	// wazero test guest serves exactly one HTTP request per _start; exercise worker proxy first.
	wc := driver.newWorkerClient(inst.socketPath)
	directReq, err := http.NewRequest(http.MethodPost, "http://guest/", bytes.NewReader([]byte("wazero")))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := wc.ProxyHTTP(sandboxID, 0, rec, directReq); err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "wazero\n" {
		t.Fatalf("direct proxy status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestWasmMigrateLiveTwoNodeWorkers(t *testing.T) {
	dir := t.TempDir()
	runDirA := filepath.Join(os.TempDir(), "aw-migrate-a")
	runDirB := filepath.Join(os.TempDir(), "aw-migrate-b")
	t.Cleanup(func() {
		_ = os.RemoveAll(runDirA)
		_ = os.RemoveAll(runDirB)
	})
	modulesDir := filepath.Join(dir, "modules")
	if err := os.MkdirAll(modulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")

	supA := newInProcessSupervisor()
	supB := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range supA.workers {
			_ = supA.Stop(id)
		}
		for id := range supB.workers {
			_ = supB.Stop(id)
		}
	})

	driverA := New(Config{RunDir: runDirA, ModulesDir: modulesDir, DefaultMemoryMB: 64}, nil)
	driverA.SetModuleResolver(fakeResolver{path: modPath, digest: "abc123"})
	driverA.SetWorkerSupervisor(supA)

	driverB := New(Config{RunDir: runDirB, ModulesDir: modulesDir, DefaultMemoryMB: 64}, nil)
	driverB.SetModuleResolver(fakeResolver{path: modPath, digest: "abc123"})
	driverB.SetWorkerSupervisor(supB)

	sandboxID := "sb-migrate-live"
	ctx := context.Background()
	createReq := models.CreateSandboxRequest{
		Image:      "demo.wasm",
		Durability: models.DurabilityPassivatable,
		MemoryMB:   64,
	}
	if _, err := driverA.Create(ctx, createReq, sandboxID, "", nil); err != nil {
		t.Fatalf("Create on node A: %v", err)
	}

	sb := &models.Sandbox{
		ID:           sandboxID,
		Durability:   models.DurabilityPassivatable,
		ModuleRef:    "demo.wasm",
		ModuleDigest: "abc123",
		MemoryMB:     64,
	}
	checkpointPath, cloneGen, err := driverA.MigrateSandbox(ctx, sb, filepath.Join(dir, "handoff"))
	if err != nil {
		t.Fatalf("MigrateSandbox: %v", err)
	}
	if checkpointPath == "" || cloneGen == "" {
		t.Fatalf("checkpoint=%q gen=%q", checkpointPath, cloneGen)
	}

	destCheckpoint := driverB.checkpointDir(sandboxID)
	if err := os.MkdirAll(filepath.Dir(destCheckpoint), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(checkpointPath, destCheckpoint); err != nil {
		t.Fatalf("copy checkpoint: %v", err)
	}

	sb.Status = models.SandboxStatusPassivated
	sb.CheckpointPath = destCheckpoint
	sb.CloneGeneration = cloneGen
	state, err := driverB.RehydrateSandbox(ctx, sb, nil)
	if err != nil {
		t.Fatalf("RehydrateSandbox on node B: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q", state.Status)
	}

	managed, err := driverB.ListManaged(ctx)
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(managed) != 1 {
		t.Fatalf("managed count = %d", len(managed))
	}

	inst, err := driverB.instance(sandboxID)
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	client := driverB.newWorkerClient(inst.socketPath)
	run, err := client.Exec(sandboxID, wasmengine.Capabilities{Args: []string{"post-migrate"}}, "_start")
	if err != nil {
		t.Fatalf("Exec after migrate: %v", err)
	}
	if run.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", run.ExitCode, run.Stderr)
	}

	managedA, err := driverA.ListManaged(ctx)
	if err != nil {
		t.Fatalf("ListManaged A: %v", err)
	}
	if len(managedA) != 0 {
		t.Fatalf("node A still has %d live instances after migrate", len(managedA))
	}
}
