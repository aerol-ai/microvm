package wasm

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/pkg/hostproc"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// heldProc is a worker process a test holds.
type heldProc struct {
	pid     int
	mu      sync.Mutex
	stopped bool
}

func (p *heldProc) Pid() int                    { return p.pid }
func (p *heldProc) Signal(syscall.Signal) error { return nil }
func (p *heldProc) Done() <-chan struct{}       { return make(chan struct{}) }
func (p *heldProc) Close() error                { return nil }
func (p *heldProc) wasStopped() bool            { p.mu.Lock(); defer p.mu.Unlock(); return p.stopped }
func (p *heldProc) markStopped()                { p.mu.Lock(); p.stopped = true; p.mu.Unlock() }

var _ hostproc.Process = (*heldProc)(nil)

// adoptingSupervisor is a supervisor that can adopt and says whether its
// workers survive.
type adoptingSupervisor struct {
	fakeSupervisor
	survives  bool
	refuse    bool
	adopted   map[string]string // key -> socket
	stoppedKs []string
}

func (s *adoptingSupervisor) Adopt(key, socket string, _ hostproc.Process) bool {
	if s.refuse {
		return false
	}
	if s.adopted == nil {
		s.adopted = map[string]string{}
	}
	s.adopted[key] = socket
	return true
}
func (s *adoptingSupervisor) Survives() bool { return s.survives }
func (s *adoptingSupervisor) Stop(key string) error {
	s.stoppedKs = append(s.stoppedKs, key)
	return s.fakeSupervisor.Stop(key)
}
func (s *adoptingSupervisor) SpawnCount(key string) int {
	if _, ok := s.adopted[key]; ok {
		return 1
	}
	return 0
}

// socketClient answers InstanceLoaded per socket and sandbox.
type socketClient struct {
	recordingWorkerClient
	loaded  map[string]bool // "socket|sandbox" -> loaded; "socket|" for a host
	err     error
	setPort int
}

func (c *socketClient) InstanceLoaded(_ context.Context, id string) (bool, error) {
	return c.loaded[id], c.err
}
func (c *socketClient) SetListenPort(string, int, string) error { c.setPort++; return nil }

// adoptDriver is a driver with stand-ins for both supervisors and a client
// factory keyed by socket.
func adoptDriver(t *testing.T, resident bool) (*Driver, *adoptingSupervisor, *adoptingSupervisor, map[string]*socketClient) {
	t.Helper()
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := New(Config{RunDir: runDir, ModulesDir: dir, ResidentHostEnabled: resident, DefaultMemoryMB: 128}, slog.New(slog.NewTextHandler(new(bytes.Buffer), nil)))
	per := &adoptingSupervisor{}
	res := &adoptingSupervisor{}
	d.SetWorkerSupervisor(per)
	d.SetResidentHostSupervisor(res)
	clients := map[string]*socketClient{}
	d.SetWorkerClientFactory(func(sock string) WorkerClient {
		c := clients[sock]
		if c == nil {
			c = &socketClient{loaded: map[string]bool{}}
			clients[sock] = c
		}
		return c
	})
	d.SetWorkerCgroup(hostproc.NewCgroup(nil, dir, "aerolvm-wasm", "WASM workers"))
	return d, per, res, clients
}

// withFound stands in the workers FindWorkers returns and records stops.
func withFound(t *testing.T, found []worker.FoundWorker, err error) {
	t.Helper()
	oldFind, oldStop := findWorkers, stopProcess
	t.Cleanup(func() { findWorkers, stopProcess = oldFind, oldStop })
	findWorkers = func(*hostproc.Cgroup) ([]worker.FoundWorker, error) { return found, err }
	stopProcess = func(p hostproc.Process) {
		if hp, ok := p.(*heldProc); ok {
			hp.markStopped()
		}
	}
}

func TestInstanceRecordRoundTrip(t *testing.T) {
	d, _, _, _ := adoptDriver(t, true)
	inst := &sandboxInstance{sandboxID: "sb-r", socketPath: "/run/x.sock", workerKey: "k", fromResidentHost: true,
		moduleRef: "python", modulePath: "/m.wasm", moduleDigest: "dd", entryExport: "_start", memoryMB: 64, resolvedListenPort: 31000}
	if _, ok := d.readInstanceRecord("sb-r"); ok {
		t.Fatal("record read before one was written")
	}
	// No work dir yet: the write fails and is only logged.
	d.recordInstance(inst)
	if err := os.MkdirAll(d.sandboxDir("sb-r"), 0o700); err != nil {
		t.Fatal(err)
	}
	d.recordInstance(inst)
	rec, ok := d.readInstanceRecord("sb-r")
	if !ok || rec.Socket != "/run/x.sock" || !rec.Resident || rec.ListenPort != 31000 || rec.MemoryMB != 64 {
		t.Fatalf("record = %+v, %v", rec, ok)
	}
	// A record that names another sandbox is not this one's.
	if err := os.WriteFile(d.instanceRecordPath("sb-r"), []byte(`{"sandbox_id":"other","socket":"/x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.readInstanceRecord("sb-r"); ok {
		t.Fatal("foreign record accepted")
	}
	(&Driver{}).recordInstance(inst) // no run dir: no-op
	d.recordInstance(nil)
	if err := writeFileAtomic(filepath.Join(t.TempDir(), "x.json"), func() {}); err == nil {
		t.Fatal("unencodable record written")
	}
}

func TestParseResidentSocket(t *testing.T) {
	run := "/run/sandboxd/wasm"
	cases := []struct {
		sock   string
		bucket string
		index  int
		ok     bool
	}{
		{run + "/resident/0123456789abcdef-256mb.sock", "0123456789abcdef-256mb", 0, true},
		{run + "/resident/0123456789abcdef-256mb-2.sock", "0123456789abcdef-256mb", 1, true},
		{run + "/resident/o0123456789abcdef-fedcba9876543210-64mb-3.sock", "o0123456789abcdef-fedcba9876543210-64mb", 2, true},
		{run + "/resident/0123456789abcdef-256mb-1.sock", "", 0, false},
		{run + "/resident/../x-256mb.sock", "", 0, false},
		{run + "/other/0123456789abcdef-256mb.sock", "", 0, false},
		{run + "/resident/nothex-256mb.sock", "", 0, false},
	}
	for _, tc := range cases {
		b, i, ok := parseResidentSocket(run, tc.sock)
		if ok != tc.ok || b != tc.bucket || i != tc.index {
			t.Errorf("parseResidentSocket(%q) = %q, %d, %v; want %q, %d, %v", tc.sock, b, i, ok, tc.bucket, tc.index, tc.ok)
		}
	}
	// Round trip with the path the driver gives a host.
	d := New(Config{RunDir: run}, nil)
	id := residentBucketID("owner", "digest", 128)
	for _, idx := range []int{0, 1, 4} {
		b, i, ok := parseResidentSocket(run, d.residentSocketPath(id, idx))
		if !ok || b != id || i != idx {
			t.Fatalf("round trip index %d = %q, %d, %v", idx, b, i, ok)
		}
	}
}

// TestAdoptWorkersSortsWhatItFinds: a healthy resident host joins its
// bucket, a per-sandbox worker waits for its sandbox, and everything else
// is stopped.
func TestAdoptWorkersSortsWhatItFinds(t *testing.T) {
	d, _, res, clients := adoptDriver(t, true)
	bucket := residentBucketID("", "dig", 128)
	good := d.residentSocketPath(bucket, 1)
	sick := d.residentSocketPath(residentBucketID("", "sick", 128), 0)
	clients[good] = &socketClient{loaded: map[string]bool{"": true}}
	clients[sick] = &socketClient{loaded: map[string]bool{"": false}}
	procs := map[string]*heldProc{}
	mk := func(name string, pid int) *heldProc { p := &heldProc{pid: pid}; procs[name] = p; return p }
	perSock := filepath.Join(d.cfg.RunDir, "sb-a", "worker.sock")
	withFound(t, []worker.FoundWorker{
		{PID: 1, Proc: mk("stray", 1)},
		{PID: 2, Resident: true, Socket: good, Proc: mk("good", 2)},
		{PID: 3, Resident: true, Socket: sick, Proc: mk("sick", 3)},
		{PID: 4, Resident: true, Socket: "/elsewhere/x.sock", Proc: mk("badname", 4)},
		{PID: 5, Socket: perSock, Proc: mk("per", 5)},
		{PID: 6, Socket: "/tmp/outside.sock", Proc: mk("outside", 6)},
	}, nil)
	report := d.AdoptWorkers(context.Background())
	if report.ResidentHosts != 1 || report.Workers != 1 || report.Stopped != 4 {
		t.Fatalf("report = %+v", report)
	}
	for name, want := range map[string]bool{"stray": true, "good": false, "sick": true, "badname": true, "per": false, "outside": true} {
		if procs[name].wasStopped() != want {
			t.Errorf("%s stopped = %v, want %v", name, procs[name].wasStopped(), want)
		}
	}
	if res.adopted[d.residentHostKey(bucket, 1)] != good {
		t.Fatalf("resident supervisor adopted %v", res.adopted)
	}
	b, h := d.residentHostBySocket(good)
	if h == nil || !h.ready || h.index != 1 || b.nextIndex != 2 {
		t.Fatalf("adopted host %+v in bucket next=%d", h, b.nextIndex)
	}
	// A create into this bucket reuses the adopted host: no new process.
	if stats := d.ResidentHostStats(); stats.Hosts != 1 || stats.Instances != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if n := d.FinishAdoption(); n != 1 || !procs["per"].wasStopped() {
		t.Fatalf("FinishAdoption stopped %d (per stopped=%v)", n, procs["per"].wasStopped())
	}
	if d.FinishAdoption() != 0 {
		t.Fatal("second FinishAdoption stopped more")
	}
}

func TestAdoptWorkersOffAndErrors(t *testing.T) {
	d := New(Config{RunDir: t.TempDir()}, nil)
	if r := d.AdoptWorkers(context.Background()); r != (AdoptReport{}) {
		t.Fatalf("no cgroup: %+v", r)
	}
	d2, _, _, _ := adoptDriver(t, true)
	withFound(t, nil, errors.New("cgroup unreadable"))
	if r := d2.AdoptWorkers(context.Background()); r != (AdoptReport{}) {
		t.Fatalf("unreadable cgroup: %+v", r)
	}
	// Resident hosts off: a leftover resident host is stopped.
	d3, _, _, clients := adoptDriver(t, false)
	sock := d3.residentSocketPath(residentBucketID("", "x", 128), 0)
	clients[sock] = &socketClient{loaded: map[string]bool{"": true}}
	p := &heldProc{pid: 9}
	withFound(t, []worker.FoundWorker{{PID: 9, Resident: true, Socket: sock, Proc: p}}, nil)
	if r := d3.AdoptWorkers(context.Background()); r.Stopped != 1 || !p.wasStopped() {
		t.Fatalf("resident off: %+v stopped=%v", r, p.wasStopped())
	}
	// The resident supervisor refuses: the host is stopped.
	d4, _, res, clients4 := adoptDriver(t, true)
	res.refuse = true
	sock4 := d4.residentSocketPath(residentBucketID("", "y", 128), 0)
	clients4[sock4] = &socketClient{loaded: map[string]bool{"": true}}
	p4 := &heldProc{pid: 10}
	withFound(t, []worker.FoundWorker{{PID: 10, Resident: true, Socket: sock4, Proc: p4}}, nil)
	if r := d4.AdoptWorkers(context.Background()); r.Stopped != 1 || !p4.wasStopped() {
		t.Fatalf("refused: %+v", r)
	}
}

// TestAdoptSandboxOnResidentHost: a started sandbox whose record names a
// live resident host is taken over with its slot held, and Destroy later
// removes just its instance.
func TestAdoptSandboxOnResidentHost(t *testing.T) {
	d, _, res, clients := adoptDriver(t, true)
	bucket := residentBucketID("", "dig", 128)
	sock := d.residentSocketPath(bucket, 0)
	clients[sock] = &socketClient{loaded: map[string]bool{"": true, "sb-1": true}}
	withFound(t, []worker.FoundWorker{{PID: 2, Resident: true, Socket: sock, Proc: &heldProc{pid: 2}}}, nil)
	d.AdoptWorkers(context.Background())

	sb := &models.Sandbox{ID: "sb-1", ModuleRef: "python", ModuleDigest: "dig", MemoryMB: 128, Env: map[string]string{"A": "1"},
		NetworkBlockAll: true, Durability: models.DurabilityPassivatable}
	if _, err := d.AdoptSandbox(context.Background(), sb, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("adopt without a record = %v", err)
	}
	if err := os.MkdirAll(d.sandboxDir("sb-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	d.recordInstance(&sandboxInstance{sandboxID: "sb-1", socketPath: sock, workerKey: bucket, fromResidentHost: true,
		moduleRef: "python", modulePath: "/m.wasm", moduleDigest: "dig", memoryMB: 128})
	state, err := d.AdoptSandbox(context.Background(), sb, []mounts.ContainerBind{{HostPath: "/h", ContainerPath: "/data"}})
	if err != nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("AdoptSandbox = %+v, %v", state, err)
	}
	inst, _ := d.instance("sb-1")
	if !inst.fromResidentHost || !inst.residentSlotHeld || inst.baseEnv["A"] != "1" || len(inst.preopens) != 2 {
		t.Fatalf("adopted instance = %+v", inst)
	}
	if in, out := d.net.blocksFor("sb-1"); !in || !out {
		t.Fatal("network block from the row not restored")
	}
	if stats := d.ResidentHostStats(); stats.Instances != 1 {
		t.Fatalf("live slots = %d, want 1", stats.Instances)
	}
	if !d.KeepOnShutdown("sb-1") {
		t.Fatal("a resident instance is checkpointed on shutdown")
	}
	// Adopting again is idempotent.
	if _, err := d.AdoptSandbox(context.Background(), sb, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	if stats := d.ResidentHostStats(); stats.Instances != 0 {
		t.Fatalf("live slots after destroy = %d", stats.Instances)
	}
	if res.stopCalls != 0 {
		t.Fatal("destroy killed the shared host")
	}
	// The host did not keep the instance: not adopted.
	if err := os.MkdirAll(d.sandboxDir("sb-2"), 0o700); err != nil {
		t.Fatal(err)
	}
	d.recordInstance(&sandboxInstance{sandboxID: "sb-2", socketPath: sock, workerKey: bucket, fromResidentHost: true})
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-2"}, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("adopt of a lost instance = %v", err)
	}
	// A record naming a host that did not survive: not adopted.
	d.recordInstance(&sandboxInstance{sandboxID: "sb-2", socketPath: d.residentSocketPath(bucket, 5), workerKey: bucket, fromResidentHost: true})
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-2"}, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("adopt on a gone host = %v", err)
	}
	if _, err := d.AdoptSandbox(context.Background(), nil, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatal("nil sandbox adopted")
	}
}

// TestAdoptSandboxOnItsOwnWorker: the per-sandbox worker its record names
// is handed to the supervisor under the record's key.
func TestAdoptSandboxOnItsOwnWorker(t *testing.T) {
	d, per, _, clients := adoptDriver(t, true)
	sock := filepath.Join(d.cfg.RunDir, "sb-w", "worker.sock")
	clients[sock] = &socketClient{loaded: map[string]bool{"sb-w": true}}
	other := filepath.Join(d.cfg.RunDir, "sb-x", "worker.sock")
	clients[other] = &socketClient{loaded: map[string]bool{}}
	withFound(t, []worker.FoundWorker{
		{PID: 3, Socket: sock, Proc: &heldProc{pid: 3}},
		{PID: 4, Socket: other, Proc: &heldProc{pid: 4}},
	}, nil)
	d.AdoptWorkers(context.Background())
	for _, id := range []string{"sb-w", "sb-x"} {
		if err := os.MkdirAll(d.sandboxDir(id), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	d.recordInstance(&sandboxInstance{sandboxID: "sb-w", socketPath: sock, workerKey: "sb-w", resolvedListenPort: 32000, memoryMB: 0})
	state, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-w", MemoryMB: 0}, nil)
	if err != nil || state == nil {
		t.Fatalf("AdoptSandbox = %v", err)
	}
	if per.adopted["sb-w"] != sock {
		t.Fatalf("supervisor adopted %v", per.adopted)
	}
	inst, _ := d.instance("sb-w")
	if inst.fromResidentHost || inst.resolvedListenPort != 32000 || inst.workerSpawnCount != 1 || inst.memoryMB != 128 {
		t.Fatalf("adopted instance = %+v", inst)
	}
	per.survives = false
	if d.KeepOnShutdown("sb-w") {
		t.Fatal("kept on shutdown though its worker dies with sandboxd")
	}
	per.survives = true
	if !d.KeepOnShutdown("sb-w") {
		t.Fatal("checkpointed on shutdown though its worker survives")
	}
	if d.KeepOnShutdown("unknown") {
		t.Fatal("unknown sandbox kept")
	}
	// The worker answers but has lost the instance: stopped, not adopted.
	d.recordInstance(&sandboxInstance{sandboxID: "sb-x", socketPath: other, workerKey: "sb-x"})
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-x"}, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("adopt of a lost instance = %v", err)
	}
	if len(per.stoppedKs) != 1 || per.stoppedKs[0] != "sb-x" {
		t.Fatalf("stopped keys = %v", per.stoppedKs)
	}
	// No pending worker for the socket: not adopted.
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-x"}, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("second adopt = %v", err)
	}
}

func TestClaimWorkerRefused(t *testing.T) {
	d, per, _, _ := adoptDriver(t, true)
	per.refuse = true
	p := &heldProc{pid: 1}
	withFound(t, nil, nil)
	d.pendingWorkers = map[string]worker.FoundWorker{"/s": {PID: 1, Socket: "/s", Proc: p}}
	if d.claimWorker(instanceRecord{SandboxID: "a", Socket: "/s", WorkerKey: "a"}) {
		t.Fatal("claimed though the supervisor refused")
	}
	if !p.wasStopped() {
		t.Fatal("refused worker left running")
	}
}

func TestHasWorkDir(t *testing.T) {
	d, _, _, _ := adoptDriver(t, true)
	if d.HasWorkDir("sb-h") || d.HasWorkDir("../x") || (&Driver{}).HasWorkDir("sb-h") {
		t.Fatal("work dir found where there is none")
	}
	if err := os.MkdirAll(d.sandboxDir("sb-h"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !d.HasWorkDir("sb-h") {
		t.Fatal("work dir not found")
	}
}

// TestRestoreSandboxPicksTheCreatePath: a restore goes to the resident host
// like a create, and to a per-sandbox worker when the sandbox has public
// traffic or exposed ports.
func TestRestoreSandboxPicksTheCreatePath(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	newDriver := func(resident bool) (*Driver, *fakeSupervisor, *fakeSupervisor) {
		per, res := &fakeSupervisor{}, &fakeSupervisor{}
		d := New(Config{RunDir: filepath.Join(t.TempDir(), "run"), ModulesDir: dir, ResidentHostEnabled: resident, DefaultMemoryMB: 64}, nil)
		d.SetModuleResolver(fakeResolver{path: modPath, digest: "dig"})
		d.SetWorkerSupervisor(per)
		d.SetResidentHostSupervisor(res)
		d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
		return d, per, res
	}
	sb := &models.Sandbox{ID: "sb-rs", ModuleRef: "demo.wasm", ModuleDigest: "dig"}
	d, per, res := newDriver(true)
	if _, err := d.RestoreSandbox(context.Background(), sb, nil); err != nil {
		t.Fatal(err)
	}
	if res.ensureCalls != 1 || per.ensureCalls != 0 {
		t.Fatalf("resident restore: resident %d per-sandbox %d", res.ensureCalls, per.ensureCalls)
	}
	if rec, ok := d.readInstanceRecord("sb-rs"); !ok || !rec.Resident {
		t.Fatalf("restore left no resident record: %+v", rec)
	}
	yes := true
	d2, per2, res2 := newDriver(true)
	if _, err := d2.RestoreSandbox(context.Background(), &models.Sandbox{ID: "sb-p", ModuleRef: "demo.wasm", AllowPublicTraffic: &yes}, nil); err != nil {
		t.Fatal(err)
	}
	if res2.ensureCalls != 0 || per2.ensureCalls != 1 {
		t.Fatalf("public restore: resident %d per-sandbox %d", res2.ensureCalls, per2.ensureCalls)
	}
	d3, _, _ := newDriver(true)
	if _, err := d3.RestoreSandbox(context.Background(), &models.Sandbox{ID: "sb-n"}, nil); err == nil || !strings.Contains(err.Error(), "module_ref") {
		t.Fatalf("restore without a module = %v", err)
	}
	if _, err := d3.RestoreSandbox(context.Background(), nil, nil); err == nil {
		t.Fatal("nil restore succeeded")
	}
	// A digest that drifted from the pin fails loudly.
	if _, err := d3.RestoreSandbox(context.Background(), &models.Sandbox{ID: "sb-d", ModuleRef: "demo.wasm", ModuleDigest: "other"}, nil); err == nil {
		t.Fatal("restore of a drifted module succeeded")
	}
	// No digest from the resolver: the per-sandbox path.
	d4, per4, _ := newDriver(true)
	d4.SetModuleResolver(fakeResolver{path: modPath})
	if _, err := d4.RestoreSandbox(context.Background(), &models.Sandbox{ID: "sb-u", ModuleRef: "demo.wasm"}, nil); err != nil {
		t.Fatal(err)
	}
	if per4.ensureCalls != 1 {
		t.Fatalf("no-digest restore per-sandbox ensures = %d", per4.ensureCalls)
	}
	req := requestFromSandbox(&models.Sandbox{ModuleRef: "m", ContainerCommand: []string{"python"}, NetworkEgressMode: "learn"})
	if req.Runtime != models.RuntimeWasm || req.ContainerCommand[0] != "python" || req.NetworkEgressMode != "learn" {
		t.Fatalf("request = %+v", req)
	}
	if firstNonEmpty("", " ", "x") != "x" || firstNonEmpty() != "" {
		t.Fatal("firstNonEmpty")
	}
}

// TestSyncGuestListenKeepsALiveGuest: a guest that still accepts on its
// port is not re-instantiated by a port sync; a dead one is.
func TestSyncGuestListenKeepsALiveGuest(t *testing.T) {
	old := guestListening
	t.Cleanup(func() { guestListening = old })
	listening := true
	guestListening = func(int) bool { return listening }
	client := &socketClient{loaded: map[string]bool{}}
	client.resolvedPort = 33000
	d := New(Config{RunDir: t.TempDir()}, nil)
	d.waitListenReady = func(string, int) error { return nil }
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	d.byID["sb-g"] = &sandboxInstance{sandboxID: "sb-g", socketPath: "/s", status: models.SandboxStatusStarted, resolvedListenPort: 33000}
	if err := d.SyncGuestListenPorts(context.Background(), "sb-g", []int{8080}); err != nil {
		t.Fatal(err)
	}
	if client.setPort != 0 {
		t.Fatalf("live guest re-instantiated (%d SetListenPort)", client.setPort)
	}
	listening = false
	if err := d.SyncGuestListenPorts(context.Background(), "sb-g", []int{8080}); err != nil {
		t.Fatal(err)
	}
	if client.setPort != 1 {
		t.Fatalf("dead guest not restarted (%d SetListenPort)", client.setPort)
	}
	if guestListening2 := old(0); guestListening2 {
		t.Fatal("port 0 reported listening")
	}
	if old(1) {
		t.Fatal("port 1 reported listening")
	}
}
