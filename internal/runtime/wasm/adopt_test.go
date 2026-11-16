package wasm

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
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

// TestInstanceRecordRoundTrip: a record goes to the driver's records dir,
// outside the sandbox's /work, and reads back whole.
func TestInstanceRecordRoundTrip(t *testing.T) {
	d, _, _, _ := adoptDriver(t, true)
	bucket := residentBucketID("", "dd", 64)
	sock := d.residentSocketPath(bucket, 0)
	inst := &sandboxInstance{sandboxID: "sb-r", socketPath: sock, workerKey: bucket, fromResidentHost: true,
		moduleRef: "python", modulePath: "/m.wasm", moduleDigest: "dd", entryExport: "_start", memoryMB: 64, resolvedListenPort: 31000}
	if _, _, ok := d.readInstanceRecord("sb-r"); ok {
		t.Fatal("record read before one was written")
	}
	// No work dir: the record does not need one.
	d.recordInstance(inst)
	rec, legacy, ok := d.readInstanceRecord("sb-r")
	if !ok || legacy || rec.Socket != sock || !rec.Resident || rec.ListenPort != 31000 || rec.MemoryMB != 64 || rec.ModulePath != "/m.wasm" {
		t.Fatalf("record = %+v, legacy %v, ok %v", rec, legacy, ok)
	}
	path := d.instanceRecordPath("sb-r")
	if want := filepath.Join(d.cfg.RunDir, recordsDirName, "sb-r.json"); path != want {
		t.Fatalf("record path = %q, want %q", path, want)
	}
	if strings.HasPrefix(path, d.sandboxDir("sb-r")+string(filepath.Separator)) {
		t.Fatalf("record %q is under the sandbox's /work", path)
	}
	for _, dir := range []string{recordsDirName, socketsDirName} {
		if st, err := os.Stat(filepath.Join(d.cfg.RunDir, dir)); err != nil || st.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v, %v; want a 0700 dir", dir, st, err)
		}
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("record file %v, %v; want 0600", st, err)
	}
	// A record that names another sandbox is not this one's.
	if err := os.WriteFile(path, []byte(`{"sandbox_id":"other","socket":"/x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := d.readInstanceRecord("sb-r"); ok {
		t.Fatal("foreign record accepted")
	}
	// Ids that could name a path outside the dirs have no record.
	for _, id := range []string{"../sb-r", "a/b", ".records", ""} {
		if d.instanceRecordPath(id) != "" || d.workerSocketPath(id) != "" || d.legacyInstanceRecordPath(id) != "" || d.legacyWorkerSocketPath(id) != "" {
			t.Fatalf("id %q has a path", id)
		}
		if _, _, ok := d.readInstanceRecord(id); ok {
			t.Fatalf("id %q has a record", id)
		}
	}
	d.recordInstance(&sandboxInstance{sandboxID: "../x", socketPath: sock}) // logged, not written
	if _, err := os.Stat(filepath.Join(d.cfg.RunDir, "x.json")); !os.IsNotExist(err) {
		t.Fatalf("record for a bad id written outside the records dir: %v", err)
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
	d.recordInstance(&sandboxInstance{sandboxID: "sb-2", socketPath: d.residentSocketPath(bucket, 5), workerKey: d.residentHostKey(bucket, 5), fromResidentHost: true})
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
	sock := d.workerSocketPath("sb-w")
	clients[sock] = &socketClient{loaded: map[string]bool{"sb-w": true}}
	other := d.workerSocketPath("sb-x")
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

// provingClient is a worker from this release: it says whose instance it
// holds, and answers "not loaded" for any other sandbox.
type provingClient struct {
	socketClient
	holder string
}

func (c *provingClient) InstanceStatus(_ context.Context, id string) (worker.InstanceStatus, error) {
	if c.err != nil {
		return worker.InstanceStatus{}, c.err
	}
	loaded := c.loaded[id] && (id == "" || id == c.holder)
	return worker.InstanceStatus{Loaded: loaded, SandboxID: c.holder, Checked: true}, nil
}

// legacyRecordDriver is an adoption driver whose clients are set per socket
// and whose module resolver knows demo.wasm (digest "dig").
func legacyRecordDriver(t *testing.T) (*Driver, *adoptingSupervisor, map[string]WorkerClient, string) {
	t.Helper()
	d, per, _, _ := adoptDriver(t, true)
	modPath := wasmmod.WriteMinimalWasm(t, d.cfg.ModulesDir, "demo.wasm")
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "dig"})
	workers := map[string]WorkerClient{}
	d.SetWorkerClientFactory(func(sock string) WorkerClient {
		if c := workers[sock]; c != nil {
			return c
		}
		return &socketClient{loaded: map[string]bool{}}
	})
	return d, per, workers, modPath
}

// writeLegacyRecord puts a record where releases before the records dir
// kept it: in the sandbox's /work, which its guest can write.
func writeLegacyRecord(t *testing.T, d *Driver, sandboxID string, rec instanceRecord) string {
	t.Helper()
	if err := os.MkdirAll(d.sandboxDir(sandboxID), 0o700); err != nil {
		t.Fatal(err)
	}
	path := d.legacyInstanceRecordPath(sandboxID)
	if err := writeFileAtomic(path, rec); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAdoptRefusesARecordInWorkNamingAnotherSandbox: a guest rewrites the
// instance.json in its /work to name another sandbox's worker. A restarted
// sandboxd does not hand it that worker: the record is refused, the other
// sandbox's worker is neither claimed nor stopped, and that sandbox is
// still adopted on its own record afterwards.
func TestAdoptRefusesARecordInWorkNamingAnotherSandbox(t *testing.T) {
	d, per, workers, _ := legacyRecordDriver(t)
	victimOld := d.legacyWorkerSocketPath("sb-victim") // a pre-upgrade worker
	victimNew := d.workerSocketPath("sb-victim")
	// A pre-upgrade worker cannot say whose instance it holds: it answers
	// loaded for any sandbox id.
	workers[victimOld] = &socketClient{loaded: map[string]bool{"sb-victim": true, "sb-evil": true}}
	workers[victimNew] = &provingClient{socketClient: socketClient{loaded: map[string]bool{"sb-victim": true}}, holder: "sb-victim"}
	procs := map[string]*heldProc{victimOld: {pid: 7}, victimNew: {pid: 8}}
	withFound(t, []worker.FoundWorker{
		{PID: 7, Socket: victimOld, Proc: procs[victimOld]},
		{PID: 8, Socket: victimNew, Proc: procs[victimNew]},
	}, nil)
	d.AdoptWorkers(context.Background())

	for _, tc := range []struct {
		name string
		rec  instanceRecord
	}{
		{"victim's pre-upgrade socket, own key", instanceRecord{Socket: victimOld, WorkerKey: "sb-evil"}},
		{"victim's pre-upgrade socket and key", instanceRecord{Socket: victimOld, WorkerKey: "sb-victim"}},
		{"victim's socket and key", instanceRecord{Socket: victimNew, WorkerKey: "sb-victim"}},
		{"victim's socket as a warm slot", instanceRecord{Socket: victimOld, WorkerKey: "sb-victim", WarmPool: true}},
		{"victim's socket as a resident host", instanceRecord{Socket: victimOld, WorkerKey: "sb-victim", Resident: true}},
		{"its own socket where only this release puts it", instanceRecord{Socket: d.workerSocketPath("sb-evil"), WorkerKey: "sb-evil"}},
		{"a socket outside the run dir", instanceRecord{Socket: "/tmp/elsewhere.sock", WorkerKey: "sb-evil"}},
	} {
		tc.rec.SandboxID = "sb-evil"
		path := writeLegacyRecord(t, d, "sb-evil", tc.rec)
		if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-evil", ModuleRef: "demo.wasm", ModuleDigest: "dig"}, nil); !errors.Is(err, ErrNotAdopted) {
			t.Fatalf("%s: AdoptSandbox = %v, want ErrNotAdopted", tc.name, err)
		}
		// Not a record of the driver's: left as the guest wrote it, unread.
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: the guest's file was removed: %v", tc.name, err)
		}
	}
	if len(per.adopted) != 0 || len(per.stoppedKs) != 0 || procs[victimOld].wasStopped() || procs[victimNew].wasStopped() {
		t.Fatalf("victim's workers touched: adopted %v stopped %v", per.adopted, per.stoppedKs)
	}
	if _, err := d.instance("sb-evil"); err == nil {
		t.Fatal("the guest's sandbox was registered")
	}
	// The victim still takes over its own worker.
	d.recordInstance(&sandboxInstance{sandboxID: "sb-victim", socketPath: victimNew, workerKey: "sb-victim"})
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-victim"}, nil); err != nil {
		t.Fatalf("victim's own adoption = %v", err)
	}
	if per.adopted["sb-victim"] != victimNew {
		t.Fatalf("supervisor adopted %v", per.adopted)
	}
}

// TestAdoptMigratesAValidLegacyRecord: a record a pre-upgrade sandboxd left
// in the sandbox's /work is used once, for which worker to take over only,
// then moved to the driver's records dir. The fields a guest could have
// rewritten (module path, memory, listen port, export) come from the row,
// the resolver and the worker instead. A record naming the sandbox's own
// pre-upgrade worker, whose socket is in /work, is not adopted at all
// (TestAdoptNeverDialsASocketInWork): the record goes, the worker is
// stopped, and the sandbox is restored.
func TestAdoptMigratesAValidLegacyRecord(t *testing.T) {
	d, per, workers, modPath := legacyRecordDriver(t)
	sock := d.legacyWorkerSocketPath("sb-old")
	proc := &heldProc{pid: 3}
	withFound(t, []worker.FoundWorker{{PID: 3, Socket: sock, Proc: proc}}, nil)
	d.AdoptWorkers(context.Background())
	legacyPath := writeLegacyRecord(t, d, "sb-old", instanceRecord{SandboxID: "sb-old", Socket: sock, WorkerKey: "sb-old"})
	sb := &models.Sandbox{ID: "sb-old", ModuleRef: "demo.wasm", ModuleDigest: "dig"}
	if _, err := d.AdoptSandbox(context.Background(), sb, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("AdoptSandbox on a /work socket = %v, want ErrNotAdopted", err)
	}
	if len(per.adopted) != 0 || !proc.wasStopped() {
		t.Fatalf("own pre-upgrade worker: adopted %v stopped %v", per.adopted, proc.wasStopped())
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy record left in /work: %v", err)
	}

	// A pre-upgrade warm-slot worker and resident host are adopted; a
	// resident host confirms the instance itself.
	slotSock := filepath.Join(wasmpool.New(d.cfg.RunDir, nil).SlotDir("dig", "pool-0123456789abcdef"), "worker.sock")
	slot := &socketClient{loaded: map[string]bool{"sb-slot": true}}
	slot.resolvedPort = 41000
	workers[slotSock] = slot
	bucket := residentBucketID("", "dig", 128)
	resSock := d.residentSocketPath(bucket, 0)
	workers[resSock] = &socketClient{loaded: map[string]bool{"": true, "sb-res": true}}
	withFound(t, []worker.FoundWorker{
		{PID: 4, Socket: slotSock, Proc: &heldProc{pid: 4}},
		{PID: 5, Resident: true, Socket: resSock, Proc: &heldProc{pid: 5}},
	}, nil)
	d.AdoptWorkers(context.Background())
	slotRecord := writeLegacyRecord(t, d, "sb-slot", instanceRecord{
		SandboxID: "sb-slot", Socket: slotSock, WorkerKey: "pool-0123456789abcdef", WarmPool: true,
		ModuleRef: "evil", ModulePath: "/etc/shadow", ModuleDigest: "evil", ModuleSize: 1 << 40,
		EntryExport: "evil", MemoryMB: 1 << 20, ListenPort: 2019,
	})
	writeLegacyRecord(t, d, "sb-res", instanceRecord{SandboxID: "sb-res", Socket: resSock, WorkerKey: bucket, Resident: true, ModulePath: "/etc/shadow"})
	for _, id := range []string{"sb-slot", "sb-res"} {
		if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: id, ModuleRef: "demo.wasm", ModuleDigest: "dig"}, nil); err != nil {
			t.Fatalf("adopt %s = %v", id, err)
		}
		if inst, _ := d.instance(id); inst.modulePath != modPath {
			t.Fatalf("%s module path = %q", id, inst.modulePath)
		}
	}
	inst, _ := d.instance("sb-slot")
	if !inst.fromWarmPool || inst.workerKey != "pool-0123456789abcdef" {
		t.Fatalf("warm slot instance = %+v", inst)
	}
	if inst.modulePath != modPath || inst.moduleRef != "demo.wasm" || inst.moduleDigest != "dig" || inst.moduleSize != 1 ||
		inst.memoryMB != 128 || inst.resolvedListenPort != 41000 || inst.entryExport != "_start" || inst.socketPath != slotSock {
		t.Fatalf("adopted instance took a field from the guest's file: %+v", inst)
	}
	if _, err := os.Stat(slotRecord); !os.IsNotExist(err) {
		t.Fatalf("legacy record left in /work: %v", err)
	}
	rec, legacy, ok := d.readInstanceRecord("sb-slot")
	if !ok || legacy || rec.Socket != slotSock || rec.ModulePath != modPath || rec.ListenPort != 41000 || rec.MemoryMB != 128 {
		t.Fatalf("moved record = %+v, legacy %v, ok %v", rec, legacy, ok)
	}
	if inst, _ := d.instance("sb-res"); !inst.fromResidentHost || !inst.residentSlotHeld {
		t.Fatalf("resident instance = %+v", inst)
	}
}

// TestAdoptLegacyRecordModuleUnresolved: a pre-upgrade record whose module
// no longer resolves is not adopted, and its worker is left unclaimed for
// FinishAdoption, so the restore that follows starts clean.
func TestAdoptLegacyRecordModuleUnresolved(t *testing.T) {
	d, per, workers, _ := legacyRecordDriver(t)
	d.resolver = nil
	sock := filepath.Join(wasmpool.New(d.cfg.RunDir, nil).SlotDir("dig", "pool-00000000000000aa"), "worker.sock")
	workers[sock] = &socketClient{loaded: map[string]bool{"sb-u": true}}
	withFound(t, []worker.FoundWorker{{PID: 3, Socket: sock, Proc: &heldProc{pid: 3}}}, nil)
	d.AdoptWorkers(context.Background())
	writeLegacyRecord(t, d, "sb-u", instanceRecord{SandboxID: "sb-u", Socket: sock, WorkerKey: "pool-00000000000000aa", WarmPool: true})
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-u", ModuleRef: "demo.wasm"}, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("AdoptSandbox = %v", err)
	}
	if len(per.adopted) != 0 || !d.hasPendingWorker(sock) {
		t.Fatalf("worker claimed though the module did not resolve: %v", per.adopted)
	}
	if _, err := d.moduleFromRow(context.Background(), &models.Sandbox{ID: "x"}); err == nil {
		t.Fatal("module resolved with no resolver")
	}
	d.SetModuleResolver(fakeResolver{path: "/m.wasm"})
	if _, err := d.moduleFromRow(context.Background(), &models.Sandbox{ID: "x"}); err == nil || !strings.Contains(err.Error(), "module_ref") {
		t.Fatalf("module of a row without one = %v", err)
	}
}

// TestLegacyRecordReadOnlyAsAPlainFile: the record in a guest's /work is
// read only when it is a small regular file at that name: not through a
// symlink (which could lead to any file on the host), not from a FIFO
// (which would block the boot), not past the size cap.
func TestLegacyRecordReadOnlyAsAPlainFile(t *testing.T) {
	d, _, _, _ := legacyRecordDriver(t)
	sock := d.legacyWorkerSocketPath("sb-l")
	valid := instanceRecord{SandboxID: "sb-l", Socket: sock, WorkerKey: "sb-l"}
	if err := os.MkdirAll(d.sandboxDir("sb-l"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := d.legacyInstanceRecordPath("sb-l")
	elsewhere := filepath.Join(t.TempDir(), "valid.json")
	if err := writeFileAtomic(elsewhere, valid); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		setup func() error
	}{
		{"symlink to a valid record", func() error { return os.Symlink(elsewhere, path) }},
		{"fifo", func() error { return syscall.Mkfifo(path, 0o600) }},
		{"directory", func() error { return os.Mkdir(path, 0o700) }},
		{"over the cap", func() error {
			raw := `{"sandbox_id":"sb-l","socket":"` + sock + `","worker_key":"sb-l"}` + strings.Repeat(" ", maxRecordBytes)
			return os.WriteFile(path, []byte(raw), 0o600)
		}},
		{"not json", func() error { return os.WriteFile(path, []byte("my app's own instance.json"), 0o600) }},
		{"another sandbox's record", func() error {
			return writeFileAtomic(path, instanceRecord{SandboxID: "sb-x", Socket: d.legacyWorkerSocketPath("sb-x"), WorkerKey: "sb-x"})
		}},
	}
	for _, tc := range cases {
		_ = os.RemoveAll(path)
		if err := tc.setup(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if rec, _, ok := d.readInstanceRecord("sb-l"); ok {
			t.Fatalf("%s: read %+v", tc.name, rec)
		}
	}
	_ = os.RemoveAll(path)
	if err := writeFileAtomic(path, valid); err != nil {
		t.Fatal(err)
	}
	if rec, legacy, ok := d.readInstanceRecord("sb-l"); !ok || !legacy || !reflect.DeepEqual(rec, valid) {
		t.Fatalf("plain legacy record = %+v, legacy %v, ok %v", rec, legacy, ok)
	}
	// A record of the driver's wins over one left in /work, and an
	// unusable one is not passed over for it.
	if err := os.MkdirAll(filepath.Join(d.cfg.RunDir, recordsDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.instanceRecordPath("sb-l"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := d.readInstanceRecord("sb-l"); ok {
		t.Fatal("fell back to the /work record past a broken one of the driver's")
	}
}

// TestAdoptRefusesAWorkerThatHoldsAnotherSandbox: whatever the record, the
// worker must answer for the sandbox. One that says it holds another
// sandbox's instance is not claimed and not stopped: it stays for that
// sandbox, and FinishAdoption stops it if nobody claims it.
func TestAdoptRefusesAWorkerThatHoldsAnotherSandbox(t *testing.T) {
	d, per, workers, _ := legacyRecordDriver(t)
	sock := d.workerSocketPath("sb-a")
	wrong := &provingClient{socketClient: socketClient{loaded: map[string]bool{"sb-a": true, "sb-b": true}}, holder: "sb-b"}
	workers[sock] = wrong
	proc := &heldProc{pid: 3}
	withFound(t, []worker.FoundWorker{{PID: 3, Socket: sock, Proc: proc}}, nil)
	d.AdoptWorkers(context.Background())
	d.recordInstance(&sandboxInstance{sandboxID: "sb-a", socketPath: sock, workerKey: "sb-a"})
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-a"}, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("AdoptSandbox = %v", err)
	}
	if len(per.adopted) != 0 || len(per.stoppedKs) != 0 || proc.wasStopped() || !d.hasPendingWorker(sock) {
		t.Fatalf("worker of another sandbox touched: adopted %v stopped %v", per.adopted, per.stoppedKs)
	}
	// Answering for the sandbox, it is taken over.
	wrong.holder = "sb-a"
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-a"}, nil); err != nil {
		t.Fatalf("AdoptSandbox once the worker answers for it = %v", err)
	}
	if per.adopted["sb-a"] != sock {
		t.Fatalf("supervisor adopted %v", per.adopted)
	}
	// A worker that holds no instance yet is ours to stop, as before.
	empty := d.workerSocketPath("sb-e")
	workers[empty] = &provingClient{socketClient: socketClient{loaded: map[string]bool{"": true}}}
	withFound(t, []worker.FoundWorker{{PID: 4, Socket: empty, Proc: &heldProc{pid: 4}}}, nil)
	d.AdoptWorkers(context.Background())
	d.recordInstance(&sandboxInstance{sandboxID: "sb-e", socketPath: empty, workerKey: "sb-e"})
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-e"}, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("adopt of an empty worker = %v", err)
	}
	if len(per.stoppedKs) != 1 || per.stoppedKs[0] != "sb-e" {
		t.Fatalf("stopped keys = %v", per.stoppedKs)
	}
	// A resident host that says it holds another sandbox (never the case
	// for a working host) is not trusted either.
	bucket := residentBucketID("", "dig", 128)
	resSock := d.residentSocketPath(bucket, 0)
	workers[resSock] = &provingClient{socketClient: socketClient{loaded: map[string]bool{"": true, "sb-r": true}}, holder: "sb-other"}
	withFound(t, []worker.FoundWorker{{PID: 5, Resident: true, Socket: resSock, Proc: &heldProc{pid: 5}}}, nil)
	d.AdoptWorkers(context.Background())
	d.recordInstance(&sandboxInstance{sandboxID: "sb-r", socketPath: resSock, workerKey: bucket, fromResidentHost: true})
	if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-r"}, nil); !errors.Is(err, ErrNotAdopted) {
		t.Fatalf("adopt on a host naming another sandbox = %v", err)
	}
}

// TestRecordRoutesValid: a record names a worker of the sandbox's own, a
// warm slot of this run dir's pool, or a resident host of this run dir,
// under the key that goes with it; a legacy record cannot name a socket
// only this release uses.
func TestRecordRoutesValid(t *testing.T) {
	d := New(Config{RunDir: "/run/sandboxd/wasm"}, nil)
	bucket := residentBucketID("", "dig", 128)
	slot := filepath.Join(wasmpool.New(d.cfg.RunDir, nil).SlotDir("sha256:0123456789", "pool-0123456789abcdef"), "worker.sock")
	cases := []struct {
		name         string
		rec          instanceRecord
		owned, older bool // valid in the driver's dir; valid in /work
	}{
		{"own socket", instanceRecord{Socket: d.workerSocketPath("sb-1"), WorkerKey: "sb-1"}, true, false},
		{"own pre-upgrade socket", instanceRecord{Socket: d.legacyWorkerSocketPath("sb-1"), WorkerKey: "sb-1"}, true, true},
		{"own socket, other key", instanceRecord{Socket: d.workerSocketPath("sb-1"), WorkerKey: "sb-2"}, false, false},
		{"other sandbox's socket", instanceRecord{Socket: d.workerSocketPath("sb-2"), WorkerKey: "sb-1"}, false, false},
		{"other sandbox's pre-upgrade socket", instanceRecord{Socket: d.legacyWorkerSocketPath("sb-2"), WorkerKey: "sb-1"}, false, false},
		{"no socket", instanceRecord{WorkerKey: "sb-1"}, false, false},
		{"warm slot", instanceRecord{Socket: slot, WorkerKey: "pool-0123456789abcdef", WarmPool: true}, true, true},
		{"warm slot, other key", instanceRecord{Socket: slot, WorkerKey: "sb-1", WarmPool: true}, false, false},
		{"warm slot not flagged", instanceRecord{Socket: slot, WorkerKey: "pool-0123456789abcdef"}, false, false},
		{"resident host", instanceRecord{Socket: d.residentSocketPath(bucket, 1), WorkerKey: d.residentHostKey(bucket, 1), Resident: true}, true, true},
		{"resident host, other key", instanceRecord{Socket: d.residentSocketPath(bucket, 1), WorkerKey: bucket, Resident: true}, false, false},
		{"resident and warm", instanceRecord{Socket: d.residentSocketPath(bucket, 0), WorkerKey: bucket, Resident: true, WarmPool: true}, false, false},
		{"resident flag on own socket", instanceRecord{Socket: d.workerSocketPath("sb-1"), WorkerKey: "sb-1", Resident: true}, false, false},
	}
	for _, tc := range cases {
		tc.rec.SandboxID = "sb-1"
		if got := d.recordRoutesValid("sb-1", tc.rec, false); got != tc.owned {
			t.Errorf("%s (driver's dir) = %v, want %v", tc.name, got, tc.owned)
		}
		if got := d.recordRoutesValid("sb-1", tc.rec, true); got != tc.older {
			t.Errorf("%s (/work) = %v, want %v", tc.name, got, tc.older)
		}
	}
}

// TestDestroyRemovesHostState: the record and the socket in the driver's
// dirs go with the sandbox.
func TestDestroyRemovesHostState(t *testing.T) {
	d, _, _, _ := adoptDriver(t, false)
	sock, err := d.ownWorkerSocket("sb-d")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, nil, 0o600); err != nil { // a killed worker's leftover
		t.Fatal(err)
	}
	d.recordInstance(&sandboxInstance{sandboxID: "sb-d", socketPath: sock, workerKey: "sb-d"})
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-d"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{sock, d.instanceRecordPath("sb-d")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left after destroy: %v", p, err)
		}
	}
	if _, err := d.ownWorkerSocket("../x"); err == nil {
		t.Fatal("socket for an id that is not a sandbox id")
	}
}

// TestHostDirsUnavailable: when the driver's dirs cannot be made, a create
// fails before it holds anything, and a record is only logged as missing.
func TestHostDirsUnavailable(t *testing.T) {
	d, _, _, _ := adoptDriver(t, false)
	d.SetModuleResolver(fakeResolver{path: "/m.wasm", digest: "dig"})
	if err := os.WriteFile(filepath.Join(d.cfg.RunDir, recordsDirName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{ModuleRef: "demo.wasm"}, "sb-h", "", nil); err == nil {
		t.Fatal("create without the driver's dirs succeeded")
	}
	if _, err := d.StartSandbox(context.Background(), &models.Sandbox{ID: "sb-h", ModuleRef: "demo.wasm"}, nil); err == nil {
		t.Fatal("start without the driver's dirs succeeded")
	}
	inst := &sandboxInstance{sandboxID: "sb-h", workDir: d.sandboxDir("sb-h"), modulePath: "/m.wasm", socketPath: d.residentSocketPath("b", 0)}
	if err := d.migrateResidentToCold(context.Background(), inst); err == nil {
		t.Fatal("migrate without the driver's dirs succeeded")
	}
	d.recordInstance(inst) // logged
	if _, _, ok := d.readInstanceRecord("sb-h"); ok {
		t.Fatal("record written without its dir")
	}
	if err := (&Driver{}).ensureHostDirs(); err == nil {
		t.Fatal("host dirs without a run dir")
	}
	// The latch: once made, the dirs are not made again.
	d2, _, _, _ := adoptDriver(t, false)
	if err := d2.ensureHostDirs(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(d2.cfg.RunDir, socketsDirName)); err != nil {
		t.Fatal(err)
	}
	if err := d2.ensureHostDirs(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d2.cfg.RunDir, socketsDirName)); !os.IsNotExist(err) {
		t.Fatalf("latched dirs made again: %v", err)
	}
}

// TestWorkerListenPortAnswer: the listen port of a pre-upgrade worker comes
// from the worker; none or a disabled listener is 0.
func TestWorkerListenPortAnswer(t *testing.T) {
	d, _, workers, _ := legacyRecordDriver(t)
	c := &socketClient{loaded: map[string]bool{}}
	workers["/s"] = c
	for _, tc := range []struct{ port, want int }{{41000, 41000}, {-1, 0}, {0, 0}} {
		c.resolvedPort = tc.port
		if got := d.workerListenPort("/s", "sb"); got != tc.want {
			t.Fatalf("port %d -> %d, want %d", tc.port, got, tc.want)
		}
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
	if rec, _, ok := d.readInstanceRecord("sb-rs"); !ok || !rec.Resident {
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

// TestAdoptNeverDialsASocketInWork: a pre-upgrade per-sandbox worker
// listens in its sandbox's dir, the guest's /work. The guest can swap that
// socket for a relative link to another sandbox's pre-upgrade socket, and a
// worker of that age answers for any sandbox id. So such a worker is never
// contacted: it is stopped (found by its command line, not the path), the
// sandbox is left to a restore (ErrNotAdopted), the other sandbox's worker
// is untouched, and nothing at the guest's path is followed or removed but
// a socket.
func TestAdoptNeverDialsASocketInWork(t *testing.T) {
	for _, recordIn := range []string{"work", "driver"} {
		t.Run("record in "+recordIn, func(t *testing.T) {
			d, per, _, _ := legacyRecordDriver(t)
			own := d.legacyWorkerSocketPath("sb-evil")
			victim := d.legacyWorkerSocketPath("sb-victim")
			var mu sync.Mutex
			dialed := map[string]bool{}
			d.SetWorkerClientFactory(func(sock string) WorkerClient {
				mu.Lock()
				dialed[sock] = true
				mu.Unlock()
				// A pre-upgrade worker: loaded for any sandbox id.
				return &socketClient{loaded: map[string]bool{"sb-evil": true, "sb-victim": true}}
			})
			procs := map[string]*heldProc{own: {pid: 7}, victim: {pid: 8}}
			withFound(t, []worker.FoundWorker{
				{PID: 7, Socket: own, Proc: procs[own]},
				{PID: 8, Socket: victim, Proc: procs[victim]},
			}, nil)
			d.AdoptWorkers(context.Background())
			for _, id := range []string{"sb-evil", "sb-victim"} {
				if err := os.MkdirAll(d.sandboxDir(id), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			// The guest's swap: its socket now leads to the victim's worker.
			if err := os.Symlink(filepath.Join("..", "sb-victim", "worker.sock"), own); err != nil {
				t.Fatal(err)
			}
			rec := instanceRecord{SandboxID: "sb-evil", Socket: own, WorkerKey: "sb-evil"}
			if recordIn == "work" {
				writeLegacyRecord(t, d, "sb-evil", rec)
			} else {
				d.recordInstance(&sandboxInstance{sandboxID: rec.SandboxID, socketPath: rec.Socket, workerKey: rec.WorkerKey})
			}

			sb := &models.Sandbox{ID: "sb-evil", ModuleRef: "demo.wasm", ModuleDigest: "dig"}
			if _, err := d.AdoptSandbox(context.Background(), sb, nil); !errors.Is(err, ErrNotAdopted) {
				t.Fatalf("AdoptSandbox = %v, want ErrNotAdopted (restore)", err)
			}
			mu.Lock()
			wasDialed := dialed[own]
			mu.Unlock()
			if wasDialed {
				t.Fatal("dialed a socket in the guest's /work")
			}
			if !procs[own].wasStopped() || d.hasPendingWorker(own) {
				t.Fatal("the sandbox's own pre-upgrade worker was left running")
			}
			if procs[victim].wasStopped() || !d.hasPendingWorker(victim) || len(per.adopted) != 0 {
				t.Fatalf("the victim's worker was touched: adopted %v", per.adopted)
			}
			if _, err := d.instance("sb-evil"); err == nil {
				t.Fatal("the sandbox was registered on the worker")
			}
			if st, err := os.Lstat(own); err != nil || st.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("the guest's link was not left alone: %v", err)
			}
			if _, err := os.Stat(d.legacyInstanceRecordPath("sb-evil")); !os.IsNotExist(err) {
				t.Fatalf("the record in /work was kept: %v", err)
			}
		})
	}
}

// TestRetireWorkDirWorkerRemovesItsSocket: the worker's own socket in /work
// goes with it; a sandbox with no worker found still gets a restore.
func TestRetireWorkDirWorkerRemovesItsSocket(t *testing.T) {
	d, _, _, _ := legacyRecordDriver(t)
	// A short run dir: a unix socket path must fit in sun_path.
	short, err := os.MkdirTemp("", "aw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	d.cfg.RunDir = short
	sock := d.legacyWorkerSocketPath("sb-s")
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket: %v", err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = ln.Close()
	rec := instanceRecord{SandboxID: "sb-s", Socket: sock, WorkerKey: "sb-s"}
	if !d.workerInWorkDir("sb-s", rec) {
		t.Fatal("the sandbox's /work socket was not recognised")
	}
	for _, other := range []instanceRecord{
		{Socket: sock, WorkerKey: "sb-s", WarmPool: true},
		{Socket: sock, WorkerKey: "sb-s", Resident: true},
		{Socket: d.workerSocketPath("sb-s"), WorkerKey: "sb-s"},
		{Socket: d.legacyWorkerSocketPath("sb-x"), WorkerKey: "sb-s"},
	} {
		if d.workerInWorkDir("sb-s", other) {
			t.Fatalf("%+v taken for the sandbox's /work socket", other)
		}
	}
	d.retireWorkDirWorker("sb-s", rec, false)
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("the worker's socket was left in /work: %v", err)
	}
}
