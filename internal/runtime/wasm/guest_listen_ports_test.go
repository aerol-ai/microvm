package wasm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// listenPortsWorkerClient is a worker of this release as the driver sees
// it: it keeps the guest's listeners and reports them like a real worker.
type listenPortsWorkerClient struct {
	recordingWorkerClient
	mu        sync.Mutex
	live      map[int]int
	engine    string
	fallback  string
	nextPort  int
	sets      [][]int
	queries   int
	invokes   int
	proxied   []int
	listErr   error
	setErr    error
	noPrimary bool
	inFlight  atomic.Int32
	overlap   atomic.Bool
	setDelay  time.Duration
}

func (c *listenPortsWorkerClient) report() worker.ListenPorts {
	r := worker.ListenPorts{Engine: c.engine, FallbackFrom: c.fallback}
	if len(c.live) > 0 {
		r.Ports = make(map[int]int, len(c.live))
		low := 0
		for g, h := range c.live {
			r.Ports[g] = h
			if low == 0 || g < low {
				low = g
			}
		}
		if !c.noPrimary {
			r.Primary = c.live[low]
		}
	}
	return r
}

func (c *listenPortsWorkerClient) ListenPorts(string) (worker.ListenPorts, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries++
	if c.listErr != nil {
		return worker.ListenPorts{}, c.listErr
	}
	return c.report(), nil
}

func (c *listenPortsWorkerClient) SetListenPorts(_ string, ports []int, _ string) (worker.ListenPorts, error) {
	if c.inFlight.Add(1) > 1 {
		c.overlap.Store(true)
	}
	defer c.inFlight.Add(-1)
	time.Sleep(c.setDelay)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets = append(c.sets, append([]int(nil), ports...))
	if c.setErr != nil {
		return worker.ListenPorts{}, c.setErr
	}
	c.live = map[int]int{}
	for _, p := range ports {
		c.nextPort++
		c.live[p] = 40000 + c.nextPort
	}
	return c.report(), nil
}

func (c *listenPortsWorkerClient) Invoke(string, string) error {
	c.mu.Lock()
	c.invokes++
	c.mu.Unlock()
	return nil
}

func (c *listenPortsWorkerClient) ProxyHTTP(_ string, guestPort int, w http.ResponseWriter, _ *http.Request) error {
	c.mu.Lock()
	c.proxied = append(c.proxied, guestPort)
	c.mu.Unlock()
	_, _ = w.Write([]byte("ok"))
	return nil
}

func (c *listenPortsWorkerClient) setCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sets)
}

func newListenPortsDriver(t *testing.T, client WorkerClient) *Driver {
	t.Helper()
	d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir()}, nil)
	d.waitListenReady = func(string, int) error { return nil }
	d.newWorkerClient = func(string) WorkerClient { return client }
	d.mu.Lock()
	d.byID["sb-ports"] = &sandboxInstance{sandboxID: "sb-ports", socketPath: "/tmp/fake.sock", status: models.SandboxStatusStarted}
	d.mu.Unlock()
	return d
}

// One listener per exposed port: a new port re-instantiates once with the
// full set; the same set, or a removed port, changes nothing; no ports
// turns the listeners off once.
func TestSyncGuestListenPortsPerPort(t *testing.T) {
	c := &listenPortsWorkerClient{engine: "wazero"}
	d := newListenPortsDriver(t, c)
	ctx := context.Background()
	steps := []struct {
		name     string
		exposed  []int
		wantSets int
		wantSet  []int
	}{
		{"first expose", []int{8080}, 1, []int{8080}},
		{"same set again (reconcile, re-expose)", []int{8080}, 1, nil},
		{"a new port", []int{9090, 8080, 9090}, 2, []int{8080, 9090}},
		{"same set again", []int{8080, 9090}, 2, nil},
		{"a port removed keeps its listener", []int{9090}, 2, nil},
		{"none turns them off", nil, 3, []int{}},
		{"none again is a no-op", nil, 3, nil},
	}
	for _, s := range steps {
		if err := d.SyncGuestListenPorts(ctx, "sb-ports", s.exposed); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if got := c.setCount(); got != s.wantSets {
			t.Fatalf("%s: set_listen_ports calls = %d, want %d (%v)", s.name, got, s.wantSets, c.sets)
		}
		if s.wantSet != nil {
			last := c.sets[len(c.sets)-1]
			if fmt.Sprint(last) != fmt.Sprint(s.wantSet) && !(len(last) == 0 && len(s.wantSet) == 0) {
				t.Fatalf("%s: set = %v, want %v", s.name, last, s.wantSet)
			}
		}
	}
	// The guest's _start runs on its own goroutine.
	invokes := func() int {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.invokes
	}
	for deadline := time.Now().Add(2 * time.Second); invokes() < 2 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if n := invokes(); n != 2 {
		t.Fatalf("guest started %d times, want 2 (one per new listener set)", n)
	}
	inst, _ := d.instance("sb-ports")
	if st := inst.guestListen(); st.primary != 0 || len(st.ports) != 0 || st.legacy {
		t.Fatalf("state after off = %+v", st)
	}
}

// A worker of this release gets the exposed port with each request, and
// routes it to that port's listener; the record keeps the map.
func TestGuestHTTPProxySendsTheExposedPortToAPerPortWorker(t *testing.T) {
	c := &listenPortsWorkerClient{engine: "wazero"}
	d := newListenPortsDriver(t, c)
	if err := d.SyncGuestListenPorts(context.Background(), "sb-ports", []int{8080, 9090}); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{9090, 8080} {
		if err := d.guestHTTPProxy("sb-ports", port, newDiscardWriter(), &http.Request{}); err != nil {
			t.Fatalf("proxy %d: %v", port, err)
		}
	}
	if fmt.Sprint(c.proxied) != "[9090 8080]" {
		t.Fatalf("proxied ports = %v", c.proxied)
	}
	raw, err := os.ReadFile(d.instanceRecordPath("sb-ports"))
	if err != nil {
		t.Fatal(err)
	}
	var rec instanceRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.ListenPort <= 0 || rec.ListenPorts[8080] != rec.ListenPort || rec.ListenPorts[9090] <= 0 || rec.ListenEngine != "wazero" {
		t.Fatalf("record = %s (%v)", raw, err)
	}
}

// A worker from an older release does not know set_listen_ports: the
// driver keeps its one listener, never sends it a port number and stops
// asking.
func TestSyncGuestListenPortsOlderWorkerKeepsOneListener(t *testing.T) {
	for _, unsupported := range []error{
		worker.ErrListenPortsUnsupported,
		fmt.Errorf("%w: resident", worker.ErrListenPortsUnsupported),
	} {
		c := &listenPortsWorkerClient{listErr: unsupported}
		c.resolvedPort = 19081
		d := newListenPortsDriver(t, c)
		old := guestListening
		guestListening = func(port int) bool { return port == 19081 }
		ctx := context.Background()
		if err := d.SyncGuestListenPorts(ctx, "sb-ports", []int{8080, 9090}); err != nil {
			guestListening = old
			t.Fatal(err)
		}
		inst, _ := d.instance("sb-ports")
		st := inst.guestListen()
		if !st.legacy || st.primary != 19081 || len(st.ports) != 0 {
			guestListening = old
			t.Fatalf("state = %+v", st)
		}
		queries := c.queries
		if err := d.SyncGuestListenPorts(ctx, "sb-ports", []int{8080, 9090}); err != nil {
			guestListening = old
			t.Fatal(err)
		}
		guestListening = old
		if c.queries != queries {
			t.Fatal("asked an older worker for per-port listeners again")
		}
		if err := d.guestHTTPProxy("sb-ports", 9090, newDiscardWriter(), &http.Request{}); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(c.proxied) != "[0]" {
			t.Fatalf("an older worker was sent port %v, want 0", c.proxied)
		}
	}
}

func TestSyncGuestListenPortsErrors(t *testing.T) {
	ctx := context.Background()
	c := &listenPortsWorkerClient{listErr: errors.New("socket gone")}
	if err := newListenPortsDriver(t, c).SyncGuestListenPorts(ctx, "sb-ports", []int{8080}); err == nil || errors.Is(err, worker.ErrListenPortsUnsupported) {
		t.Fatalf("query error = %v", err)
	}
	c = &listenPortsWorkerClient{setErr: errors.New("bind failed")}
	if err := newListenPortsDriver(t, c).SyncGuestListenPorts(ctx, "sb-ports", []int{8080}); err == nil {
		t.Fatal("set error swallowed")
	}
	c = &listenPortsWorkerClient{noPrimary: true}
	if err := newListenPortsDriver(t, c).SyncGuestListenPorts(ctx, "sb-ports", []int{8080}); err == nil {
		t.Fatal("a set with no bound listener passed")
	}
	// Turning listeners off when the worker fails stays an error.
	c = &listenPortsWorkerClient{live: map[int]int{8080: 41000}, setErr: errors.New("boom")}
	if err := newListenPortsDriver(t, c).SyncGuestListenPorts(ctx, "sb-ports", nil); err == nil {
		t.Fatal("off error swallowed")
	}
	// A guest that does not come up is reported.
	c = &listenPortsWorkerClient{}
	d := newListenPortsDriver(t, c)
	d.waitListenReady = func(string, int) error { return errors.New("not up") }
	if err := d.SyncGuestListenPorts(ctx, "sb-ports", []int{8080}); err == nil {
		t.Fatal("readiness error swallowed")
	}
}

// Two exposes at once: the syncs run one after the other, so the worker
// never re-instantiates the guest twice at once, and the last set wins.
func TestSyncGuestListenPortsConcurrentExposes(t *testing.T) {
	c := &listenPortsWorkerClient{setDelay: 20 * time.Millisecond}
	d := newListenPortsDriver(t, c)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, set := range [][]int{{8080}, {8080, 9090}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- d.SyncGuestListenPorts(ctx, "sb-ports", set)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if c.overlap.Load() {
		t.Fatal("two set_listen_ports ran at once")
	}
	// Whichever ran last, the guest serves 8080; a final sync of the full
	// set (the service's, which reads the store under its lock) ends with
	// both.
	if err := d.SyncGuestListenPorts(ctx, "sb-ports", []int{8080, 9090}); err != nil {
		t.Fatal(err)
	}
	inst, _ := d.instance("sb-ports")
	if st := inst.guestListen(); st.ports[8080] <= 0 || st.ports[9090] <= 0 {
		t.Fatalf("state = %+v", st)
	}
}

// The driver says once that a sandbox serves HTTP on a fallback engine.
func TestNoteGuestListenersLogsAFallbackOnce(t *testing.T) {
	var buf bytes.Buffer
	c := &listenPortsWorkerClient{engine: "wazero", fallback: "wasmtime"}
	d := newListenPortsDriver(t, c)
	d.logger = slog.New(slog.NewTextHandler(&buf, nil))
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := d.SyncGuestListenPorts(ctx, "sb-ports", []int{8080}); err != nil {
			t.Fatal(err)
		}
	}
	if n := bytes.Count(buf.Bytes(), []byte("serves HTTP on another engine")); n != 1 {
		t.Fatalf("fallback logged %d times:\n%s", n, buf.String())
	}
	inst, _ := d.instance("sb-ports")
	if inst.guestListen().engine != "wazero" {
		t.Fatalf("engine = %q", inst.guestListen().engine)
	}
}

// Adoption reads the listeners back from the record: a per-port map means a
// worker of this release, a lone listener one from an older release.
func TestAdoptRestoresGuestListeners(t *testing.T) {
	cases := []struct {
		name       string
		rec        instanceRecord
		wantLegacy bool
		wantPorts  int
	}{
		{"per port", instanceRecord{ListenPort: 41001, ListenPorts: map[int]int{8080: 41001, 9090: 41002}, ListenEngine: "wazero"}, false, 2},
		{"one listener", instanceRecord{ListenPort: 41001}, true, 0},
		{"none", instanceRecord{}, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, _, _, clients := adoptDriver(t, true)
			sock := filepath.Join(d.cfg.RunDir, "sb-w", "worker.sock")
			clients[sock] = &socketClient{loaded: map[string]bool{"sb-w": true}}
			withFound(t, []worker.FoundWorker{{PID: 3, Socket: sock, Proc: &heldProc{pid: 3}}}, nil)
			d.AdoptWorkers(context.Background())
			if err := os.MkdirAll(d.sandboxDir("sb-w"), 0o700); err != nil {
				t.Fatal(err)
			}
			tc.rec.SandboxID, tc.rec.Socket, tc.rec.WorkerKey = "sb-w", sock, "sb-w"
			if err := d.ensureHostDirs(); err != nil {
				t.Fatal(err)
			}
			if err := writeFileAtomic(d.instanceRecordPath("sb-w"), tc.rec); err != nil {
				t.Fatal(err)
			}
			if _, err := d.AdoptSandbox(context.Background(), &models.Sandbox{ID: "sb-w"}, nil); err != nil {
				t.Fatalf("AdoptSandbox: %v", err)
			}
			inst, _ := d.instance("sb-w")
			st := inst.guestListen()
			if st.legacy != tc.wantLegacy || len(st.ports) != tc.wantPorts || st.primary != tc.rec.ListenPort || st.engine != tc.rec.ListenEngine {
				t.Fatalf("state = %+v", st)
			}
		})
	}
}

// A restart starts the guest without listeners, maybe on a new worker:
// the driver forgets the old ones.
func TestStartForgetsGuestListeners(t *testing.T) {
	sup := &fakeSupervisor{}
	c := &listenPortsWorkerClient{}
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.supervisor = sup
	d.newWorkerClient = func(string) WorkerClient { return c }
	inst := &sandboxInstance{sandboxID: "sb-restart", socketPath: "/tmp/fake.sock", status: models.SandboxStatusStopped,
		resolvedListenPort: 41000, listenPorts: map[int]int{8080: 41000}, legacyListen: true}
	d.mu.Lock()
	d.byID["sb-restart"] = inst
	d.mu.Unlock()
	if _, err := d.Start(context.Background(), "sb-restart"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := inst.guestListen(); st.primary != 0 || len(st.ports) != 0 || st.legacy {
		t.Fatalf("state after start = %+v", st)
	}
}

func TestDesiredListenPorts(t *testing.T) {
	if got := fmt.Sprint(desiredListenPorts([]int{9090, 0, 8080, 70000, 9090, -1})); got != "[8080 9090]" {
		t.Fatalf("desiredListenPorts = %s", got)
	}
	if !coversPorts(map[int]int{8080: 1, 9090: 2}, []int{9090}) || coversPorts(map[int]int{8080: 1}, []int{8080, 9090}) || coversPorts(map[int]int{8080: 0}, []int{8080}) {
		t.Fatal("coversPorts")
	}
}

type discardWriter struct{ h http.Header }

func newDiscardWriter() *discardWriter               { return &discardWriter{h: http.Header{}} }
func (w *discardWriter) Header() http.Header         { return w.h }
func (w *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *discardWriter) WriteHeader(int)             {}

// The whole path on a real worker: a guest that reads AEROL_WASM_LISTEN_FDS
// answers each exposed port on its own listener through the driver's HTTP
// gateway, and a re-sync of the same ports leaves it serving.
func TestDriverServesEachExposedPortOnItsOwnListener(t *testing.T) {
	absMod := ensureWasip1HTTPWasm(t)
	runDir := shortRunDir(t)
	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	driver := New(Config{RunDir: runDir, ModulesDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
	driver.SetModuleResolver(fakeResolver{path: absMod, digest: "wasip1-http"})
	driver.SetWorkerSupervisor(sup)

	ctx := context.Background()
	const sandboxID = "sb-multiport"
	if _, err := driver.Create(ctx, models.CreateSandboxRequest{
		Image: "wasip1-http.wasm", ContainerCommand: []string{"aerolhttp", "multiport"},
	}, sandboxID, "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ports := []int{8080, 9090}
	if err := driver.SyncGuestListenPorts(ctx, sandboxID, ports); err != nil {
		t.Fatalf("SyncGuestListenPorts: %v", err)
	}
	driver.SyncAllowedPorts(sandboxID, ports)
	inst, err := driver.instance(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	before := inst.guestListen()
	if len(before.ports) != 2 || before.legacy {
		t.Fatalf("listeners = %+v", before)
	}

	get := func(port int) string {
		dial, err := driver.EnsureHTTPListener(ctx, sandboxID, port)
		if err != nil {
			t.Fatalf("EnsureHTTPListener(%d): %v", port, err)
		}
		var last string
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			resp, err := http.Get("http://" + dial + "/port")
			if err != nil {
				last = err.Error()
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			last = string(body)
			if resp.StatusCode == http.StatusOK && last == fmt.Sprint(port) {
				return last
			}
		}
		t.Fatalf("port %d answered %q", port, last)
		return ""
	}
	get(8080)
	get(9090)

	// Reconcile and re-expose sync the same ports: no re-instantiation.
	if err := driver.SyncGuestListenPorts(ctx, sandboxID, ports); err != nil {
		t.Fatalf("re-sync: %v", err)
	}
	if after := inst.guestListen(); fmt.Sprint(after.ports) != fmt.Sprint(before.ports) {
		t.Fatalf("listeners changed on a re-sync: %v -> %v", before.ports, after.ports)
	}
	get(9090)
}
