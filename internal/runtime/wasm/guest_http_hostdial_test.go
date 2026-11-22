package wasm

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// hostDialClient records which proxy path the driver took.
type hostDialClient struct {
	recordingWorkerClient
	mu        sync.Mutex
	dialedErr error
	dialed    []string // "host ports guestPort"
	host      string
	ports     []int
	plain     int
	block     chan struct{}
	started   chan struct{}
}

func (c *hostDialClient) ProxyHTTPDialed(_ string, guestPort int, host string, ports []int, in, out *atomic.Int64, _ http.ResponseWriter, _ *http.Request) error {
	c.mu.Lock()
	c.host, c.ports = host, ports
	c.dialed = append(c.dialed, host)
	c.mu.Unlock()
	if c.block != nil {
		c.started <- struct{}{}
		<-c.block
	}
	if c.dialedErr == nil {
		in.Add(7)
		out.Add(11)
	}
	return c.dialedErr
}

func (c *hostDialClient) ProxyHTTP(string, int, http.ResponseWriter, *http.Request) error {
	c.mu.Lock()
	c.plain++
	c.mu.Unlock()
	return nil
}

// sandboxd connects to the guest's listener itself and names only the
// listener ports it knows for the sandbox; a worker from an older release
// gets the plain proxy_http, and one that predates per-port listeners is
// never asked.
func TestGuestHTTPProxyHostDials(t *testing.T) {
	for _, tc := range []struct {
		name      string
		st        func(*sandboxInstance)
		dialedErr error
		dialed    int
		plain     int
		wantErr   bool
	}{
		{"this release", func(i *sandboxInstance) {
			i.resolvedListenPort, i.listenPorts = 41000, map[int]int{8080: 41000, 9090: 41001}
		}, nil, 1, 0, false},
		{"older release", func(i *sandboxInstance) { i.resolvedListenPort, i.listenPorts = 41000, map[int]int{8080: 41000} }, worker.ErrHostDialUnsupported, 1, 1, false},
		{"refused listener", func(i *sandboxInstance) { i.resolvedListenPort, i.listenPorts = 41000, map[int]int{8080: 41000} }, errors.New("guest listener: port 1 is not one of this sandbox's listeners"), 1, 0, true},
		{"before per-port listeners", func(i *sandboxInstance) { i.resolvedListenPort, i.legacyListen = 41000, true }, nil, 0, 1, false},
	} {
		d := New(Config{ModulesDir: t.TempDir(), GuestListenHost: "127.0.97.1"}, nil)
		client := &hostDialClient{dialedErr: tc.dialedErr}
		d.SetWorkerClientFactory(func(string) WorkerClient { return client })
		inst := &sandboxInstance{sandboxID: "sb-hd", socketPath: "/tmp/fake.sock", status: models.SandboxStatusStarted}
		tc.st(inst)
		d.mu.Lock()
		d.byID["sb-hd"] = inst
		d.mu.Unlock()
		err := d.guestHTTPProxy("sb-hd", 8080, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		if (err != nil) != tc.wantErr || len(client.dialed) != tc.dialed || client.plain != tc.plain {
			t.Fatalf("%s: err=%v dialed=%d plain=%d", tc.name, err, len(client.dialed), client.plain)
		}
		if tc.dialed > 0 {
			slices.Sort(client.ports)
			want := []int{41000}
			if len(inst.listenPorts) == 2 {
				want = []int{41000, 41000, 41001}
			} else if len(inst.listenPorts) == 1 {
				want = []int{41000, 41000}
			}
			if client.host != "127.0.97.1" || !slices.Equal(client.ports, want) {
				t.Fatalf("%s: host %q ports %v, want %v", tc.name, client.host, client.ports, want)
			}
		}
	}
}

func TestListenerPorts(t *testing.T) {
	if got := (guestListenState{}).listenerPorts(); len(got) != 0 {
		t.Fatalf("none = %v", got)
	}
	got := guestListenState{primary: 5, ports: map[int]int{80: 5, 81: 6, 82: 0}}.listenerPorts()
	slices.Sort(got)
	if !slices.Equal(got, []int{5, 5, 6}) {
		t.Fatalf("ports = %v", got)
	}
}

// sandboxd counts what it relays as the sandbox's usage, in the counters
// its worker's counts join (DrainNetworkByteCounters).
func TestGuestHTTPProxyCountsUsage(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir(), GuestListenHost: "127.0.97.1"}, nil)
	client := &hostDialClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	d.mu.Lock()
	d.byID["sb-u"] = &sandboxInstance{sandboxID: "sb-u", socketPath: "/tmp/fake.sock", status: models.SandboxStatusStarted, resolvedListenPort: 41000, listenPorts: map[int]int{8080: 41000}}
	d.mu.Unlock()
	if err := d.guestHTTPProxy("sb-u", 8080, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
		t.Fatal(err)
	}
	got := d.net.DrainNetworkByteCounters()["sb-u"]
	if got.BytesIn != 7 || got.BytesOut != 11 {
		t.Fatalf("usage = %+v, want in 7 out 11", got)
	}
}

// Past GuestHTTPMaxInFlight requests at once, a sandbox's next request is
// refused at once (the gateway answers 503), and a slot frees when one
// ends.
func TestGuestHTTPProxyCapsInFlight(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir(), GuestListenHost: "127.0.97.1", GuestHTTPMaxInFlight: 2}, nil)
	client := &hostDialClient{block: make(chan struct{}), started: make(chan struct{}, 2)}
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	d.mu.Lock()
	d.byID["sb-c"] = &sandboxInstance{sandboxID: "sb-c", socketPath: "/tmp/fake.sock", status: models.SandboxStatusStarted, resolvedListenPort: 41000, listenPorts: map[int]int{8080: 41000}}
	d.mu.Unlock()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.guestHTTPProxy("sb-c", 8080, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}
	<-client.started
	<-client.started
	err := d.guestHTTPProxy("sb-c", 8080, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrGuestBusy) {
		t.Fatalf("third request = %v, want ErrGuestBusy", err)
	}
	close(client.block)
	wg.Wait()
	if err := d.guestHTTPProxy("sb-c", 8080, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
		t.Fatalf("after the others ended: %v", err)
	}
	if New(Config{}, nil).guestHTTPMaxInFlight() != defaultGuestHTTPMaxInFlight {
		t.Fatal("default cap")
	}

	// The gateway answers a busy sandbox with 503.
	d.SyncAllowedPorts("sb-c", []int{8080})
	d.net.SetHTTPProxy(func(string, int, http.ResponseWriter, *http.Request) error { return ErrGuestBusy })
	rec := httptest.NewRecorder()
	d.net.serveHTTP("sb-c", 8080, rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("gateway status %d, want 503", rec.Code)
	}
}
