package wasm

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// hostDialClient records which proxy path the driver took.
type hostDialClient struct {
	recordingWorkerClient
	dialedErr error
	dialed    []string // "host ports guestPort"
	host      string
	ports     []int
	plain     int
}

func (c *hostDialClient) ProxyHTTPDialed(_ string, guestPort int, host string, ports []int, _ http.ResponseWriter, _ *http.Request) error {
	c.host, c.ports = host, ports
	c.dialed = append(c.dialed, host)
	return c.dialedErr
}

func (c *hostDialClient) ProxyHTTP(string, int, http.ResponseWriter, *http.Request) error {
	c.plain++
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
