package worker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// fakeMultiListenEngine is a MultiListenEngine whose listeners and accepts
// the test sets.
type fakeMultiListenEngine struct {
	fakeNetworkAwareEngine
	listeners    []wasmengine.WASIListener
	accepted     map[int]bool
	instantiated []wasmengine.Capabilities
	instErr      error
	noListen     bool
}

func (f *fakeMultiListenEngine) Instantiate(_ context.Context, caps wasmengine.Capabilities) error {
	f.instantiated = append(f.instantiated, caps)
	return f.instErr
}
func (f *fakeMultiListenEngine) ResolvedListeners() []wasmengine.WASIListener {
	return append([]wasmengine.WASIListener(nil), f.listeners...)
}
func (f *fakeMultiListenEngine) ListenerAccepted(guestPort int) bool { return f.accepted[guestPort] }
func (f *fakeMultiListenEngine) SupportsListen() bool                { return !f.noListen }

// serveOnce runs one framed request through s.Serve.
func serveOnce(t *testing.T, s *Server, env Envelope) Envelope {
	t.Helper()
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	if err := writeFrame(c1, env); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = c1.Close()
	<-done
	return reply
}

func decodeReport(t *testing.T, reply Envelope) listenPortsPayload {
	t.Helper()
	if reply.Type != MsgOK {
		var p errorPayload
		_ = decodePayload(reply.Payload, &p)
		t.Fatalf("reply = %s %q", reply.Type, p.Message)
	}
	var p listenPortsPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSetListenPortsInstantiatesOneListenerPerPort(t *testing.T) {
	eng := &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{
		{GuestPort: 8080, HostPort: 41000}, {GuestPort: 9090, HostPort: 41001},
	}}
	s := &Server{eng: eng, lastCaps: wasmengine.Capabilities{WASIListenPort: 5555, Args: []string{"a"}}}
	reply := serveOnce(t, s, Envelope{Type: MsgSetListenPorts, SandboxID: "sb",
		Payload: mustPayload(t, setListenPortsPayload{Ports: []int{9090, 8080, 9090}, Host: "127.0.0.1"})})
	report := decodeReport(t, reply)
	if report.Primary != 41000 || report.Ports[8080] != 41000 || report.Ports[9090] != 41001 || report.Engine != "wazero" {
		t.Fatalf("report = %+v", report)
	}
	if len(eng.instantiated) != 1 {
		t.Fatalf("instantiations = %d, want 1", len(eng.instantiated))
	}
	caps := eng.instantiated[0]
	if caps.WASIListenPort != wasmengine.WASIListenPortDisabled || len(caps.WASIListeners) != 2 ||
		caps.WASIListeners[0] != (wasmengine.WASIListener{GuestPort: 8080}) || caps.WASIListeners[1] != (wasmengine.WASIListener{GuestPort: 9090}) ||
		caps.WASIListenHost != "127.0.0.1" || len(caps.Args) != 1 {
		t.Fatalf("instantiated caps = %+v", caps)
	}
	// The bound host ports are kept, so set_capability re-binds the same ones.
	if s.lastCaps.WASIListeners[0].HostPort != 41000 || s.lastCaps.WASIListeners[1].HostPort != 41001 {
		t.Fatalf("lastCaps listeners = %+v", s.lastCaps.WASIListeners)
	}

	// No ports turns them off.
	eng.listeners = nil
	report = decodeReport(t, serveOnce(t, s, Envelope{Type: MsgSetListenPorts, SandboxID: "sb", Payload: mustPayload(t, setListenPortsPayload{})}))
	if report.Primary != 0 || len(report.Ports) != 0 {
		t.Fatalf("report after off = %+v", report)
	}
	if last := eng.instantiated[len(eng.instantiated)-1]; last.ListenEnabled() {
		t.Fatalf("caps after off = %+v", last)
	}
}

func TestSetListenPortsErrors(t *testing.T) {
	cases := []struct {
		name    string
		s       *Server
		payload []byte
		want    string
	}{
		{"bad payload", &Server{eng: &fakeMultiListenEngine{}}, []byte(`{`), "unexpected"},
		{"bad port", &Server{eng: &fakeMultiListenEngine{}}, mustPayload(t, setListenPortsPayload{Ports: []int{70000}}), "invalid listen port"},
		{"no engine", &Server{}, mustPayload(t, setListenPortsPayload{Ports: []int{8080}}), "engine not loaded"},
		{"engine cannot listen", &Server{eng: &fakeMultiListenEngine{noListen: true}}, mustPayload(t, setListenPortsPayload{Ports: []int{8080}}), "not supported"},
		{"instantiate fails", &Server{eng: &fakeMultiListenEngine{instErr: errors.New("boom")}}, mustPayload(t, setListenPortsPayload{Ports: []int{8080}}), "boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := serveOnce(t, tc.s, Envelope{Type: MsgSetListenPorts, SandboxID: "sb", Payload: tc.payload})
			var p errorPayload
			if reply.Type != MsgError || decodePayload(reply.Payload, &p) != nil || !strings.Contains(p.Message, tc.want) {
				t.Fatalf("reply = %s %q, want an error with %q", reply.Type, p.Message, tc.want)
			}
		})
	}
	// Turning listeners off needs no listen support.
	s := &Server{eng: &fakeMultiListenEngine{noListen: true}}
	decodeReport(t, serveOnce(t, s, Envelope{Type: MsgSetListenPorts, SandboxID: "sb", Payload: mustPayload(t, setListenPortsPayload{})}))
}

func TestListenPortsReport(t *testing.T) {
	// No engine: nothing listens.
	report := decodeReport(t, serveOnce(t, &Server{}, Envelope{Type: MsgListenPorts, SandboxID: "sb"}))
	if report.Primary != 0 || report.Engine == "" {
		t.Fatalf("report without engine = %+v", report)
	}
	// An engine with one listener for every port reports only the primary.
	report = decodeReport(t, serveOnce(t, &Server{eng: &fakeNetworkAwareEngine{port: 4242}}, Envelope{Type: MsgListenPorts, SandboxID: "sb"}))
	if report.Primary != 4242 || len(report.Ports) != 0 {
		t.Fatalf("single-listener report = %+v", report)
	}
	// A single WASIListenPort listener on a multi-listen engine has guest
	// port 0: it is the primary and no port's own.
	eng := &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{{HostPort: 4343}}}
	report = decodeReport(t, serveOnce(t, &Server{eng: eng}, Envelope{Type: MsgListenPorts, SandboxID: "sb"}))
	if report.Primary != 4343 || len(report.Ports) != 0 {
		t.Fatalf("legacy listener report = %+v", report)
	}
	// Asking changes nothing.
	if len(eng.instantiated) != 0 {
		t.Fatal("listen_ports re-instantiated the guest")
	}
}

func TestListenerFor(t *testing.T) {
	multi := &fakeMultiListenEngine{
		listeners: []wasmengine.WASIListener{{GuestPort: 8080, HostPort: 41000}, {GuestPort: 9090, HostPort: 41001}},
		accepted:  map[int]bool{9090: true},
	}
	unaccepted := &fakeMultiListenEngine{listeners: multi.listeners}
	cases := []struct {
		name      string
		eng       wasmengine.Engine
		guestPort int
		want      int
	}{
		{"no engine", nil, 8080, 0},
		{"single listener", &fakeNetworkAwareEngine{port: 4242}, 9090, 4242},
		{"single listener gone", &fakeNetworkAwareEngine{}, 9090, 0},
		{"no live listener", &fakeMultiListenEngine{}, 8080, 0},
		{"its own listener once accepted", multi, 9090, 41001},
		{"the primary while unaccepted", unaccepted, 9090, 41000},
		{"the primary for its own port", multi, 8080, 41000},
		{"the primary for an unknown port", multi, 7070, 41000},
		{"the primary for port 0", multi, 0, 41000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := listenerFor(tc.eng, tc.guestPort); got != tc.want {
				t.Fatalf("listenerFor(%d) = %d, want %d", tc.guestPort, got, tc.want)
			}
		})
	}
}

func TestNormalizeListenPorts(t *testing.T) {
	got, err := normalizeListenPorts([]int{9090, 8080, 9090, 1, 65535})
	if err != nil || len(got) != 4 || got[0] != 1 || got[1] != 8080 || got[2] != 9090 || got[3] != 65535 {
		t.Fatalf("normalize = %v, %v", got, err)
	}
	for _, bad := range []int{0, -1, 65536} {
		if _, err := normalizeListenPorts([]int{bad}); err == nil {
			t.Fatalf("port %d accepted", bad)
		}
	}
}

// An adopted worker from an older release answers a message it does not
// know with an empty invoke_result, and a resident host refuses listener
// work: both read as ErrListenPortsUnsupported, so the driver keeps the
// one listener. Any other error stays itself.
func TestClientListenPortsReplies(t *testing.T) {
	okBody := mustPayload(t, listenPortsPayload{Ports: map[int]int{8080: 41000}, Primary: 41000, Engine: "wazero", FallbackFrom: "wasmtime"})
	cases := []struct {
		name        string
		reply       Envelope
		unsupported bool
		wantErr     bool
	}{
		{"report", Envelope{Type: MsgOK, Payload: okBody}, false, false},
		{"old worker", Envelope{Type: MsgInvokeResult}, true, true},
		{"resident host", Envelope{Type: MsgError, Payload: mustPayload(t, errorPayload{Message: "set_listen_ports not supported in resident-host mode (route to per-sandbox worker)"})}, true, true},
		{"other error", Envelope{Type: MsgError, Payload: mustPayload(t, errorPayload{Message: "engine not loaded"})}, false, true},
		{"bad error payload", Envelope{Type: MsgError, Payload: []byte(`{`)}, false, true},
		{"bad report", Envelope{Type: MsgOK, Payload: []byte(`{`)}, false, true},
		{"unexpected type", Envelope{Type: MsgPong}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, call := range []func(*Client) (ListenPorts, error){
				func(c *Client) (ListenPorts, error) { return c.ListenPorts("sb") },
				func(c *Client) (ListenPorts, error) { return c.SetListenPorts("sb", []int{8080}, "127.0.0.1") },
			} {
				c := NewClient("dummy")
				c.dial = mockDialer(t, tc.reply)
				got, err := call(c)
				if (err != nil) != tc.wantErr || errors.Is(err, ErrListenPortsUnsupported) != tc.unsupported {
					t.Fatalf("err = %v, want err %v unsupported %v", err, tc.wantErr, tc.unsupported)
				}
				if !tc.wantErr && (got.Primary != 41000 || got.Ports[8080] != 41000 || got.Engine != "wazero" || got.FallbackFrom != "wasmtime") {
					t.Fatalf("report = %+v", got)
				}
			}
		})
	}
	// Transport errors pass through.
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) { return nil, errors.New("dial boom") }
	if _, err := c.ListenPorts("sb"); err == nil {
		t.Fatal("ListenPorts without a worker succeeded")
	}
	if _, err := c.SetListenPorts("sb", nil, ""); err == nil {
		t.Fatal("SetListenPorts without a worker succeeded")
	}
	orig := encodePayload
	encodePayload = func(any) ([]byte, error) { return nil, errors.New("encode boom") }
	_, err := c.SetListenPorts("sb", nil, "")
	encodePayload = orig
	if err == nil {
		t.Fatal("SetListenPorts with a failing encoder succeeded")
	}
}

// A real resident host refuses the messages in a way the client reads as
// unsupported.
func TestResidentHostRefusesListenPorts(t *testing.T) {
	rs := &ResidentServer{}
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() { _ = rs.Serve(c2) }()
		return c1, nil
	}
	if _, err := c.SetListenPorts("sb", []int{8080}, ""); !errors.Is(err, ErrListenPortsUnsupported) {
		t.Fatalf("resident SetListenPorts = %v", err)
	}
	if _, err := c.ListenPorts("sb"); !errors.Is(err, ErrListenPortsUnsupported) {
		t.Fatalf("resident ListenPorts = %v", err)
	}
}

func TestServeListenPortsWriteErrors(t *testing.T) {
	s := &Server{eng: &fakeMultiListenEngine{}}
	orig := encodePayload
	t.Cleanup(func() { encodePayload = orig })
	encodePayload = func(any) ([]byte, error) { return nil, errors.New("encode boom") }
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if err := s.serveListenPorts(context.Background(), c2, Envelope{Type: MsgListenPorts}); err == nil {
		t.Fatal("report encode error not returned")
	}
	if err := s.serveListenPorts(context.Background(), c2, Envelope{Type: MsgSetListenPorts, Payload: []byte(`{`)}); err == nil {
		t.Fatal("error encode error not returned")
	}
	// A failed write ends Serve.
	encodePayload = orig
	_ = c1.Close()
	if err := s.serveListenPorts(context.Background(), c2, Envelope{Type: MsgListenPorts}); err == nil {
		t.Fatal("write to a closed conn succeeded")
	}
}

// getPort asks a worker's guest, through ProxyHTTP on exposed port port,
// which port it answered on.
func getPort(t *testing.T, client *Client, sandboxID string, port int) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://gateway/port", nil)
	var last string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		rec := httptest.NewRecorder()
		if err := client.ProxyHTTP(sandboxID, port, rec, req); err != nil {
			last = err.Error()
			continue
		}
		body, _ := io.ReadAll(rec.Body)
		if rec.Code == http.StatusOK {
			return string(body)
		}
		last = string(body)
	}
	t.Fatalf("GET /port on %d: %s", port, last)
	return ""
}

// startServingGuest loads the aerolhttp guest in a test worker, gives it a
// listener per port and starts its _start.
func startServingGuest(t *testing.T, sandboxID string, args []string, ports []int) *Client {
	t.Helper()
	modPath := ensureWasip1HTTPWasm(t)
	client, cleanup := startTestWorker(t)
	t.Cleanup(cleanup)
	if _, err := client.LoadModule(sandboxID, modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := client.Instantiate(sandboxID, wasmengine.Capabilities{
		WASIListenPort: wasmengine.WASIListenPortDisabled,
		Args:           args,
		Preopens:       []wasmengine.Preopen{{GuestPath: "/work", HostPath: t.TempDir()}},
	}); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	report, err := client.SetListenPorts(sandboxID, ports, "127.0.0.1")
	if err != nil {
		t.Fatalf("SetListenPorts: %v", err)
	}
	if report.Primary <= 0 || len(report.Ports) != len(ports) {
		t.Fatalf("report = %+v", report)
	}
	go func() { _ = client.Invoke(sandboxID, "_start") }()
	t.Cleanup(func() { _ = client.StopInstance(sandboxID) })
	return client
}

// A guest that reads AEROL_WASM_LISTEN_FDS serves each exposed port on its
// own listener: the two ports answer differently.
func TestWorkerServesEachPortOnItsOwnListener(t *testing.T) {
	client := startServingGuest(t, "sb-multiport", []string{"aerolhttp", "multiport"}, []int{8080, 9090})
	if got := getPort(t, client, "sb-multiport", 8080); got != "8080" {
		t.Fatalf("port 8080 answered %q", got)
	}
	// The guest accepts on every listener as it starts; until it reaches
	// 9090's, a request for 9090 goes to the primary.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := getPort(t, client, "sb-multiport", 9090)
		if got == "9090" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("port 9090 answered %q", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
	report, err := client.ListenPorts("sb-multiport")
	if err != nil || report.Ports[8080] <= 0 || report.Ports[9090] <= 0 || report.Primary != report.Ports[8080] {
		t.Fatalf("ListenPorts = %+v, %v", report, err)
	}
}

// A guest written for one listener accepts only on AEROL_WASM_LISTEN_FD (the
// lowest port's): with two exposed ports it still serves both.
func TestWorkerSingleListenerGuestServesEveryPort(t *testing.T) {
	client := startServingGuest(t, "sb-singleport", []string{"aerolhttp"}, []int{8080, 9090})
	for _, port := range []int{8080, 9090, 8080} {
		if got := getPort(t, client, "sb-singleport", port); got != "single" {
			t.Fatalf("port %d answered %q", port, got)
		}
	}
}
