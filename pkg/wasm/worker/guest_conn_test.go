package worker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// The guest_listener reply decides whether sandboxd connects itself: a
// worker from an older release (an unknown message, a resident host, a
// platform that cannot) says so, and anything else is an error, never a
// connection.
func TestConnectGuestReplies(t *testing.T) {
	errBody := func(msg string) []byte { return mustPayload(t, errorPayload{Message: msg}) }
	for _, tc := range []struct {
		name        string
		reply       Envelope
		unsupported bool
		want        string
	}{
		{"older worker", Envelope{Type: MsgInvokeResult}, true, ""},
		{"resident host", Envelope{Type: MsgError, Payload: errBody("guest_listener not supported in resident-host mode (route to per-sandbox worker)")}, true, ""},
		{"cannot here", Envelope{Type: MsgError, Payload: errBody(ErrHostDialUnsupported.Error())}, true, ""},
		{"not listening", Envelope{Type: MsgError, Payload: errBody("wasm guest is not listening")}, false, "not listening"},
		{"bad error body", Envelope{Type: MsgError, Payload: []byte("{")}, false, ""},
		{"odd reply", Envelope{Type: MsgPong}, false, "unexpected reply"},
		{"no socket", Envelope{Type: MsgOK}, false, "no listening socket"},
	} {
		_, _, err := connectGuest(tc.reply, nil, "127.0.0.1", []int{1})
		if err == nil || errors.Is(err, ErrHostDialUnsupported) != tc.unsupported || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}

// The reverse proxy gets the one connection sandboxd opened, and no other.
func TestOneConnDialer(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	dial := oneConnDialer(c1)
	if got, err := dial(context.Background()); err != nil || got != c1 {
		t.Fatalf("first dial = %v, %v", got, err)
	}
	if _, err := dial(context.Background()); err == nil {
		t.Fatal("a second dial got a connection")
	}
}

func TestFinishProxyHTTP(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := finishProxyHTTP(Envelope{Type: MsgProxyHTTPResult, Payload: mustPayload(t, proxyHTTPResultPayload{StatusCode: 201, Body: []byte("ok")})}, rec); err != nil || rec.Code != 201 || rec.Body.String() != "ok" {
		t.Fatalf("result = %v %d %q", err, rec.Code, rec.Body.String())
	}
	for _, reply := range []Envelope{
		{Type: MsgError, Payload: mustPayload(t, errorPayload{Message: "boom"})},
		{Type: MsgError, Payload: []byte("{")},
		{Type: MsgPong},
		{Type: MsgProxyHTTPResult, Payload: []byte("{")},
	} {
		if err := finishProxyHTTP(reply, httptest.NewRecorder()); err == nil {
			t.Errorf("reply %s passed", reply.Type)
		}
	}
}

// A worker that dropped its privileges opens no connection to its guest:
// a proxy_http without one is refused, whatever the guest listens on.
func TestConfinedWorkerRefusesToDialItsGuest(t *testing.T) {
	confined.Store(true)
	t.Cleanup(func() { confined.Store(false) })
	port, conns := sentinelListener(t)
	s := &Server{eng: &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{{GuestPort: 8080, HostPort: port}}}}
	reply := serveOnce(t, s, Envelope{Type: MsgProxyHTTP, SandboxID: "sb", Payload: mustPayload(t, proxyHTTPPayload{GuestPort: 8080, Method: http.MethodGet, RequestURI: "/"})})
	var p errorPayload
	_ = decodePayload(reply.Payload, &p)
	if reply.Type != MsgError || p.Message != errGuestConnRequired.Error() {
		t.Fatalf("reply = %s %q", reply.Type, p.Message)
	}
	if n := conns(); n != 0 {
		t.Fatalf("the confined worker dialed its guest %d times", n)
	}
}

// Where the worker cannot find its listening sockets (off Linux), it says
// it does not take guest connections, and sandboxd falls back to the
// worker's own dial.
func TestGuestListenerUnsupportedHere(t *testing.T) {
	prev := hostDialSupported
	hostDialSupported = false
	t.Cleanup(func() { hostDialSupported = prev })
	s := &Server{eng: &fakeMultiListenEngine{}}
	reply := serveOnce(t, s, Envelope{Type: MsgGuestListener, SandboxID: "sb", Payload: mustPayload(t, guestListenerPayload{GuestPort: 8080})})
	if _, _, err := connectGuest(reply, nil, "127.0.0.1", nil); !errors.Is(err, ErrHostDialUnsupported) {
		t.Fatalf("reply %s: %v", reply.Type, err)
	}
	// A payload that does not decode is an error, not a fallback.
	reply = serveOnce(t, s, Envelope{Type: MsgGuestListener, SandboxID: "sb", Payload: []byte("{")})
	if _, _, err := connectGuest(reply, nil, "127.0.0.1", nil); err == nil || errors.Is(err, ErrHostDialUnsupported) {
		t.Fatalf("bad payload: %v", err)
	}
}

func TestRawFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	if fd, err := rawFD(f); err != nil || fd < 0 {
		t.Fatalf("rawFD = %d, %v", fd, err)
	}
	_ = f.Close()
	if _, err := rawFD(f); err == nil {
		t.Fatal("rawFD of a closed file")
	}
}
