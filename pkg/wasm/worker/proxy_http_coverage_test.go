package worker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestCoverage95ProxyRecorderEdges(t *testing.T) {
	r := newLimitedProxyResponseRecorder(2)
	if _, err := r.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if !r.Overflowed() || string(r.Body()) != "ab" {
		t.Fatalf("recorder = overflow:%v body:%q", r.Overflowed(), r.Body())
	}
	if _, err := r.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	if r.StatusCode() != http.StatusOK {
		t.Fatalf("implicit status = %d", r.StatusCode())
	}

	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenPort: wasmengine.WASIListenPortDisabled}}
	if _, err := s.guestHTTPTarget(0); err == nil {
		t.Fatal("disabled guest listener unexpectedly resolved")
	}
	s.lastCaps = wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: 1}
	if _, err := s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{Method: "BAD METHOD", RequestURI: "/"}); err == nil {
		t.Fatal("invalid method unexpectedly succeeded")
	}
}

func TestCoverage95ProxyGuestHTTPFailureAndCounters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("reply"))
	}))
	defer upstream.Close()
	hostPort := strings.TrimPrefix(upstream.URL, "http://")
	_, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: port}}
	req := httptest.NewRequest(http.MethodPost, "http://guest/x", strings.NewReader("request"))
	rec := httptest.NewRecorder()
	if err := s.proxyGuestHTTP(context.Background(), "sb", 0, rec, req); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "reply" {
		t.Fatalf("proxy response = %d %q", rec.Code, rec.Body.String())
	}
	usage := s.netUsageFor("sb")
	if usage.bytesIn.Load() == 0 || usage.bytesOut.Load() == 0 {
		t.Fatalf("proxy bytes were not metered: in=%d out=%d", usage.bytesIn.Load(), usage.bytesOut.Load())
	}
}

func TestCoverage95ProxyHTTPBranches(t *testing.T) {
	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: 1}}
	rec := newLimitedProxyResponseRecorder(4)
	req, _ := http.NewRequest(http.MethodGet, "http://guest/big", nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("overflow-body"))
	}))
	defer upstream.Close()
	hostPort := strings.TrimPrefix(upstream.URL, "http://")
	_, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	s.lastCaps.WASIListenPort = port
	if err := s.proxyGuestHTTP(context.Background(), "sb", 0, rec, req); err != nil {
		t.Fatal(err)
	}
	if !rec.Overflowed() {
		t.Fatal("expected proxy response overflow")
	}
	result, err := s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		Method: http.MethodGet, RequestURI: "/big", GuestPort: port,
	})
	if err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("proxyGuestHTTPFromPayload = %+v, %v", result, err)
	}
	_, err = s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		Method: "\x00", RequestURI: "/",
	})
	if err == nil {
		t.Fatal("expected invalid method error")
	}

	body, err := buildProxyHTTPPayload(0, httptest.NewRequest(http.MethodGet, "http://x/", strings.NewReader("ok")))
	if err != nil || len(body.Body) != 2 {
		t.Fatalf("buildProxyHTTPPayload = %+v, %v", body, err)
	}

	c := NewClient("dummy")
	resultPayload, _ := encodePayload(proxyHTTPResultPayload{StatusCode: 201, Body: []byte("ok")})
	c.dial = mockDialer(t, Envelope{Type: MsgProxyHTTPResult, Payload: resultPayload})
	recorder := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if err := c.ProxyHTTP("sb", 80, recorder, req2); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != 201 {
		t.Fatalf("proxy status = %d", recorder.Code)
	}
}

func TestCoverage95BuildProxyHTTPPayloadReadError(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://x/", errReader{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildProxyHTTPPayload(0, req); err == nil {
		t.Fatal("expected body read error")
	}
}

func TestCoverage95ProxyGuestHTTPFromPayloadOverflow(t *testing.T) {
	big := make([]byte, maxProxyHTTPBody+1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer upstream.Close()
	hostPort := strings.TrimPrefix(upstream.URL, "http://")
	_, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: port}}
	_, err = s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		Method: http.MethodGet, RequestURI: "/big", GuestPort: port,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("overflow err = %v", err)
	}
}

func TestCoverage95ClientProxyHTTPDecodeErrors(t *testing.T) {
	c := NewClient("dummy")
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)

	c.dial = mockDialer(t, Envelope{Type: MsgProxyHTTPResult, Payload: []byte(`{`)})
	if err := c.ProxyHTTP("sb", 80, httptest.NewRecorder(), req); err == nil {
		t.Fatal("expected decode error")
	}

	c.dial = mockDialer(t, Envelope{Type: MsgHealthPing})
	if _, err := c.ResolvedListenPort("sb"); err == nil {
		t.Fatal("expected unexpected reply type")
	}

	payload, _ := encodePayload(errorPayload{Message: "boom"})
	c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
	if _, err := c.ResolvedListenPort("sb"); err == nil {
		t.Fatal("expected resolved listen error")
	}
}

func TestCoverage95ServerProxyHTTPSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("guest-ok"))
	}))
	defer upstream.Close()
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	eng := &successNetworkEngine{fakeNetworkAwareEngine: fakeNetworkAwareEngine{port: port}}
	s := &Server{eng: eng, lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: port}}
	payload, _ := encodePayload(proxyHTTPPayload{Method: http.MethodGet, RequestURI: "/", GuestPort: port})
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	_ = writeFrame(c1, Envelope{Type: MsgProxyHTTP, SandboxID: "sb", Payload: payload})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgProxyHTTPResult {
		t.Fatalf("proxy reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
}

func TestCoverage95ProxyGuestHTTPFromPayloadTargetError(t *testing.T) {
	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenPort: wasmengine.WASIListenPortDisabled}}
	_, err := s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		Method: http.MethodGet, RequestURI: "/",
	})
	if err == nil {
		t.Fatal("expected disabled guest listener error")
	}
}

func TestCoverage95ClientResolvedListenPortDecodeError(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: []byte(`{`)})
	if _, err := c.ResolvedListenPort("sb"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestCoverage95ClientProxyHTTPUnexpectedReply(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgOK})
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if err := c.ProxyHTTP("sb", 80, httptest.NewRecorder(), req); err == nil {
		t.Fatal("expected unexpected reply type")
	}
}

func TestCoverage95ServerSetListenPortUnsupportedEngine(t *testing.T) {
	s := &Server{eng: noListenEngine{}}
	setPort, _ := encodePayload(setListenPortPayload{Port: 8080})
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	_ = writeFrame(c1, Envelope{Type: MsgSetListenPort, SandboxID: "sb", Payload: setPort})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgError {
		t.Fatalf("set listen reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
}

func TestCoverage95ClientErrorReplyDecodeFailures(t *testing.T) {
	c := NewClient("dummy")
	bad := Envelope{Type: MsgError, Payload: []byte(`{`)}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)

	c.dial = mockDialer(t, bad)
	if _, err := c.ResolvedListenPort("sb"); err == nil {
		t.Fatal("expected ResolvedListenPort error payload decode failure")
	}

	c.dial = mockDialer(t, bad)
	if err := c.ProxyHTTP("sb", 80, httptest.NewRecorder(), req); err == nil {
		t.Fatal("expected ProxyHTTP error payload decode failure")
	}
}

func TestCoverage95ProxyHTTPEncodeFailure(t *testing.T) {
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		if _, ok := v.(proxyHTTPPayload); ok {
			return nil, errors.New("encode proxy payload failed")
		}
		return origEncode(v)
	}
	c := NewClient("dummy")
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if err := c.ProxyHTTP("sb", 80, httptest.NewRecorder(), req); err == nil {
		t.Fatal("expected ProxyHTTP encode failure")
	}
}
