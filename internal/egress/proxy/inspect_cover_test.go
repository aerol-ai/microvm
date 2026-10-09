package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

type fixedSrc struct {
	src egress.Source
	ok  bool
}

func (f fixedSrc) Source(netip.Addr) (egress.Source, bool)                    { return f.src, f.ok }
func (f fixedSrc) Track(string, string, uint16, net.Conn) *egress.TrackedConn { return nil }
func (f fixedSrc) BinName(string, netip.AddrPort) (string, bool)              { return "", false }

func TestInspectHandlerRefusesBeforeDial(t *testing.T) {
	peer := netip.MustParseAddr("10.1.0.8")
	p := New(fixedSrc{}, func(Decision) {}, Config{})
	h := &inspectHandler{p: p, id: "sb", peer: peer, name: "example.com"}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Host = "example.com"

	h.p.src = fixedSrc{}
	h.ServeHTTP(httptest.NewRecorder(), req)

	h.p.src = fixedSrc{ok: true, src: egress.Source{Spec: egress.Spec{ID: "other"}}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	h.p.src = fixedSrc{ok: true, src: egress.Source{Spec: egress.Spec{ID: "sb"}, Blocked: egress.BlockQuota}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	req.Host = "front.example"
	h.p.src = fixedSrc{ok: true, src: egress.Source{Spec: egress.Spec{ID: "sb"}}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	h.p.src = fixedSrc{ok: true, src: egress.Source{
		Spec: egress.Spec{ID: "sb"}, Policy: pol, Mode: egress.ModeAllowlist,
	}}
	h.name = "other.example"
	h.ServeHTTP(httptest.NewRecorder(), req)
}

// scriptSrc is the gateway with its Source answers changed from call from
// on, so a test can change the sandbox between two of the proxy's checks
// without the gateway's sweep closing the connection first. On one
// connection the proxy asks on accept (call 1), per request (2), and again
// once the request's upstream is dialed (3).
type scriptSrc struct {
	*egress.Gateway
	from   int
	change func(egress.Source) (egress.Source, bool)

	mu    sync.Mutex
	calls int
}

func (s *scriptSrc) Source(ip netip.Addr) (egress.Source, bool) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	src, ok := s.Gateway.Source(ip)
	if call < s.from {
		return src, ok
	}
	return s.change(src)
}

func changedFrom(call int, change func(egress.Source) (egress.Source, bool)) func(*egress.Gateway) Sources {
	return func(gw *egress.Gateway) Sources { return &scriptSrc{Gateway: gw, from: call, change: change} }
}

func detached(egress.Source) (egress.Source, bool) { return egress.Source{}, false }

func blocked(s egress.Source) (egress.Source, bool) {
	s.Blocked = egress.BlockQuota
	return s, true
}

func TestInspectHandlerRefusesUnlistedHostAndBinary(t *testing.T) {
	gw := egress.New(egress.Options{Backend: egress.NewMemBackend()})
	if err := gw.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	spec := allowSpec("api.example.com")
	spec.IP = peer
	spec.Rules = []egresspolicy.RuleSpec{{Host: "api.example.com", Ports: []uint16{443}, Binaries: []string{"/usr/bin/git"}}}
	if err := gw.Attach(spec); err != nil {
		t.Fatal(err)
	}
	src, _ := gw.Source(peer)
	var got []Decision
	p := New(fixedSrc{src: src, ok: true}, func(d Decision) { got = append(got, d) }, Config{})
	for _, tc := range []struct {
		name, reason string
	}{
		{"other.example.com", ReasonHostNotAllowed},
		// No Identify configured: a per-binary rule can't admit anything.
		{"api.example.com", ReasonBinaryUnknown},
	} {
		h := &inspectHandler{p: p, id: "sb", peer: peer, name: tc.name}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+tc.name+"/", nil))
		if rec.Code != http.StatusForbidden || got[len(got)-1].Reason != tc.reason {
			t.Fatalf("%s: %d %+v", tc.name, rec.Code, got[len(got)-1])
		}
	}
}

func TestInspectUpstreamErrorReasons(t *testing.T) {
	var got Decision
	h := &inspectHandler{p: New(fixedSrc{}, func(d Decision) { got = d }, Config{}), id: "sb", name: "api.example.com"}
	for _, tc := range []struct {
		err    error
		reason string
		status int
	}{
		{fmt.Errorf("dial: %w", egresspolicy.ErrDialRefused), ReasonBlockedIP, http.StatusForbidden},
		{fmt.Errorf("%w: connection refused", egresspolicy.ErrUpstreamProxy), ReasonUpstreamProxy, http.StatusBadGateway},
		{&http.MaxBytesError{Limit: 64}, ReasonBodyTooLarge, http.StatusRequestEntityTooLarge},
		{errors.New("connection reset"), ReasonDialFailed, http.StatusBadGateway},
	} {
		rec := httptest.NewRecorder()
		h.upstreamError(rec, nil, tc.err)
		if rec.Code != tc.status || got.Reason != tc.reason || !strings.Contains(rec.Body.String(), tc.reason) {
			t.Fatalf("%v: %d %q %+v", tc.err, rec.Code, rec.Body.String(), got)
		}
	}
}

// TestInspectHandshakeFailure: a client that doesn't trust the node CA
// aborts the handshake, and the proxy closes the connection.
func TestInspectHandshakeFailure(t *testing.T) {
	r := newInspectRig(t, Config{}, acmeRules...)
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tls.Client(raw, &tls.Config{ServerName: "api.example.com", RootCAs: x509.NewCertPool()}).Handshake(); err == nil {
		t.Fatal("a leaf from an untrusted CA must fail the handshake")
	}
	_, err = io.Copy(io.Discard, raw)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the proxy kept the connection open after a failed handshake")
	}
}

// TestInspectDialRefusedByGuard: an inspected name resolving into private
// space is refused when its upstream is dialed.
func TestInspectDialRefusedByGuard(t *testing.T) {
	r := newInspectRig(t, Config{}, acmeRules...)
	r.dialer.mu.Lock()
	r.dialer.resolve["api.example.com"] = "10.0.0.5"
	r.dialer.mu.Unlock()
	code, body, _ := do(t, r.client(false), http.MethodGet, "https://api.example.com/repos/acme/x", "", "")
	if code != http.StatusForbidden || !strings.Contains(body, ReasonBlockedIP) || r.last().Reason != ReasonBlockedIP {
		t.Fatalf("private upstream: %d %q %+v", code, body, r.last())
	}
}

// TestInspectThroughUpstreamProxy (§5.10 PC-4): an inspected request is
// re-originated through the operator's proxy; a proxy that is down is
// upstream_proxy_unavailable.
func TestInspectThroughUpstreamProxy(t *testing.T) {
	bank := startBankProxy(t)
	up, err := egresspolicy.NewUpstream("http://"+bank.addr, "", nil, nil, netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	r := newInspectRig(t, Config{Upstream: up}, acmeRules...)
	bank.mu.Lock()
	bank.backend["api.example.com:443"] = r.dialer.backend["api.example.com"]
	bank.mu.Unlock()
	code, body, _ := do(t, r.client(false), http.MethodGet, "https://api.example.com/repos/acme/x", "", "")
	if code != http.StatusOK || !strings.HasPrefix(body, "GET /repos/acme/x host=api.example.com") {
		t.Fatalf("through the proxy: %d %q", code, body)
	}
	bank.mu.Lock()
	seen := append([]string(nil), bank.seen...)
	bank.mu.Unlock()
	if len(seen) != 1 || seen[0] != "CONNECT api.example.com:443" {
		t.Fatalf("proxy saw %v", seen)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	down, _ := egresspolicy.NewUpstream("http://"+dead, "", nil, nil, netip.MustParsePrefix("198.18.0.0/15"))
	d := newInspectRig(t, Config{Upstream: down}, acmeRules...)
	code, body, _ = do(t, d.client(false), http.MethodGet, "https://api.example.com/repos/acme/x", "", "")
	if code != http.StatusBadGateway || !strings.Contains(body, ReasonUpstreamProxy) || d.last().Reason != ReasonUpstreamProxy {
		t.Fatalf("dead proxy: %d %q %+v", code, body, d.last())
	}
}

// TestInspectRecheckedOnceDialed: the sandbox is read again once each
// inspected upstream is dialed, direct or through the operator's proxy, so
// a detach that landed during the dial fails the request.
func TestInspectRecheckedOnceDialed(t *testing.T) {
	bank := startBankProxy(t)
	up, err := egresspolicy.NewUpstream("http://"+bank.addr, "", nil, nil, netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  Config
	}{{"direct", Config{}}, {"proxied", Config{Upstream: up}}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newInspectRigOver(t, tc.cfg, changedFrom(3, detached), acmeRules...)
			bank.mu.Lock()
			bank.backend["api.example.com:443"] = r.dialer.backend["api.example.com"]
			bank.mu.Unlock()
			code, body, _ := do(t, r.client(false), http.MethodGet, "https://api.example.com/repos/acme/x", "", "")
			if code != http.StatusBadGateway || !strings.Contains(body, ReasonDialFailed) {
				t.Fatalf("detached during the dial: %d %q", code, body)
			}
		})
	}
}
