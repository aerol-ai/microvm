package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

var peer = netip.MustParseAddr("127.0.0.1")

// fakeDNS maps names to pretend public addresses (run through the dial guard)
// and to the local backend actually dialed.
type fakeDialer struct {
	mu      sync.Mutex
	resolve map[string]string // name -> pretend IP
	backend map[string]string // name or pretend IP -> real local addr
	dialed  []string
}

func (f *fakeDialer) DialContext(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(address)
	f.mu.Lock()
	ip, ok := f.resolve[host]
	if !ok {
		ip = host
	}
	real := f.backend[host]
	f.dialed = append(f.dialed, address)
	f.mu.Unlock()
	if d.Control != nil {
		if err := d.Control(network, net.JoinHostPort(ip, port), nil); err != nil {
			return nil, &net.OpError{Op: "dial", Net: network, Err: err}
		}
	}
	if real == "" {
		return nil, fmt.Errorf("no backend for %s", address)
	}
	return net.Dial("tcp", real)
}

type rig struct {
	gw        *egress.Gateway
	addr      string
	dialer    *fakeDialer
	mu        sync.Mutex
	decisions []Decision
	proxy     *Proxy
}

func (r *rig) last() Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.decisions[len(r.decisions)-1]
}

func newRig(t *testing.T, port uint16, spec egress.Spec, cfg Config) *rig {
	t.Helper()
	return newRigOver(t, port, spec, cfg, nil)
}

// newRigOver is newRig with the proxy reading the gateway through wrap; nil
// reads it directly.
func newRigOver(t *testing.T, port uint16, spec egress.Spec, cfg Config, wrap func(*egress.Gateway) Sources) *rig {
	t.Helper()
	gw := egress.New(egress.Options{Backend: egress.NewMemBackend()})
	if err := gw.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	spec.IP = peer
	if err := gw.Attach(spec); err != nil {
		t.Fatal(err)
	}
	r := &rig{gw: gw, dialer: &fakeDialer{resolve: map[string]string{}, backend: map[string]string{}}}
	cfg.Dialer = r.dialer
	cfg.OriginalDst = func(net.Conn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(netip.MustParseAddr("93.184.216.34"), port), nil
	}
	var src Sources = gw
	if wrap != nil {
		src = wrap(gw)
	}
	r.proxy = New(src, func(d Decision) {
		r.mu.Lock()
		r.decisions = append(r.decisions, d)
		r.mu.Unlock()
	}, cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = r.proxy.Serve(ln) }()
	r.addr = ln.Addr().String()
	return r
}

func tlsBackend(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secure-ok")
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func httpBackend(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain-ok host="+r.Host)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func tlsGet(addr, sni string) (string, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
	b, err := io.ReadAll(conn)
	return string(b), err
}

func allowSpec(allow ...string) egress.Spec { return egress.Spec{ID: "sb", AllowOut: allow} }

func TestTLSAllowedAndDenied(t *testing.T) {
	r := newRig(t, 443, allowSpec("pypi.org", "*.pythonhosted.org"), Config{})
	r.dialer.resolve["pypi.org"] = "151.101.0.223"
	r.dialer.backend["pypi.org"] = tlsBackend(t)

	body, err := tlsGet(r.addr, "pypi.org")
	if err != nil || !strings.Contains(body, "secure-ok") {
		t.Fatalf("allowed SNI: %q, %v", body, err)
	}
	if d := r.last(); !d.Allowed || d.Host != "pypi.org" || d.Rule != "pypi.org" {
		t.Fatalf("decision = %+v", d)
	}
	_, err = tlsGet(r.addr, "evil.example")
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("denied SNI err = %v, want TLS access_denied alert", err)
	}
	if d := r.last(); d.Allowed || d.Reason != ReasonSNINotAllowed {
		t.Fatalf("decision = %+v", d)
	}
	r.dialer.mu.Lock()
	for _, a := range r.dialer.dialed {
		if strings.HasPrefix(a, "evil.example") {
			t.Fatal("a denied SNI was dialed")
		}
	}
	r.dialer.mu.Unlock()
}

func TestTLSNoSNIAndIPLiteral(t *testing.T) {
	r := newRig(t, 443, allowSpec("pypi.org"), Config{HelloTimeout: 500 * time.Millisecond})
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	// A hello without SNI (no ServerName and an IP target).
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	err = tc.Handshake()
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("no-SNI err = %v", err)
	}
	if d := r.last(); d.Reason != ReasonNoSNI && d.Reason != ReasonSNINotAllowed {
		t.Fatalf("decision = %+v", d)
	}
	// Garbage that isn't TLS is denied the same way after the peek fails.
	c2, _ := net.Dial("tcp", r.addr)
	_, _ = c2.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	buf := make([]byte, 16)
	n, _ := c2.Read(buf)
	if n == 0 || buf[0] != 0x15 {
		t.Fatalf("non-TLS on 443 must get an alert record, got %x", buf[:n])
	}
	_ = c2.Close()
}

func TestTLSDialGuardRefusesPrivate(t *testing.T) {
	r := newRig(t, 443, allowSpec("intranet.example"), Config{})
	r.dialer.resolve["intranet.example"] = "10.0.0.5"
	r.dialer.backend["intranet.example"] = tlsBackend(t)
	if _, err := tlsGet(r.addr, "intranet.example"); err == nil {
		t.Fatal("an allowed name resolving into private space must be refused")
	}
	if d := r.last(); d.Reason != ReasonBlockedIP {
		t.Fatalf("decision = %+v, want blocked_ip", d)
	}
}

func TestTLSDenylistMode(t *testing.T) {
	r := newRig(t, 443, egress.Spec{ID: "sb", DenyOut: []string{"203.0.113.0/24"}}, Config{})
	r.dialer.resolve["anything.example"] = "198.51.100.7"
	r.dialer.backend["anything.example"] = tlsBackend(t)
	if body, err := tlsGet(r.addr, "anything.example"); err != nil || !strings.Contains(body, "secure-ok") {
		t.Fatalf("deny-list mode must default-accept: %q %v", body, err)
	}
	r.dialer.resolve["bad.example"] = "203.0.113.9"
	r.dialer.backend["bad.example"] = tlsBackend(t)
	if _, err := tlsGet(r.addr, "bad.example"); err == nil {
		t.Fatal("a name resolving into a deny CIDR must be refused")
	}
}

func TestTLSLearnMode(t *testing.T) {
	r := newRig(t, 443, egress.Spec{ID: "sb", Learn: true}, Config{})
	r.dialer.resolve["new.example"] = "198.51.100.8"
	r.dialer.backend["new.example"] = tlsBackend(t)
	if body, err := tlsGet(r.addr, "new.example"); err != nil || !strings.Contains(body, "secure-ok") {
		t.Fatalf("learn mode must allow: %q %v", body, err)
	}
	if d := r.last(); !d.Allowed || d.Mode != egress.ModeLearn || d.Host != "new.example" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestBlockedAndCaps(t *testing.T) {
	r := newRig(t, 443, allowSpec("pypi.org"), Config{MaxConnsPerSandbox: 1})
	r.dialer.resolve["pypi.org"] = "151.101.0.223"
	backend := make(chan net.Conn, 4)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			backend <- c
		}
	}()
	r.dialer.backend["pypi.org"] = ln.Addr().String()
	// Hold one connection open (a hello the backend never answers).
	first, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	go func() {
		_ = tls.Client(first, &tls.Config{ServerName: "pypi.org", InsecureSkipVerify: true}).Handshake()
	}()
	select {
	case <-backend:
	case <-time.After(2 * time.Second):
		t.Fatal("first connection never reached the backend")
	}
	// The second is over the per-sandbox cap: alert without a hello read.
	second, _ := net.Dial("tcp", r.addr)
	buf := make([]byte, 16)
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := second.Read(buf)
	if n < 7 || buf[0] != 0x15 || buf[6] != 0x31 {
		t.Fatalf("over-cap must get access_denied immediately, got %x", buf[:n])
	}
	_ = second.Close()
	if d := r.last(); d.Reason != ReasonConnCap {
		t.Fatalf("decision = %+v", d)
	}
	if r.proxy.Active() != 1 {
		t.Fatalf("active = %d", r.proxy.Active())
	}
	// Blocking closes the live connection (tracked) and denies new ones.
	if err := r.gw.SetBlocked("sb", egress.BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := first.Read(buf); err == nil {
		t.Fatal("block must close the tracked connection")
	}
	third, _ := net.Dial("tcp", r.addr)
	_ = third.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ = third.Read(buf)
	if n == 0 || buf[0] != 0x15 {
		t.Fatalf("blocked sandbox must be refused, got %x", buf[:n])
	}
	_ = third.Close()
}

func TestUnknownSourceClosed(t *testing.T) {
	r := newRig(t, 443, allowSpec("pypi.org"), Config{})
	if err := r.gw.Detach("sb", peer); err != nil {
		t.Fatal(err)
	}
	c, _ := net.Dial("tcp", r.addr)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("unknown source must be closed")
	}
	if d := r.last(); d.Reason != ReasonUnknownSource {
		t.Fatalf("decision = %+v", d)
	}
}

func httpExchange(t *testing.T, addr string, reqs ...string) []string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	var out []string
	for _, raw := range reqs {
		if _, err := io.WriteString(c, raw); err != nil {
			break
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			break
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		out = append(out, fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(b))))
		if resp.Close {
			break
		}
	}
	return out
}

func TestHTTPPerRequestHost(t *testing.T) {
	r := newRig(t, 80, allowSpec("pypi.org"), Config{})
	r.dialer.resolve["pypi.org"] = "151.101.0.223"
	r.dialer.backend["pypi.org"] = httpBackend(t)
	got := httpExchange(t, r.addr,
		"GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n",
	)
	if len(got) != 2 || !strings.HasPrefix(got[0], "200 plain-ok") || !strings.HasPrefix(got[1], "403 aerolvm egress policy: host evil.example not allowed") {
		t.Fatalf("keep-alive host switch: %v", got)
	}
	got = httpExchange(t, r.addr, "CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n")
	if len(got) != 1 || !strings.HasPrefix(got[0], "400") {
		t.Fatalf("CONNECT: %v", got)
	}
	got = httpExchange(t, r.addr, "GET / HTTP/1.1\r\nHost: pypi.org:8080\r\n\r\n")
	if len(got) != 1 || !strings.HasPrefix(got[0], "400") {
		t.Fatalf("foreign port in Host: %v", got)
	}
	r.dialer.resolve["intranet.example"] = "10.1.2.3"
}

func TestHTTPGuardAndDialFailure(t *testing.T) {
	r := newRig(t, 80, allowSpec("pypi.org", "intranet.example", "dead.example"), Config{})
	r.dialer.resolve["intranet.example"] = "10.1.2.3"
	r.dialer.backend["intranet.example"] = httpBackend(t)
	got := httpExchange(t, r.addr, "GET / HTTP/1.1\r\nHost: intranet.example\r\n\r\n")
	if len(got) != 1 || !strings.HasPrefix(got[0], "403") {
		t.Fatalf("private resolution: %v", got)
	}
	r.dialer.resolve["dead.example"] = "198.51.100.9"
	got = httpExchange(t, r.addr, "GET / HTTP/1.1\r\nHost: dead.example\r\n\r\n")
	if len(got) != 1 || !strings.HasPrefix(got[0], "502") {
		t.Fatalf("dial failure: %v", got)
	}
}

func TestHTTPUpgradeSplices(t *testing.T) {
	r := newRig(t, 80, allowSpec("ws.example"), Config{})
	r.dialer.resolve["ws.example"] = "198.51.100.10"
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		line, _ := br.ReadString('\n')
		_, _ = io.WriteString(c, "echo:"+line)
		_ = c.Close()
	}()
	r.dialer.backend["ws.example"] = ln.Addr().String()
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: ws.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade response: %v %v", resp, err)
	}
	_, _ = io.WriteString(c, "hello\n")
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, _ := br.ReadString('\n')
	if line != "echo:hello\n" {
		t.Fatalf("raw splice after upgrade: %q", line)
	}
}

func TestRequestHostAndHelpers(t *testing.T) {
	dst := netip.MustParseAddrPort("93.184.216.34:80")
	cases := []struct {
		host string
		want string
		ok   bool
	}{
		{"Pypi.Org.", "pypi.org", true},
		{"pypi.org:80", "pypi.org", true},
		{"pypi.org:81", "", false},
		{"", "93.184.216.34", true},
		{"[2001:db8::1]:80", "2001:db8::1", true},
	}
	for _, tc := range cases {
		req := &http.Request{Host: tc.host, URL: &url.URL{}}
		got, ok := requestHost(req, dst)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("requestHost(%q) = %q,%v", tc.host, got, ok)
		}
	}
	h := http.Header{}
	h.Add("Connection", "keep-alive, Upgrade")
	if isUpgrade(&http.Request{Header: h}) {
		t.Fatal("Upgrade header missing: not an upgrade")
	}
	h.Set("Upgrade", "websocket")
	if !isUpgrade(&http.Request{Header: h}) {
		t.Fatal("upgrade not detected")
	}
	if egresspolicyRefused(fmt.Errorf("x: %w", egresspolicy.ErrDialRefused)) != true {
		t.Fatal("refusal detection")
	}
}

// TestHTTPKeepAliveSeesPolicyUpdate covers §5.8 on :80: the second request on
// a keep-alive connection is judged by the policy as it is after a live
// update, not the one the connection was opened under.
func TestHTTPKeepAliveSeesPolicyUpdate(t *testing.T) {
	r := newRig(t, 80, allowSpec("pypi.org", "files.example"), Config{})
	backend := httpBackend(t)
	r.dialer.resolve["pypi.org"], r.dialer.backend["pypi.org"] = "151.101.0.223", backend
	r.dialer.resolve["files.example"], r.dialer.backend["files.example"] = "151.101.0.224", backend
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	get := func(host string) string {
		if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.Status
	}
	if got := get("files.example"); !strings.HasPrefix(got, "200") {
		t.Fatalf("first request = %s", got)
	}
	spec := allowSpec("files.example")
	spec.IP = peer
	if err := r.gw.Attach(spec); err != nil {
		t.Fatal(err)
	}
	if got := get("pypi.org"); !strings.HasPrefix(got, "403") {
		t.Fatalf("a host the update removed was served on the open connection: %s", got)
	}
}
