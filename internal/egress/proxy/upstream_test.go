package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// bankProxy is a stand-in for the operator's upstream proxy: CONNECT tunnels
// to a mapped backend; absolute-form requests are answered directly.
type bankProxy struct {
	addr    string
	backend map[string]string // CONNECT target → local addr
	mu      sync.Mutex
	seen    []string
	auth    []string
}

func startBankProxy(t *testing.T) *bankProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	b := &bankProxy{addr: ln.Addr().String(), backend: map[string]string{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return b
}

func (b *bankProxy) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	b.mu.Lock()
	b.seen = append(b.seen, req.Method+" "+req.RequestURI)
	b.auth = append(b.auth, req.Header.Get("Proxy-Authorization"))
	target := b.backend[req.Host]
	b.mu.Unlock()
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-proxy")
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(c, up)
}

// TestUpstreamChaining (§5.10 PC-4, EF-82): an allowed name goes through
// the operator's proxy (CONNECT on 443, absolute form on 80, credentials on
// both); a no_proxy name dials direct; a proxy that is down fails fast with
// upstream_proxy_unavailable.
func TestUpstreamChaining(t *testing.T) {
	bank := startBankProxy(t)
	bank.backend["pypi.org:443"] = tlsBackend(t)
	up, err := egresspolicy.NewUpstream("http://"+bank.addr, "aerol:s3cret", []string{"mirror.example"}, nil, netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, 443, allowSpec("pypi.org", "mirror.example"), Config{Upstream: up})
	r.dialer.resolve["mirror.example"] = "151.101.0.10"
	r.dialer.backend["mirror.example"] = tlsBackend(t)

	body, err := tlsGet(r.addr, "pypi.org")
	if err != nil || !strings.Contains(body, "secure-ok") {
		t.Fatalf("proxied TLS: %q %v", body, err)
	}
	bank.mu.Lock()
	tunneled := len(bank.seen) == 1 && bank.seen[0] == "CONNECT pypi.org:443" && strings.HasPrefix(bank.auth[0], "Basic ")
	bank.mu.Unlock()
	if !tunneled {
		t.Fatalf("the proxy must see one authenticated CONNECT: %v", bank.seen)
	}
	if body, err := tlsGet(r.addr, "mirror.example"); err != nil || !strings.Contains(body, "secure-ok") {
		t.Fatalf("no_proxy name dials direct: %q %v", body, err)
	}
	r.dialer.mu.Lock()
	direct := len(r.dialer.dialed) == 1 && r.dialer.dialed[0] == "mirror.example:443"
	r.dialer.mu.Unlock()
	if !direct {
		t.Fatalf("direct dials = %v", r.dialer.dialed)
	}

	h := newRig(t, 80, allowSpec("pypi.org"), Config{Upstream: up})
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET /simple/ HTTP/1.1\r\nHost: pypi.org\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	_ = c.Close()
	if !strings.Contains(string(b), "via-proxy") {
		t.Fatalf("plain HTTP through the proxy: %q", b)
	}
	bank.mu.Lock()
	last, lastAuth := bank.seen[len(bank.seen)-1], bank.auth[len(bank.auth)-1]
	bank.mu.Unlock()
	if last != "GET http://pypi.org/simple/" || !strings.HasPrefix(lastAuth, "Basic ") {
		t.Fatalf("absolute form = %q auth=%q", last, lastAuth)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close()
	down, _ := egresspolicy.NewUpstream("http://"+dead, "", nil, nil, netip.MustParsePrefix("198.18.0.0/15"))
	d := newRig(t, 443, allowSpec("pypi.org"), Config{Upstream: down})
	if _, err := tlsGet(d.addr, "pypi.org"); err == nil {
		t.Fatal("a dead upstream must fail the handshake")
	}
	if dec := d.last(); dec.Reason != ReasonUpstreamProxy {
		t.Fatalf("reason = %q, want %s", dec.Reason, ReasonUpstreamProxy)
	}
	hd := newRig(t, 80, allowSpec("pypi.org"), Config{Upstream: down})
	c, _ = net.Dial("tcp", hd.addr)
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: pypi.org\r\nConnection: close\r\n\r\n")
	b, _ = io.ReadAll(c)
	_ = c.Close()
	if !strings.Contains(string(b), "502") || !strings.Contains(string(b), ReasonUpstreamProxy) {
		t.Fatalf("dead upstream on :80 = %q", b)
	}
}

// TestUpstreamUpgrade: a websocket upgrade to a proxied name tunnels through
// the upstream with CONNECT to port 80.
func TestUpstreamUpgrade(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
					_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nws-ok")
				}
			}()
		}
	}()
	bank := startBankProxy(t)
	bank.backend["pypi.org:80"] = ln.Addr().String()
	up, _ := egresspolicy.NewUpstream("http://"+bank.addr, "", nil, nil, netip.MustParsePrefix("198.18.0.0/15"))
	r := newRig(t, 80, allowSpec("pypi.org"), Config{Upstream: up})
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: pypi.org\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "101") || !strings.Contains(string(b), "ws-ok") {
		t.Fatalf("upgrade through the upstream = %q", b)
	}
	bank.mu.Lock()
	defer bank.mu.Unlock()
	if len(bank.seen) != 1 || bank.seen[0] != "CONNECT pypi.org:80" {
		t.Fatalf("proxy saw %v", bank.seen)
	}
}
