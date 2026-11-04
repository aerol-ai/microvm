package egresspolicy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeConnectProxy accepts CONNECT, checks the credentials when want is set,
// answers 200 (plus extra bytes after the header when early is set) and
// pipes to the target.
type fakeConnectProxy struct {
	ln    net.Listener
	want  string
	early string
	mu    sync.Mutex
	seen  []string
}

func startConnectProxy(t *testing.T, want string) *fakeConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeConnectProxy{ln: ln, want: want}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *fakeConnectProxy) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.seen = append(p.seen, req.Method+" "+req.Host)
	p.mu.Unlock()
	if p.want != "" && req.Header.Get("Proxy-Authorization") != p.want {
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"+p.early)
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(c, up)
}

func echoServer(t *testing.T) string {
	t.Helper()
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
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = io.WriteString(c, "echo "+line)
			}()
		}
	}()
	return ln.Addr().String()
}

var synthetic = netip.MustParsePrefix("198.18.0.0/15")

func TestNewUpstreamValidation(t *testing.T) {
	for _, tc := range []struct {
		url, auth string
		noProxy   []string
		syn       netip.Prefix
	}{
		{"https://proxy:3128", "", nil, synthetic},
		{"http://proxy", "", nil, synthetic},
		{"http://proxy:3128", "nocolon", nil, synthetic},
		{"http://proxy:3128", "", []string{"bad host!"}, synthetic},
		{"http://proxy:3128", "", nil, netip.Prefix{}},
		{"http://proxy:3128", "", nil, netip.MustParsePrefix("fd00::/64")},
	} {
		if _, err := NewUpstream(tc.url, tc.auth, tc.noProxy, nil, tc.syn); err == nil {
			t.Errorf("%+v: want error", tc)
		}
	}
}

func TestUpstreamBypassAndProxyFunc(t *testing.T) {
	zone, err := NewInternalZone([]string{"corp.bank.internal"}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	up, err := NewUpstream("http://10.1.1.1:3128", "", []string{"mirror.example", "*.cdn.example", "10.9.0.0/16"}, zone, synthetic)
	if err != nil {
		t.Fatal(err)
	}
	for host, bypass := range map[string]bool{
		"203.0.113.5": true, "[::1]": true, // IP literals go direct
		"git.corp.bank.internal": true, // internal zone
		"mirror.example":         true, "a.mirror.example": true,
		"x.cdn.example": true, "cdn.example": false, // *. is subdomains only
		"pypi.org": false, "": true,
	} {
		if got := up.Bypass(host); got != bypass {
			t.Errorf("Bypass(%q) = %v, want %v", host, got, bypass)
		}
	}
	var nilUp *Upstream
	if !nilUp.Bypass("pypi.org") || nilUp.IsSynthetic(netip.MustParseAddr("198.18.0.5")) || nilUp.ProxyHeader() != nil {
		t.Fatal("nil upstream goes direct")
	}
	if u, _ := nilUp.ProxyFunc(&http.Request{URL: &url.URL{Host: "pypi.org"}}); u != nil {
		t.Fatal("nil upstream proxies nothing")
	}
	if u, _ := up.ProxyFunc(&http.Request{URL: &url.URL{Host: "pypi.org:443"}}); u == nil || u.Host != "10.1.1.1:3128" || u.User != nil {
		t.Fatalf("ProxyFunc = %v", u)
	}
	if u, _ := up.ProxyFunc(&http.Request{URL: &url.URL{Host: "mirror.example"}}); u != nil {
		t.Fatal("no_proxy names go direct")
	}
	if up.Addr() != "10.1.1.1:3128" || up.ProxyHeader() != nil {
		t.Fatal("no credentials, no header")
	}
}

// TestSyntheticIP: stable per name, inside the range, never its first or
// last address.
func TestSyntheticIP(t *testing.T) {
	up, _ := NewUpstream("http://proxy:3128", "", nil, nil, netip.MustParsePrefix("198.18.0.0/30"))
	seen := map[netip.Addr]bool{}
	for _, name := range []string{"a.example", "b.example", "c.example", "PyPI.org.", "pypi.org"} {
		ip := up.SyntheticIP(name)
		if !up.IsSynthetic(ip) || ip == netip.MustParseAddr("198.18.0.0") || ip == netip.MustParseAddr("198.18.0.3") {
			t.Fatalf("%s → %s outside the usable range", name, ip)
		}
		seen[ip] = true
	}
	if up.SyntheticIP("PyPI.org.") != up.SyntheticIP("pypi.org") {
		t.Fatal("canonical names must map to one address")
	}
}

// TestDialConnect: a tunnel through the proxy with credentials, early bytes
// kept, and failures reported as ErrUpstreamProxy.
func TestDialConnect(t *testing.T) {
	target := echoServer(t)
	auth := "Basic YWVyb2w6czNjcmV0" // aerol:s3cret
	p := startConnectProxy(t, auth)
	up, err := NewUpstream("http://"+p.ln.Addr().String(), "aerol:s3cret", nil, nil, synthetic)
	if err != nil {
		t.Fatal(err)
	}
	if h := up.ProxyHeader(); h.Get("Proxy-Authorization") != auth {
		t.Fatalf("header = %v", h)
	}
	c, err := up.DialConnect(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "hi\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	_ = c.Close()
	if line != "echo hi\n" {
		t.Fatalf("tunnel = %q", line)
	}
	p.early = "early\n"
	c, err = up.DialConnect(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	line, _ = bufio.NewReader(c).ReadString('\n')
	_ = c.Close()
	if line != "early\n" {
		t.Fatalf("bytes after the CONNECT answer were lost: %q", line)
	}

	wrongAuth, _ := NewUpstream("http://"+p.ln.Addr().String(), "aerol:nope", nil, nil, synthetic)
	if _, err := wrongAuth.DialConnect(context.Background(), target); !errors.Is(err, ErrUpstreamProxy) || !strings.Contains(err.Error(), "407") {
		t.Fatalf("refused tunnel: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close()
	down, _ := NewUpstream("http://"+dead, "", nil, nil, synthetic)
	if _, err := down.DialConnect(context.Background(), target); !errors.Is(err, ErrUpstreamProxy) {
		t.Fatalf("proxy down: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := up.DialConnect(ctx, target); !errors.Is(err, ErrUpstreamProxy) {
		t.Fatalf("cancelled: %v", err)
	}
}
