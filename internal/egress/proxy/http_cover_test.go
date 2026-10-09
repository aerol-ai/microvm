package proxy

import (
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TestHTTPSourceRecheckedPerRequest: the sandbox is read again for each
// request and once its upstream is dialed (direct or through the operator's
// proxy), so a detach or block that lands in between refuses the request.
func TestHTTPSourceRecheckedPerRequest(t *testing.T) {
	bank := startBankProxy(t)
	up, err := egresspolicy.NewUpstream("http://"+bank.addr, "", nil, nil, netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	const dialFailed = "502 aerolvm egress policy: pypi.org: dial_failed"
	for _, tc := range []struct {
		name   string
		cfg    Config
		wrap   func(*egress.Gateway) Sources
		want   string // the response, "" for a close without one
		reason string
	}{
		{"detached before the request", Config{}, changedFrom(2, detached), "", ReasonUnknownSource},
		{"blocked before the request", Config{}, changedFrom(2, blocked), "", ReasonBlocked},
		{"detached once dialed", Config{}, changedFrom(3, detached), dialFailed, ReasonDialFailed},
		{"detached once the proxy is dialed", Config{Upstream: up}, changedFrom(3, detached), dialFailed, ReasonDialFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRigOver(t, 80, allowSpec("pypi.org"), tc.cfg, tc.wrap)
			r.dialer.resolve["pypi.org"] = "151.101.0.223"
			r.dialer.backend["pypi.org"] = httpBackend(t)
			got := httpExchange(t, r.addr, "GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n")
			if strings.Join(got, "") != tc.want {
				t.Fatalf("responses = %q, want %q", got, tc.want)
			}
			if d := r.last(); d.Reason != tc.reason || d.Allowed {
				t.Fatalf("decision = %+v", d)
			}
		})
	}
}

// TestHTTPIPLiteralHost: a Host that is an address is held to the CIDR
// rules, not the name rules.
func TestHTTPIPLiteralHost(t *testing.T) {
	r := newRig(t, 80, allowSpec("pypi.org", "198.51.100.0/24"), Config{})
	r.dialer.backend["198.51.100.7"] = httpBackend(t)
	got := httpExchange(t, r.addr,
		"GET / HTTP/1.1\r\nHost: 198.51.100.7\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: 203.0.113.5\r\n\r\n")
	if len(got) != 2 || !strings.HasPrefix(got[0], "200 plain-ok") || !strings.HasPrefix(got[1], "403") {
		t.Fatalf("IP hosts: %v", got)
	}
	if d := r.last(); d.Reason != ReasonHostNotAllowed || d.Host != "203.0.113.5" {
		t.Fatalf("decision = %+v", d)
	}
}

// TestHTTPUpgradeFailures: an upgrade whose upstream can't be dialed gets a
// 502; one whose request can't be forwarded whole is closed unanswered.
func TestHTTPUpgradeFailures(t *testing.T) {
	r := newRig(t, 80, allowSpec("ws.example"), Config{})
	r.dialer.resolve["ws.example"] = "198.51.100.10"
	const upgrade = "GET /ws HTTP/1.1\r\nHost: ws.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
	got := httpExchange(t, r.addr, upgrade+"\r\n")
	if len(got) != 1 || got[0] != "502 aerolvm egress policy: ws.example: dial_failed" {
		t.Fatalf("undialable upgrade: %v", got)
	}

	backend := httpBackend(t)
	r.dialer.mu.Lock()
	r.dialer.backend["ws.example"] = backend
	r.dialer.mu.Unlock()
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The body promises more than the client sends before closing its side,
	// so writing the request upstream fails partway.
	if _, err := io.WriteString(c, upgrade+"Content-Length: 64\r\n\r\nshort"); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(c); err != nil || len(b) != 0 {
		t.Fatalf("a half-forwarded upgrade must be closed unanswered: %q %v", b, err)
	}
}
