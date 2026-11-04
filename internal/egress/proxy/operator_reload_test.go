package proxy

// Regression tests from the second review of PR #622: each reproduces a
// finding against the reviewed head and passes with its fix.

import (
	"bufio"
	"fmt"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestOperatorReloadRevokesHTTPStream(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "11")
		_, _ = io.WriteString(w, "before")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "after")
	}))
	defer srv.Close()
	r := newRig(t, 80, allowSpec("pypi.org"), Config{})
	r.dialer.resolve["pypi.org"] = "151.101.0.223"
	r.dialer.backend["pypi.org"] = strings.TrimPrefix(srv.URL, "http://")
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: pypi.org\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	before := make([]byte, 6)
	if _, err := io.ReadFull(resp.Body, before); err != nil {
		close(release)
		t.Fatal(err)
	}
	guard := egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("151.101.0.0/16")}}
	r.proxy.SetOperator(guard, nil)
	// Exactly the daemon's revocation predicate after installing the guard.
	closed := r.gw.RevalidateConns(func(pol *egresspolicy.Policy, host string, dst netip.AddrPort) bool {
		return dst.IsValid() && guard.Check(pol, egresspolicy.DialTarget{Name: host, NameAllowed: true, Addr: dst}) != nil
	})
	close(release)
	after, _ := io.ReadAll(resp.Body)
	if closed == 0 && string(after) == "after" {
		t.Fatal("HTTP stream keeps delivering after operator revocation because its tracked destination is never set")
	}
}

// TestAdmitDialedRechecksTheCurrentGuard: a connection dialed under the old
// guard while a reload landed is recorded on its tracked downstream and
// refused by the new guard right after the dial.
func TestAdmitDialedRechecksTheCurrentGuard(t *testing.T) {
	r := newRig(t, 443, allowSpec("pypi.org"), Config{})
	up1, up2 := net.Pipe()
	defer up2.Close()
	dn1, dn2 := net.Pipe()
	defer dn2.Close()
	tc := r.gw.Track("sb", "pypi.org", 443, dn1)
	defer tc.Close()
	a := admission{ip: peer, id: "sb", host: "pypi.org", port: 443, nameAllowed: true}
	dst := netip.MustParseAddrPort("151.101.0.223:443")
	if err := r.proxy.admitDialed(up1, dst, tc, a); err != nil {
		t.Fatal(err)
	}
	r.proxy.SetOperator(egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("151.101.0.0/16")}}, nil)
	up3, up4 := net.Pipe()
	defer up4.Close()
	if err := r.proxy.admitDialed(up3, dst, tc, a); err == nil {
		t.Fatal("the current guard must refuse a dial that raced the reload")
	}
	if _, err := up4.Write([]byte("x")); err == nil {
		t.Fatal("the refused upstream must be closed")
	}
	if err := r.proxy.admitDialed(up1, netip.AddrPort{}, tc, a); err != nil {
		t.Fatal("a connection through the operator's proxy (no address) skips the guard")
	}
}

// TestStillAdmittedAfterRegistration (review 3 finding 6): once registered,
// a connection is checked against its sandbox as it is now, on every path
// including the operator's proxy (no destination address): a detach, a
// block or a policy that no longer allows its host refuses it; an unchanged
// or still-permitting policy doesn't.
func TestStillAdmittedAfterRegistration(t *testing.T) {
	r := newRig(t, 443, allowSpec("pypi.org", "github.com"), Config{})
	src, _ := r.gw.Source(peer)
	a := admission{ip: peer, id: "sb", host: "pypi.org", port: 443, pol: src.Policy, nameAllowed: true}
	admit := func() error {
		up1, up2 := net.Pipe()
		defer up2.Close()
		dn1, dn2 := net.Pipe()
		defer dn2.Close()
		tc := r.gw.Track("sb", a.host, a.port, dn1)
		defer tc.Close()
		return r.proxy.admitDialed(up1, netip.AddrPort{}, tc, a)
	}
	if err := admit(); err != nil {
		t.Fatalf("unchanged sandbox: %v", err)
	}
	// A policy change that still allows the host keeps it.
	wider := allowSpec("pypi.org", "github.com", "example.com")
	wider.IP = peer
	if err := r.gw.Attach(wider); err != nil {
		t.Fatal(err)
	}
	if err := admit(); err != nil {
		t.Fatalf("still permitted: %v", err)
	}
	narrower := allowSpec("github.com")
	narrower.IP = peer
	if err := r.gw.Attach(narrower); err != nil {
		t.Fatal(err)
	}
	if err := admit(); err == nil {
		t.Fatal("a policy that dropped the host must refuse it")
	}
	a.host = "github.com"
	if err := r.gw.SetBlocked("sb", egress.BlockHold, true); err != nil {
		t.Fatal(err)
	}
	if err := admit(); err == nil {
		t.Fatal("a blocked sandbox must refuse it")
	}
	if err := r.gw.Detach("sb", peer); err != nil {
		t.Fatal(err)
	}
	if err := admit(); err == nil {
		t.Fatal("a detached sandbox must refuse it")
	}
}
