package proxy

// Regression tests from the second review of PR #622: each reproduces a
// finding against the reviewed head and passes with its fix.

import (
	"bufio"
	"fmt"
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
	dst := netip.MustParseAddrPort("151.101.0.223:443")
	if err := r.proxy.admitDialed(up1, dst, tc, nil, "pypi.org", true); err != nil {
		t.Fatal(err)
	}
	r.proxy.SetOperator(egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("151.101.0.0/16")}}, nil)
	up3, up4 := net.Pipe()
	defer up4.Close()
	if err := r.proxy.admitDialed(up3, dst, tc, nil, "pypi.org", true); err == nil {
		t.Fatal("the current guard must refuse a dial that raced the reload")
	}
	if _, err := up4.Write([]byte("x")); err == nil {
		t.Fatal("the refused upstream must be closed")
	}
	if err := r.proxy.admitDialed(up1, netip.AddrPort{}, tc, nil, "pypi.org", true); err != nil {
		t.Fatal("a connection through the operator's proxy (no address) is not checked")
	}
}
