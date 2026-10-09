package worker

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func mustPolicy(t *testing.T, allow, deny []string) *egresspolicy.Policy {
	t.Helper()
	p, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: allow, DenyOut: deny})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestMediatorPolicyDecisions covers P1-6: denials fail fast with a typed
// error naming host and reason, before any network I/O.
func TestMediatorPolicyDecisions(t *testing.T) {
	m := newNetMediator()
	m.SetPolicy("sb", mustPolicy(t, []string{"pypi.org", "203.0.113.0/24"}, nil))
	ctx := context.Background()
	cases := []struct {
		addr   string
		reason string
	}{
		{"evil.example:443", reasonHostNotAllowed},
		{"pypi.org:22", reasonHostNotAllowed}, // a bare host admits 80/443 only
		{"198.51.100.1:443", reasonIPNotAllowed},
	}
	for _, tc := range cases {
		_, err := m.DialContext(ctx, "sb", "tcp", tc.addr)
		var denied *wasmengine.EgressDeniedError
		if !errors.As(err, &denied) || denied.Reason != tc.reason {
			t.Fatalf("%s: err = %v, want denial %s", tc.addr, err, tc.reason)
		}
		if !errors.Is(err, wasmengine.ErrNetworkEgressBlocked) {
			t.Fatal("a denial must map to the guest's blocked error")
		}
	}
	// A deny CIDR that decided is named in the error (P1-13).
	m.SetPolicy("sb", mustPolicy(t, nil, []string{"198.51.100.0/24"}))
	_, err := m.DialContext(ctx, "sb", "tcp", "198.51.100.9:443")
	var byRule *wasmengine.EgressDeniedError
	if !errors.As(err, &byRule) || byRule.Rule != "198.51.100.0/24" || !strings.Contains(err.Error(), "rule 198.51.100.0/24") {
		t.Fatalf("deny-rule err = %v", err)
	}
	// An allowed CIDR that names loopback is still refused by the guard.
	m.SetPolicy("sb", mustPolicy(t, []string{"127.0.0.0/8"}, nil))
	if _, err := m.DialContext(ctx, "sb", "tcp", "127.0.0.1:9"); err == nil {
		t.Fatal("loopback must be refused even when a CIDR allows it")
	} else {
		var denied *wasmengine.EgressDeniedError
		if !errors.As(err, &denied) || denied.Reason != reasonBlockedIP {
			t.Fatalf("loopback err = %v, want blocked_ip", err)
		}
	}
	// No policy keeps today's behavior.
	m.SetPolicy("sb", nil)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	c, err := m.DialContext(ctx, "sb", "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("open default must dial: %v", err)
	}
	_ = c.Close()
	if _, err := m.DialContext(ctx, "sb", "tcp", "no-port"); err != nil {
		// open default: the plain dialer reports the bad address
	}
	m.SetPolicy("sb", mustPolicy(t, []string{"pypi.org"}, nil))
	if _, err := m.DialContext(ctx, "sb", "tcp", "no-port"); err == nil {
		t.Fatal("a malformed address must fail under policy")
	}
	if _, err := m.DialContext(ctx, "sb", "tcp", "pypi.org:99999"); err == nil {
		t.Fatal("a bad port must fail under policy")
	}
}

func TestApplyCapsPolicy(t *testing.T) {
	m := newNetMediator()
	m.ApplyCapsPolicy("sb", wasmengine.Capabilities{EgressAllowOut: []string{"pypi.org"}})
	if m.policyFor("sb") != nil {
		t.Fatal("caps without EgressPolicySet must not change the policy")
	}
	m.ApplyCapsPolicy("sb", wasmengine.Capabilities{EgressAllowOut: []string{"pypi.org"}, EgressPolicySet: true})
	if m.policyFor("sb") == nil {
		t.Fatal("policy not applied")
	}
	m.ApplyCapsPolicy("sb", wasmengine.Capabilities{EgressDenyOut: []string{"evil.com"}, EgressPolicySet: true})
	if p := m.policyFor("sb"); p == nil || !p.BlockAll() {
		t.Fatal("an invalid stored policy must fail closed as block-all")
	}
	m.ApplyCapsPolicy("sb", wasmengine.Capabilities{EgressPolicySet: true})
	if m.policyFor("sb") != nil {
		t.Fatal("empty lists remove the policy")
	}
	m.SetPolicy("", nil)
	m.SetDialGuard(egresspolicy.DialGuard{Strict: true})
	if !m.dialGuard().Strict {
		t.Fatal("guard not stored")
	}
}

// clientHello returns the bytes of a real TLS ClientHello for sni.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
		_ = a.Close()
	}()
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16<<10)
	n, _ := b.Read(buf)
	_ = b.Close()
	return buf[:n]
}

type captureConn struct {
	net.Conn
	written []byte
	closed  bool
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}
func (c *captureConn) Close() error { c.closed = true; return nil }

// TestSNICheck: on 443 the guest's SNI must be the dialed name (TLS fronting
// inside an allowed IP is refused); fragmented hellos are reassembled; non-TLS
// bytes pass through.
func TestSNICheck(t *testing.T) {
	good := clientHello(t, "pypi.org")
	under := &captureConn{}
	c := &sniCheckConn{Conn: under, host: "pypi.org", port: 443}
	half := len(good) / 2
	if n, err := c.Write(good[:half]); err != nil || n != half || len(under.written) != 0 {
		t.Fatalf("partial hello must buffer: n=%d err=%v written=%d", n, err, len(under.written))
	}
	if _, err := c.Write(good[half:]); err != nil || len(under.written) != len(good) {
		t.Fatalf("matching SNI must flush: %v %d", err, len(under.written))
	}
	if _, err := c.Write([]byte("more")); err != nil {
		t.Fatal("after the decision bytes flow freely")
	}

	under = &captureConn{}
	c = &sniCheckConn{Conn: under, host: "pypi.org", port: 443}
	_, err := c.Write(clientHello(t, "evil.example"))
	var denied *wasmengine.EgressDeniedError
	if !errors.As(err, &denied) || denied.Reason != reasonSNIMismatch || !under.closed || len(under.written) != 0 {
		t.Fatalf("fronting: err=%v closed=%v written=%d", err, under.closed, len(under.written))
	}

	under = &captureConn{}
	c = &sniCheckConn{Conn: under, host: "pypi.org", port: 443}
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil || len(under.written) == 0 {
		t.Fatal("non-TLS bytes on 443 pass through")
	}
}

func TestResidentSetEgressPolicyMessage(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	srv := &ResidentServer{}
	client, _ := serveResidentWith(t, srv)
	if _, err := client.LoadModule("host", modPath, 0); err != nil {
		t.Fatal(err)
	}
	caps := nonListenCaps("wasm")
	caps.EgressAllowOut, caps.EgressPolicySet = []string{"pypi.org"}, true
	if err := client.Instantiate("sb", caps); err != nil {
		t.Fatal(err)
	}
	if srv.mediator().policyFor("sb") == nil {
		t.Fatal("instantiate caps must install the policy")
	}
	if err := client.SetEgressPolicy("sb", nil, nil, false); err != nil {
		t.Fatal(err)
	}
	if srv.mediator().policyFor("sb") != nil {
		t.Fatal("set_egress_policy with empty lists must remove the policy")
	}
	if err := client.SetEgressPolicy("sb", []string{"github.com"}, nil, false); err != nil {
		t.Fatal(err)
	}
	if p := srv.mediator().policyFor("sb"); p == nil {
		t.Fatal("live update not applied")
	} else if ok, _ := p.MatchHost("github.com"); !ok {
		t.Fatal("live update must replace the policy")
	}
	_ = io.EOF
}

// TestMediatorReportsDenials (H5): every policy denial, including an SNI
// mismatch caught after the dial, reaches the denial observer with the
// sandbox, destination and reason; allowed dials do not.
func TestMediatorReportsDenials(t *testing.T) {
	m := newNetMediator()
	type denial struct{ id, addr, reason string }
	var got []denial
	m.SetEgressDenialObserver(func(id, _, addr, reason string) { got = append(got, denial{id, addr, reason}) })
	m.SetPolicy("sb", mustPolicy(t, []string{"pypi.org"}, nil))
	if _, err := m.DialContext(context.Background(), "sb", "tcp", "evil.example:443"); err == nil {
		t.Fatal("denied")
	}
	if len(got) != 1 || got[0] != (denial{"sb", "evil.example:443", reasonHostNotAllowed}) {
		t.Fatalf("denials = %+v", got)
	}
	c := &sniCheckConn{Conn: &captureConn{}, host: "pypi.org", port: 443, onDeny: func(sni string) {
		m.observeDenial("sb", "tcp", sni+":443", reasonSNIMismatch)
	}}
	if _, err := c.Write(clientHello(t, "evil.example")); err == nil {
		t.Fatal("fronting must be refused")
	}
	if len(got) != 2 || got[1].reason != reasonSNIMismatch || got[1].addr != "evil.example:443" {
		t.Fatalf("sni denial = %+v", got)
	}
	(*NetMediator)(nil).SetEgressDenialObserver(nil)
}

// TestInstallOperatorGuard (§5.10): the worker applies the operator file's
// internal zone and floor; a file it can't load leaves it strict until a good
// one appears, which the poll then installs.
func TestInstallOperatorGuard(t *testing.T) {
	fastOperatorPoll(t)
	m := newNetMediator()
	t.Cleanup(m.stopOperatorWatch)
	installOperatorGuard(m)
	if m.dialGuard().Strict || m.dialGuard().Zone != nil {
		t.Fatal("no file: the default guard")
	}
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ninternal_zone: {suffixes: [corp.bank.internal], cidrs: [10.0.0.0/8]}\ndeny_cidrs: [10.66.0.0/16]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_EGRESS_OPERATOR_FILE", path)
	installOperatorGuard(m)
	if g := m.dialGuard(); g.Zone == nil || len(g.DenyFloor) != 1 || g.Strict {
		t.Fatalf("operator guard = %+v", g)
	}
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	t.Setenv("SB_EGRESS_OPERATOR_FILE", missing)
	installOperatorGuard(m)
	if !m.dialGuard().Strict {
		t.Fatal("an unreadable file must leave the worker strict")
	}
	writeOperatorFile(t, missing, "version: 1\ndeny_cidrs: [10.66.0.0/16]\n")
	waitFor(t, "the poll to install the file that appeared", func() bool {
		g := m.dialGuard()
		return !g.Strict && len(g.DenyFloor) == 1
	})
	found := false
	for _, kv := range workerEnvironment() {
		if strings.HasPrefix(kv, "SB_EGRESS_OPERATOR_FILE=") {
			found = true
		}
	}
	if !found {
		t.Fatal("workers must inherit SB_EGRESS_OPERATOR_FILE")
	}
}

// TestMediatorUpstream (§5.10 PC-4): an allowed name the operator proxies is
// dialed by CONNECT through the upstream, never resolved here.
func TestMediatorUpstream(t *testing.T) {
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err == nil {
			_, _ = c.Write([]byte("hello\n"))
			_ = c.Close()
		}
	}()
	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer proxyLn.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := proxyLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		seen <- strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
		up, err := net.Dial("tcp", target.Addr().String())
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		_, _ = io.Copy(c, up)
	}()
	up, err := egresspolicy.NewUpstream("http://"+proxyLn.Addr().String(), "", nil, nil, netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	m := newNetMediator()
	m.upstream = up
	m.SetPolicy("sb", mustPolicy(t, []string{"pypi.org:8443"}, nil))
	c, err := m.DialContext(context.Background(), "sb", "tcp", "pypi.org:8443")
	if err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	_ = c.Close()
	if line != "hello\n" || <-seen != "CONNECT pypi.org:8443 HTTP/1.1" {
		t.Fatalf("tunnel = %q", line)
	}
}

// TestMediatorLearnMode (P2-7): learn mode allows every destination and
// records it; the recording is read over the worker RPC and dropped when
// the instance stops.
func TestMediatorLearnMode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	srv := &ResidentServer{}
	client, _ := serveResidentWith(t, srv)
	if _, err := client.LoadModule("host", modPath, 0); err != nil {
		t.Fatal(err)
	}
	caps := nonListenCaps("wasm")
	caps.EgressPolicySet, caps.EgressLearn = true, true
	if err := client.Instantiate("sb", caps); err != nil {
		t.Fatal(err)
	}
	m := srv.mediator()
	p := m.policyFor("sb")
	if p == nil || p.Mode() != egresspolicy.ModeLearn {
		t.Fatal("caps must install learn mode")
	}
	// The dial guard still applies in learn mode, and a refused dial is
	// not recorded.
	if _, err := m.DialContext(context.Background(), "sb", "tcp", ln.Addr().String()); err == nil {
		t.Fatal("loopback stays refused in learn mode")
	}
	if l := m.Learned("sb"); len(l.CIDRs) != 0 {
		t.Fatalf("a refused dial was recorded: %+v", l)
	}
	m.recordLearned("sb", p, "203.0.113.9", 5432)
	m.recordLearned("sb", mustPolicy(t, []string{"pypi.org"}, nil), "pypi.org", 443) // enforce: not recorded
	l, err := client.EgressLearned("sb")
	if err != nil || len(l.CIDRs) != 1 {
		t.Fatalf("recording = %+v %v", l, err)
	}
	// Switching to enforce keeps the recording readable.
	if err := client.SetEgressPolicy("sb", []string{"127.0.0.1/32"}, nil, false); err != nil {
		t.Fatal(err)
	}
	if l, _ := client.EgressLearned("sb"); len(l.CIDRs) != 1 {
		t.Fatalf("after enforce = %+v", l)
	}
	if err := client.SetEgressPolicy("sb", nil, nil, true); err != nil {
		t.Fatal(err)
	}
	m.ForgetLearned("sb")
	if l := m.Learned("sb"); len(l.CIDRs) != 0 || len(l.Entries) != 0 {
		t.Fatalf("after forget = %+v", l)
	}
}

// echoServer listens on loopback and echoes every connection back.
func echoServer(t *testing.T) string {
	t.Helper()
	return echoServerOn(t, "127.0.0.1")
}

func echoServerOn(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
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
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// connectProxy is an upstream proxy that tunnels every CONNECT to target,
// whatever name the client asked for, so policy-mode names can be dialed in
// an offline test (the guard refuses a direct loopback dial).
func connectProxy(t *testing.T, target string) *egresspolicy.Upstream {
	t.Helper()
	return connectProxyHook(t, target, nil)
}

// connectProxyHook runs beforeOK after it has the CONNECT and before it
// answers, which is a dial in flight from the mediator's side.
func connectProxyHook(t *testing.T, target string, beforeOK func()) *egresspolicy.Upstream {
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
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				if beforeOK != nil {
					beforeOK()
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				go func() {
					_, _ = io.Copy(up, br)
					_ = up.Close()
				}()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	up, err := egresspolicy.NewUpstream("http://"+ln.Addr().String(), "", nil, nil, netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	return up
}

// assertEchoes proves c is still open end to end.
func assertEchoes(t *testing.T, what string, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatalf("%s: write on a connection that should stay open: %v", what, err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping\n" {
		t.Fatalf("%s: echo = %q, %v; want the connection to stay open", what, buf, err)
	}
}

// assertRevoked proves c was closed: a read fails at once instead of
// waiting out the deadline.
func assertRevoked(t *testing.T, what string, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("%s: connection still open after revocation (read err %v)", what, err)
	}
}

func assertDenied(t *testing.T, what string, err error, reason string) {
	t.Helper()
	var denied *wasmengine.EgressDeniedError
	if !errors.As(err, &denied) || denied.Reason != reason || !errors.Is(err, wasmengine.ErrNetworkEgressBlocked) {
		t.Fatalf("%s: err = %v, want a %s denial", what, err, reason)
	}
}

func (m *NetMediator) connCount(sandboxID string) int {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return len(m.conns[sandboxID])
}

// fastOperatorPoll makes the operator-file poll tick fast for one test.
func fastOperatorPoll(t *testing.T) {
	t.Helper()
	old := operatorPoll
	operatorPoll = 5 * time.Millisecond
	t.Cleanup(func() { operatorPoll = old })
}

// writeOperatorFile replaces the file and moves its mtime forward, so the
// poll sees a new version even within the filesystem's timestamp grain.
func writeOperatorFile(t *testing.T, path, body string) {
	t.Helper()
	var prev time.Time
	if st, err := os.Stat(path); err == nil {
		prev = st.ModTime()
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime().After(prev) {
		next := prev.Add(time.Second)
		if err := os.Chtimes(path, next, next); err != nil {
			t.Fatal(err)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestMediatorNoPolicyDialsUseOperatorGuard (review finding 8): a sandbox
// with no policy dials through the operator guard too, so the deny floor
// binds it; with no operator guard it keeps the open default byte for byte.
// The floor is all that binds it (the private-range rule and the zone are
// policy-mode rules), except that a strict guard (operator file unreadable)
// fails closed.
func TestMediatorNoPolicyDialsUseOperatorGuard(t *testing.T) {
	target := echoServer(t)
	zone, err := egresspolicy.NewInternalZone([]string{"corp.bank.internal"}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		guard  egresspolicy.DialGuard
		denied bool
	}{
		{"no_guard_open_default", egresspolicy.DialGuard{}, false},
		{"floor_not_covering", egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}, false},
		{"zone_only", egresspolicy.DialGuard{Zone: zone}, false},
		{"loopback_floor", egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}, true},
		{"strict_unreadable_file", egresspolicy.DialGuard{Strict: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newNetMediator()
			var denials []string
			m.SetEgressDenialObserver(func(_, _, addr, reason string) { denials = append(denials, addr+" "+reason) })
			m.SetDialGuard(tc.guard)
			c, err := m.DialContext(context.Background(), "sb", "tcp", target)
			if tc.denied {
				assertDenied(t, "no-policy dial", err, reasonBlockedIP)
				if len(denials) != 1 || denials[0] != target+" "+reasonBlockedIP {
					t.Fatalf("a floor refusal must be audited: %v", denials)
				}
				if m.connCount("sb") != 0 {
					t.Fatal("a refused dial must not be tracked")
				}
				return
			}
			if err != nil {
				t.Fatalf("no-policy dial: %v", err)
			}
			defer c.Close()
			assertEchoes(t, "no-policy conn", c)
		})
	}
}

// TestMediatorNoPolicySkipsUpstream: a no-policy dial by name never goes
// through the operator's upstream proxy, only through the guard; the proxy
// serves allowed names of a policy.
func TestMediatorNoPolicySkipsUpstream(t *testing.T) {
	target := echoServer(t)
	_, port, _ := net.SplitHostPort(target)
	m := newNetMediator()
	m.upstream = connectProxy(t, "127.0.0.1:1") // a tunnel would fail
	m.SetDialGuard(egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	c, err := m.DialContext(context.Background(), "sb", "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("no-policy name dial: %v", err)
	}
	defer c.Close()
	if c.RemoteAddr().String() != target {
		t.Fatalf("dialed %s, want the target %s directly", c.RemoteAddr(), target)
	}
	assertEchoes(t, "direct no-policy conn", c)
}

// TestMediatorPolicyChangeClosesRevokedConns (review finding 9): a live
// policy change closes the open connections it no longer admits, leaves the
// ones it does and other sandboxes' alone, and an egress block closes them
// all.
func TestMediatorPolicyChangeClosesRevokedConns(t *testing.T) {
	target := echoServer(t)
	m := newNetMediator()
	m.upstream = connectProxy(t, target)
	ctx := context.Background()
	dial := func(id, addr string) net.Conn {
		t.Helper()
		c, err := m.DialContext(ctx, id, "tcp", addr)
		if err != nil {
			t.Fatalf("%s %s: %v", id, addr, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	m.SetPolicy("sb", mustPolicy(t, []string{"a.example:8443", "b.example:8443"}, nil))
	m.SetPolicy("other", mustPolicy(t, []string{"a.example:8443"}, nil))
	a, b, other := dial("sb", "a.example:8443"), dial("sb", "b.example:8443"), dial("other", "a.example:8443")
	open := dial("np", target) // no policy: a direct loopback conn
	assertEchoes(t, "a before", a)

	m.SetPolicy("sb", mustPolicy(t, []string{"b.example:8443"}, nil))
	assertRevoked(t, "a after its name was dropped", a)
	assertEchoes(t, "b still allowed", b)
	assertEchoes(t, "another sandbox's conn", other)
	if n := m.connCount("sb"); n != 1 {
		t.Fatalf("registry holds %d conns for sb, want 1 (closed ones leave)", n)
	}

	// Removing a policy reopens egress; it revokes nothing.
	m.SetPolicy("np", nil)
	assertEchoes(t, "no-policy conn after nil", open)
	// Gaining a policy re-decides direct conns by IP through the guard.
	m.SetPolicy("np", mustPolicy(t, []string{"pypi.org"}, nil))
	assertRevoked(t, "loopback conn once a policy applies", open)

	// An egress block (quota or block-all) closes every open conn.
	m.SetBlocks("sb", false, true)
	assertRevoked(t, "b after an egress block", b)
	m.SetBlocks("other", true, false) // ingress only: egress conns stay
	assertEchoes(t, "other after an ingress-only block", other)
	m.AddBlocks("other", false, true)
	assertRevoked(t, "other after AddBlocks", other)
	for _, id := range []string{"sb", "other", "np"} {
		if n := m.connCount(id); n != 0 {
			t.Fatalf("%s: %d conns left in the registry", id, n)
		}
	}
	if _, err := m.DialContext(ctx, "sb", "tcp", "b.example:8443"); !errors.Is(err, wasmengine.ErrNetworkEgressBlocked) {
		t.Fatalf("blocked sandbox dialed: %v", err)
	}
}

// TestMediatorSNIDenialOnTunnel: the SNI check also guards a name tunneled
// through the upstream on 443, and its refusal is audited.
func TestMediatorSNIDenialOnTunnel(t *testing.T) {
	m := newNetMediator()
	m.upstream = connectProxy(t, echoServer(t))
	var got []string
	m.SetEgressDenialObserver(func(_, _, addr, reason string) { got = append(got, addr+" "+reason) })
	m.SetPolicy("sb", mustPolicy(t, []string{"pypi.org"}, nil))
	c, err := m.DialContext(context.Background(), "sb", "tcp", "pypi.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(clientHello(t, "evil.example")); err == nil {
		t.Fatal("fronting through the tunnel must be refused")
	}
	if len(got) != 1 || got[0] != "evil.example:443 "+reasonSNIMismatch {
		t.Fatalf("denials = %v", got)
	}
}

// TestMediatorTrackRechecksInFlightDial: a change that lands while a dial is
// in flight scans the registry before the new connection is in it, so track
// re-decides the connection against the current state before handing it out.
func TestMediatorTrackRechecksInFlightDial(t *testing.T) {
	m := newNetMediator()
	dest := connDest{host: "pypi.org", name: "pypi.org", port: 443, tunneled: true}
	m.SetPolicy("sb", mustPolicy(t, []string{"github.com"}, nil))
	inner, peer := net.Pipe()
	defer peer.Close()
	if c, err := m.track("sb", dest, inner); err == nil || c != nil {
		t.Fatalf("track admitted a destination the current policy refuses: %v", err)
	}
	if _, err := inner.Write([]byte("x")); err == nil {
		t.Fatal("the refused connection must be closed")
	}
	if m.connCount("sb") != 0 {
		t.Fatal("the refused connection must leave the registry")
	}
	m.SetPolicy("sb", mustPolicy(t, []string{"pypi.org"}, nil))
	inner2, peer2 := net.Pipe()
	defer peer2.Close()
	c, err := m.track("sb", dest, inner2)
	if err != nil || m.connCount("sb") != 1 {
		t.Fatalf("track = %v, conns = %d", err, m.connCount("sb"))
	}
	if err := c.Close(); err != nil || c.Close() != nil || m.connCount("sb") != 0 {
		t.Fatal("Close must be idempotent and unregister")
	}
	if remoteAddr(peer2).IsValid() {
		t.Fatal("a non-TCP connection has no address the guard could judge")
	}
}

// TestMediatorRevokedWhileDialing: a block that lands while the tunnel is
// being set up (after the policy check, before the dial returns) still keeps
// the connection from the guest.
func TestMediatorRevokedWhileDialing(t *testing.T) {
	m := newNetMediator()
	m.upstream = connectProxyHook(t, echoServer(t), func() { m.SetBlocks("sb", false, true) })
	m.SetPolicy("sb", mustPolicy(t, []string{"pypi.org:8443"}, nil))
	c, err := m.DialContext(context.Background(), "sb", "tcp", "pypi.org:8443")
	if !errors.Is(err, wasmengine.ErrNetworkEgressBlocked) || c != nil {
		t.Fatalf("a dial revoked in flight reached the guest: %v", err)
	}
	if m.connCount("sb") != 0 {
		t.Fatal("the revoked dial must not stay in the registry")
	}
}

// localIPv4 is a non-loopback, non-link-local IPv4 address of this host: the
// guard admits a direct dial there when a policy CIDR allows it, which a
// loopback listener can never show.
func localIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no interface addresses: %v", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok {
			if ip = ip.Unmap(); ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	t.Skip("this host has no non-loopback IPv4 address")
	return netip.Addr{}
}

// TestMediatorDirectPolicyConnRevoked: a direct (not tunneled) policy conn is
// held to the address it reached. A tightened operator floor and a narrowed
// CIDR list both close it.
func TestMediatorDirectPolicyConnRevoked(t *testing.T) {
	ip := localIPv4(t)
	target := echoServerOn(t, ip.String())
	cidr := netip.PrefixFrom(ip, 32).String()
	m := newNetMediator()
	ctx := context.Background()
	m.SetPolicy("sb", mustPolicy(t, []string{cidr}, nil))
	c, err := m.DialContext(ctx, "sb", "tcp", target)
	if err != nil {
		t.Fatalf("a CIDR-allowed direct dial: %v", err)
	}
	defer c.Close()
	assertEchoes(t, "direct policy conn", c)

	m.SetDialGuard(egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix(cidr)}})
	assertRevoked(t, "a policy conn the new floor covers", c)
	_, err = m.DialContext(ctx, "sb", "tcp", target)
	assertDenied(t, "a policy dial into the floor", err, reasonBlockedIP)

	m.SetDialGuard(egresspolicy.DialGuard{})
	c2, err := m.DialContext(ctx, "sb", "tcp", target)
	if err != nil {
		t.Fatalf("after the floor was lifted: %v", err)
	}
	defer c2.Close()
	m.SetPolicy("sb", mustPolicy(t, []string{"203.0.113.0/24"}, nil))
	assertRevoked(t, "a direct conn whose CIDR was dropped", c2)
}

// TestAdmits pins the re-decision rules a live connection is held to.
func TestAdmits(t *testing.T) {
	floor := egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	strict := egresspolicy.DialGuard{Strict: true}
	names := mustPolicy(t, []string{"pypi.org"}, nil)
	cidr := mustPolicy(t, []string{"198.51.100.0/24"}, nil)
	learn, err := egresspolicy.Compile(egresspolicy.Spec{Mode: egresspolicy.ModeLearn})
	if err != nil {
		t.Fatal(err)
	}
	public := netip.MustParseAddrPort("198.51.100.7:443")
	byName := connDest{host: "pypi.org", name: "pypi.org", port: 443, addr: public}
	byIP := connDest{host: "198.51.100.7", port: 443, addr: public}
	cases := []struct {
		name string
		a    admission
		d    connDest
		want bool
	}{
		{"blocked", admission{blocked: true}, byName, false},
		{"open_no_guard_loopback", admission{}, connDest{host: "127.0.0.1", port: 80, addr: netip.MustParseAddrPort("127.0.0.1:80")}, true},
		{"open_floor_refuses", admission{guard: floor}, connDest{host: "203.0.113.9", port: 80, addr: netip.MustParseAddrPort("203.0.113.9:80")}, false},
		{"open_floor_allows_private", admission{guard: floor}, connDest{host: "10.0.0.9", port: 80, addr: netip.MustParseAddrPort("10.0.0.9:80")}, true},
		{"open_strict_refuses_private", admission{guard: strict}, connDest{host: "10.0.0.9", port: 80, addr: netip.MustParseAddrPort("10.0.0.9:80")}, false},
		{"open_tunnel_skips_guard", admission{guard: strict}, connDest{host: "pypi.org", name: "pypi.org", port: 443, tunneled: true}, true},
		{"policy_name_allowed", admission{policy: names}, byName, true},
		{"policy_name_dropped", admission{policy: cidr}, byName, false},
		{"policy_tunnel_allowed", admission{policy: names, guard: strict}, connDest{host: "pypi.org", name: "pypi.org", port: 443, tunneled: true}, true},
		{"policy_name_resolved_to_loopback", admission{policy: names}, connDest{host: "pypi.org", name: "pypi.org", port: 443, addr: netip.MustParseAddrPort("127.0.0.1:443")}, false},
		{"policy_cidr_allowed", admission{policy: cidr}, byIP, true},
		{"policy_cidr_floor_wins", admission{policy: mustPolicy(t, []string{"203.0.113.0/24"}, nil), guard: floor}, connDest{host: "203.0.113.9", port: 443, addr: netip.MustParseAddrPort("203.0.113.9:443")}, false},
		{"policy_unparsed_host", admission{policy: cidr}, connDest{host: "no-port"}, false},
		{"learn_public", admission{policy: learn}, byIP, true},
		{"policy_unknown_addr_fails_closed", admission{policy: names}, connDest{host: "pypi.org", name: "pypi.org", port: 443}, false},
	}
	for _, tc := range cases {
		if got := admits(tc.a, tc.d); got != tc.want {
			t.Errorf("%s: admits = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestOperatorReloadReachesRunningWorker (review finding 7, WASM part): the
// worker follows the operator file the way sandboxd does. A tightened floor
// refuses new dials and closes the open connections it now covers; an
// invalid edit keeps the last good file; an upstream that can't be built
// keeps the previous chain; the poll stops with the worker.
func TestOperatorReloadReachesRunningWorker(t *testing.T) {
	fastOperatorPoll(t)
	target := echoServer(t)
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	writeOperatorFile(t, path, "version: 1\ndeny_cidrs: [203.0.113.0/24]\n")
	t.Setenv("SB_EGRESS_OPERATOR_FILE", path)
	m := newNetMediator()
	installOperatorGuard(m)
	t.Cleanup(m.stopOperatorWatch)
	ctx := context.Background()
	live, err := m.DialContext(ctx, "sb", "tcp", target)
	if err != nil {
		t.Fatalf("a floor that doesn't cover the listener must admit it: %v", err)
	}
	defer live.Close()
	assertEchoes(t, "before the reload", live)

	floorIs := func(cidr string) func() bool {
		return func() bool {
			g := m.dialGuard()
			return len(g.DenyFloor) == 1 && g.DenyFloor[0].String() == cidr
		}
	}
	writeOperatorFile(t, path, "version: 1\ndeny_cidrs: [127.0.0.0/8]\n")
	waitFor(t, "the tightened floor", floorIs("127.0.0.0/8"))
	assertRevoked(t, "a conn the new floor covers", live)
	_, err = m.DialContext(ctx, "sb", "tcp", target)
	assertDenied(t, "a dial after the reload", err, reasonBlockedIP)

	// An invalid edit keeps the last good file.
	writeOperatorFile(t, path, "version: 1\ndeny_cidrs: [not-a-cidr]\n")
	time.Sleep(50 * time.Millisecond)
	if !floorIs("127.0.0.0/8")() {
		t.Fatalf("an invalid reload replaced the guard: %+v", m.dialGuard())
	}

	// The upstream chain follows the file too, and survives a bad auth_file.
	writeOperatorFile(t, path, "version: 1\ndeny_cidrs: [127.0.0.0/8]\nupstream_proxy: {url: \"http://10.0.0.1:3128\"}\n")
	waitFor(t, "the upstream chain", func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.upstream != nil
	})
	m.mu.RLock()
	prev := m.upstream
	m.mu.RUnlock()
	missing := filepath.Join(t.TempDir(), "proxy-auth")
	writeOperatorFile(t, path, "version: 1\ndeny_cidrs: [192.0.2.0/24]\nupstream_proxy: {url: \"http://10.0.0.2:3128\", auth_file: \""+missing+"\"}\n")
	waitFor(t, "the next floor", floorIs("192.0.2.0/24"))
	m.mu.RLock()
	kept := m.upstream == prev
	m.mu.RUnlock()
	if !kept {
		t.Fatal("an upstream that can't be built must keep the previous chain")
	}

	m.mu.RLock()
	done := m.operatorDone
	m.mu.RUnlock()
	m.stopOperatorWatch()
	select {
	case <-done:
	default:
		t.Fatal("stopOperatorWatch must wait for the poll to end")
	}
	m.stopOperatorWatch() // idempotent
	(*NetMediator)(nil).stopOperatorWatch()
}

// TestWorkerCloseStopsOperatorPoll: both worker kinds stop the poll when they
// stop serving, and closing one that never built a mediator is harmless.
func TestWorkerCloseStopsOperatorPoll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	writeOperatorFile(t, path, "version: 1\n")
	t.Setenv("SB_EGRESS_OPERATOR_FILE", path)
	stopped := func(m *NetMediator) bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.stopOperator == nil
	}
	(&Server{}).close()
	(&ResidentServer{}).close()

	s := &Server{}
	if m := s.mediator(); stopped(m) {
		t.Fatal("the worker must poll the operator file")
	} else {
		s.close()
		if !stopped(m) {
			t.Fatal("Server.close must stop the poll")
		}
	}
	r := &ResidentServer{}
	if m := r.mediator(); stopped(m) {
		t.Fatal("the resident host must poll the operator file")
	} else {
		r.close()
		if !stopped(m) {
			t.Fatal("ResidentServer.close must stop the poll")
		}
	}
}
