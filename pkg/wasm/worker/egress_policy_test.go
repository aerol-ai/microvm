package worker

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
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
// internal zone and floor; a file it can't load leaves it strict.
func TestInstallOperatorGuard(t *testing.T) {
	m := newNetMediator()
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
	t.Setenv("SB_EGRESS_OPERATOR_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
	installOperatorGuard(m)
	if !m.dialGuard().Strict {
		t.Fatal("an unreadable file must leave the worker strict")
	}
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
