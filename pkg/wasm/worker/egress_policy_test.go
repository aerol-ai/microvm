package worker

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
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
	if err := client.SetEgressPolicy("sb", nil, nil); err != nil {
		t.Fatal(err)
	}
	if srv.mediator().policyFor("sb") != nil {
		t.Fatal("set_egress_policy with empty lists must remove the policy")
	}
	if err := client.SetEgressPolicy("sb", []string{"github.com"}, nil); err != nil {
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
