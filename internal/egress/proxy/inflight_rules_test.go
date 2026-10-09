package proxy

// Regression tests from the fourth review of PR #622: each reproduces a
// finding against the reviewed head (4fdb667c) and passes with its fix.

import (
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

func TestInFlightTLSDialHonorsABinaryRuleChange(t *testing.T) {
	id := &fakeIdentity{exe: "/usr/bin/curl"}
	spec := allowSpec("pypi.org")
	spec.Rules = []egresspolicy.RuleSpec{{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/bin/curl"}}}
	spec.Pid = 4242
	r := newRig(t, 443, spec, Config{Identify: id.identify, DialTimeout: 3 * time.Second})
	r.dialer.resolve["pypi.org"] = "151.101.0.223"
	r.dialer.backend["pypi.org"] = tlsBackend(t)
	d := &pausedDialer{base: r.dialer, entered: make(chan struct{}), resume: make(chan struct{})}
	r.proxy.cfg.Dialer = d
	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() { body, err := tlsGet(r.addr, "pypi.org"); done <- result{body, err} }()
	select {
	case <-d.entered:
	case <-time.After(3 * time.Second):
		close(d.resume)
		t.Fatal("dial not entered")
	}
	next := spec
	next.IP = peer
	next.Rules = []egresspolicy.RuleSpec{{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/bin/wget"}}}
	err := r.gw.Attach(next)
	close(d.resume)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err == nil && strings.Contains(got.body, "secure-ok") {
			t.Fatal("TLS connection from revoked curl binary completed after the policy changed to wget-only")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not settle")
	}
}

func TestInFlightTLSDialHonorsNewInspection(t *testing.T) {
	r := newInspectRig(t, Config{DialTimeout: 3 * time.Second})
	d := &pausedDialer{base: r.dialer, entered: make(chan struct{}), resume: make(chan struct{})}
	r.proxy.cfg.Dialer = d
	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() { body, err := tlsGet(r.addr, "api.example.com"); done <- result{body, err} }()
	select {
	case <-d.entered:
	case <-time.After(3 * time.Second):
		close(d.resume)
		t.Fatal("dial not entered")
	}
	next := allowSpec("api.example.com", "other.example.com")
	next.IP = peer
	next.Rules = []egresspolicy.RuleSpec{{Host: "api.example.com", Inspect: true, Methods: []string{"POST"}}}
	err := r.gw.Attach(next)
	close(d.resume)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err == nil && strings.Contains(got.body, "GET / host=api.example.com") {
			t.Fatal("raw TLS bypassed the newly installed inspection rule: GET succeeded under POST-only policy")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not settle")
	}
}
