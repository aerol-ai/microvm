package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// fakeIdentity stands in for procid: every connection is the current exe.
type fakeIdentity struct {
	mu   sync.Mutex
	exe  string
	err  error
	pids []int
}

func (f *fakeIdentity) set(exe string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exe, f.err = exe, err
}

func (f *fakeIdentity) identify(pid int, _, _ netip.AddrPort) (func(string) bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pids = append(f.pids, pid)
	if f.err != nil {
		return nil, f.err
	}
	exe := f.exe
	return func(p string) bool { return p == exe }, nil
}

// TestBinariesTLS (EF-55): a per-binary rule on 443 admits only the listed
// executable; the admitted rules decide inspection.
func TestBinariesTLS(t *testing.T) {
	id := &fakeIdentity{exe: "/usr/bin/git"}
	r := newInspectRig(t, Config{Identify: id.identify},
		egresspolicy.RuleSpec{Host: "api.example.com", Ports: []uint16{443}, Binaries: []string{"/usr/bin/git"}},
		egresspolicy.RuleSpec{Host: "api.example.com", Inspect: true, Methods: []string{"GET"}, Binaries: []string{"/usr/bin/curl"}})

	// git: admitted for the whole connection, passed through uninspected.
	conn, err := tls.Dial("tcp", r.addr, &tls.Config{ServerName: "api.example.com", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if org := conn.ConnectionState().PeerCertificates[0].Issuer.Organization; len(org) > 0 && org[0] == "AerolVM egress inspection" {
		t.Fatal("git's connection must not be inspected")
	}
	conn.Close()

	// curl: admitted by the inspect rule, so GET only.
	id.set("/usr/bin/curl", nil)
	c := r.client(false)
	if code, _, _ := do(t, c, http.MethodGet, "https://api.example.com/x", "", ""); code != 200 {
		t.Fatalf("curl GET = %d", code)
	}
	if code, _, _ := do(t, c, http.MethodPost, "https://api.example.com/x", "", "b"); code != 403 {
		t.Fatalf("curl POST = %d", code)
	}

	// wget: no rule admits it; an untraceable connection is refused too.
	for _, tc := range []struct {
		exe    string
		err    error
		reason string
	}{{"/usr/bin/wget", nil, ReasonBinaryNotAllowed}, {"", errors.New("gone"), ReasonBinaryUnknown}} {
		id.set(tc.exe, tc.err)
		if _, err := tls.Dial("tcp", r.addr, &tls.Config{ServerName: "api.example.com", InsecureSkipVerify: true}); err == nil {
			t.Fatalf("%s must be refused", tc.exe)
		}
		if d := r.last(); d.Reason != tc.reason {
			t.Fatalf("decision = %+v", d)
		}
	}
	// No identifier at all: refused, never passed through.
	none := newInspectRig(t, Config{}, egresspolicy.RuleSpec{Host: "api.example.com", Ports: []uint16{443}, Binaries: []string{"/usr/bin/git"}})
	if _, err := tls.Dial("tcp", none.addr, &tls.Config{ServerName: "api.example.com", InsecureSkipVerify: true}); err == nil || none.last().Reason != ReasonBinaryUnknown {
		t.Fatalf("no identifier: %v %+v", err, none.last())
	}
}

// TestBinariesHTTP: on port 80 the connection is traced once, on the first
// request a per-binary rule covers.
func TestBinariesHTTP(t *testing.T) {
	id := &fakeIdentity{exe: "/usr/bin/curl"}
	spec := allowSpec("plain.example.com", "other.example.com")
	spec.Rules = []egresspolicy.RuleSpec{{Host: "plain.example.com", Binaries: []string{"/usr/bin/curl"}}}
	spec.Pid = 4242
	r := newRig(t, 80, spec, Config{Identify: id.identify})
	backend := httpBackend(t)
	for _, h := range []string{"plain.example.com", "other.example.com"} {
		r.dialer.resolve[h] = "151.101.0.1"
		r.dialer.backend[h] = backend
	}
	got := httpExchange(t, r.addr,
		"GET / HTTP/1.1\r\nHost: plain.example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: plain.example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n")
	if len(got) != 3 || !strings.HasPrefix(got[0], "200") || !strings.HasPrefix(got[2], "200") {
		t.Fatalf("curl: %v", got)
	}
	if len(id.pids) != 1 || id.pids[0] != 4242 {
		t.Fatalf("traced %v times with pids %v; want once, with the spec's pid", len(id.pids), id.pids)
	}
	id.set("/usr/bin/wget", nil)
	got = httpExchange(t, r.addr, "GET / HTTP/1.1\r\nHost: plain.example.com\r\n\r\n")
	if len(got) != 1 || !strings.HasPrefix(got[0], "403") || !strings.Contains(got[0], "binaries") || r.last().Reason != ReasonBinaryNotAllowed {
		t.Fatalf("wget: %v", got)
	}
}

// TestBinariesTraced (EF-55): a port other than 80/443, redirected through
// bin_learned, is spliced only for the listed executable.
func TestBinariesTraced(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	id := &fakeIdentity{exe: "/usr/bin/git"}
	spec := allowSpec("github.com:22")
	spec.Rules = []egresspolicy.RuleSpec{{Host: "github.com", Ports: []uint16{22}, Binaries: []string{"/usr/bin/git"}}}
	r := newRig(t, 22, spec, Config{Identify: id.identify})
	r.dialer.backend["93.184.216.34"] = echo.Addr().String()
	dial := func() (string, error) {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			return "", err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("ssh")); err != nil {
			return "", err
		}
		b := make([]byte, 3)
		_, err = io.ReadFull(c, b)
		return string(b), err
	}
	// Not learned yet: no name, refused.
	if got, err := dial(); err == nil || r.last().Reason != ReasonBinaryUnknown {
		t.Fatalf("unnamed flow: %q %v", got, err)
	}
	if err := r.gw.LearnFor("sb", "github.com", netip.MustParseAddr("93.184.216.34"), 22, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, err := dial(); err != nil || got != "ssh" {
		t.Fatalf("git: %q %v", got, err)
	}
	if d := r.last(); !d.Allowed || d.Host != "github.com" || d.Port != 22 {
		t.Fatalf("decision = %+v", d)
	}
	id.set("/usr/bin/nc", nil)
	if _, err := dial(); err == nil || r.last().Reason != ReasonBinaryNotAllowed {
		t.Fatalf("nc must be reset: %v %+v", err, r.last())
	}
	// A dial the guard refuses (the backend address is unknown here).
	id.set("/usr/bin/git", nil)
	delete(r.dialer.backend, "93.184.216.34")
	if _, err := dial(); err == nil || r.last().Reason != ReasonDialFailed {
		t.Fatalf("dial failure: %v %+v", err, r.last())
	}
}
