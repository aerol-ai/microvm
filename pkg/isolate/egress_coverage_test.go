package isolate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

func TestSplitAuthority(t *testing.T) {
	tests := []struct {
		authority string
		host      string
		port      uint16
		ok        bool
	}{
		{"api.example.com", "api.example.com", 443, true}, // no port: dialed as https
		{"api.example.com:8443", "api.example.com", 8443, true},
		{"203.0.113.7:80", "203.0.113.7", 80, true},
		{"[2001:db8::1]:443", "2001:db8::1", 443, true},
		{"[2001:db8::1]", "2001:db8::1", 443, true},
		{"api.example.com:0", "api.example.com", 0, false},
		{"api.example.com:http", "api.example.com", 0, false},
		{"", "", 443, true},
	}
	for _, tc := range tests {
		host, port, ok := splitAuthority(tc.authority)
		if host != tc.host || port != tc.port || ok != tc.ok {
			t.Errorf("splitAuthority(%q) = %q %d %v, want %q %d %v", tc.authority, host, port, ok, tc.host, tc.port, tc.ok)
		}
	}
}

// TestEgressDialControl pins the dial-time half of isolate's SSRF guard (D15):
// the shared transport refuses special-use resolved addresses.
func TestEgressDialControl(t *testing.T) {
	control := egressTransport.(*http.Transport).DialContext
	if control == nil {
		t.Fatal("egress transport must dial through the guarded dialer")
	}
	strict := currentIsolateGuard().Control(nil, "", false)
	if err := strict("tcp", "127.0.0.1:80", nil); err == nil {
		t.Fatal("loopback must be denied")
	}
	if err := strict("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatal("link-local must be denied")
	}
	if err := strict("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("public IP must be allowed: %v", err)
	}
	// No port → treat whole address as host.
	if err := strict("tcp", "10.0.0.1", nil); err == nil {
		t.Fatal("private IP without port must be denied")
	}
	// A real dial to a loopback listener is refused before connect.
	_, err := control(context.Background(), "tcp", "127.0.0.1:1")
	if !errors.Is(err, egresspolicy.ErrDialRefused) {
		t.Fatalf("dial to loopback = %v, want ErrDialRefused", err)
	}
}

// TestProxyEgressPortAndPrecedence covers the request-path decisions the
// shared grammar adds: port semantics (EF-45 port rows), "*." syntax, and
// allow-wins mixed lists (D4).
func TestProxyEgressPortAndPrecedence(t *testing.T) {
	old := egressTransport
	t.Cleanup(func() { egressTransport = old })
	egressTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	h := &Host{}
	tests := []struct {
		name      string
		p         EgressPolicy
		authority string
		want      int
	}{
		{"bare_host_default_port", EgressPolicy{Allow: []string{"api.example.com"}}, "api.example.com", http.StatusOK},
		{"bare_host_other_port", EgressPolicy{Allow: []string{"api.example.com"}}, "api.example.com:8443", http.StatusForbidden},
		{"host_port_rule", EgressPolicy{Allow: []string{"api.example.com:8443"}}, "api.example.com:8443", http.StatusOK},
		{"star_wildcard", EgressPolicy{Allow: []string{"*.example.com"}}, "x.y.example.com", http.StatusOK},
		{"star_wildcard_not_apex", EgressPolicy{Allow: []string{"*.example.com"}}, "example.com", http.StatusForbidden},
		{"mixed_default_accept", EgressPolicy{Allow: []string{"api.example.com"}, Deny: []string{"198.51.100.0/24"}}, "other.example", http.StatusOK},
		{"mixed_deny_cidr_literal", EgressPolicy{Allow: []string{"api.example.com"}, Deny: []string{"198.51.100.0/24"}}, "198.51.100.7", http.StatusForbidden},
		{"invalid_port", EgressPolicy{}, "api.example.com:0", http.StatusForbidden},
		{"private_literal_even_if_cidr_allowed", EgressPolicy{Allow: []string{"10.0.0.0/8"}}, "10.0.0.5:8080", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://placeholder/", nil)
			req.Host = tc.authority
			rec := httptest.NewRecorder()
			h.proxyEgress(rec, req, "sb-port", mustPolicy(t, tc.p))
			if rec.Code != tc.want {
				t.Fatalf("%s via %+v = %d, want %d (%s)", tc.authority, tc.p, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestProxyEgressSuccessAndUpstreamError(t *testing.T) {
	old := egressTransport
	t.Cleanup(func() { egressTransport = old })

	egressTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" {
			t.Fatalf("scheme = %q, want https", r.URL.Scheme)
		}
		return &http.Response{
			StatusCode: http.StatusTeapot,
			Header:     http.Header{"X-Up": []string{"1"}},
			Body:       io.NopCloser(strings.NewReader("proxied")),
		}, nil
	})
	h := &Host{}
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1", nil)
	rec := httptest.NewRecorder()
	h.proxyEgress(rec, req, "sb-proxy", mustPolicy(t, EgressPolicy{}))
	if rec.Code != http.StatusTeapot || rec.Body.String() != "proxied" || rec.Header().Get("X-Up") != "1" {
		t.Fatalf("proxy success = %d %q hdr=%v", rec.Code, rec.Body.String(), rec.Header())
	}

	egressTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})
	rec = httptest.NewRecorder()
	h.proxyEgress(rec, httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil), "sb-proxy", mustPolicy(t, EgressPolicy{}))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("upstream err = %d, want 502", rec.Code)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSetEgressPolicyEdges(t *testing.T) {
	h, err := NewHost(HostConfig{
		WorkerdPath:    "/w",
		GroupKey:       "acme",
		RunDir:         shortRunDir(t),
		EgressPoolSize: 1,
		Logger:         slog.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.SetEgressPolicy("", EgressPolicy{}) // no-op

	// Claim a slot, then flip to block-all — must free it.
	h.SetEgressPolicy("sb-1", EgressPolicy{})
	if _, ok := h.slotByID["sb-1"]; !ok {
		t.Fatal("expected slot")
	}
	h.SetEgressPolicy("sb-1", EgressPolicy{}) // already assigned — keep slot
	if _, ok := h.slotByID["sb-1"]; !ok {
		t.Fatal("re-set should keep slot")
	}
	h.SetEgressPolicy("sb-1", EgressPolicy{BlockAll: true})
	if _, ok := h.slotByID["sb-1"]; ok {
		t.Fatal("block-all must free prior slot")
	}

	// A stored pre-grammar row (hostname deny, D15) fails closed: block-all,
	// no slot — never the old deny-by-name behavior and never open.
	h.SetEgressPolicy("sb-legacy", EgressPolicy{})
	h.SetEgressPolicy("sb-legacy", EgressPolicy{Deny: []string{"evil.com"}})
	if _, ok := h.slotByID["sb-legacy"]; ok {
		t.Fatal("uncompilable policy must release the slot")
	}
	if p := h.egressPolicy["sb-legacy"]; p == nil || !p.BlockAll() {
		t.Fatalf("uncompilable policy stored as %+v, want block-all", p)
	}

	// Force startSlotServerLocked failure: replace sock path with a directory
	// that os.Remove cannot clear (non-empty), so Listen fails.
	h2, err := NewHost(HostConfig{
		WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t), EgressPoolSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	sock := h2.egressSocks[0]
	if err := os.MkdirAll(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sock, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h2.SetEgressPolicy("sb-x", EgressPolicy{})
	if _, ok := h2.slotByID["sb-x"]; ok {
		t.Fatal("listen failure must fall back to deny-all (no slot)")
	}
}

// TestProxyEgressLearnMode (P2-7): a learn-mode policy allows anything, and
// each successful upstream contact reaches the learn observer; an enforce
// policy never does.
func TestProxyEgressLearnMode(t *testing.T) {
	old := egressTransport
	t.Cleanup(func() { egressTransport = old })
	egressTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
	})
	var seen []string
	h := &Host{}
	h.SetLearnObserver(func(id, host string, port uint16) {
		seen = append(seen, fmt.Sprintf("%s %s:%d", id, host, port))
	})
	learn := mustPolicy(t, EgressPolicy{Learn: true})
	if learn.Mode() != egresspolicy.ModeLearn {
		t.Fatalf("mode = %q", learn.Mode())
	}
	rec := httptest.NewRecorder()
	h.proxyEgress(rec, httptest.NewRequest(http.MethodGet, "http://anything.example/", nil), "sb-l", learn)
	if rec.Code != http.StatusOK || len(seen) != 1 || seen[0] != "sb-l anything.example:443" {
		t.Fatalf("learn = %d %v", rec.Code, seen)
	}
	h.proxyEgress(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil), "sb-e", mustPolicy(t, EgressPolicy{}))
	if len(seen) != 1 {
		t.Fatalf("an enforce policy must not be recorded: %v", seen)
	}
	var nilHost *Host
	nilHost.SetLearnObserver(nil)
}
