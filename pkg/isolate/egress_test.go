package isolate

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

func mustPolicy(t *testing.T, p EgressPolicy) *egresspolicy.Policy {
	t.Helper()
	cp, err := compileEgressPolicy(p)
	if err != nil {
		t.Fatalf("compile %+v: %v", p, err)
	}
	return cp
}

// TestEgressPolicyMatching is the isolate regression contract (D15, T1):
// isolate is on the shared egresspolicy matcher. Every pre-migration row is
// kept; the deny-precedence row now asserts allow-wins (D4), and hostname
// deny entries moved to CIDRs because the shared grammar rejects them.
func TestEgressPolicyMatching(t *testing.T) {
	tests := []struct {
		name string
		p    EgressPolicy
		host string
		port uint16
		want bool
	}{
		{"block-all denies", EgressPolicy{BlockAll: true}, "api.example.com", 443, false},
		{"empty allow = allow all", EgressPolicy{}, "api.example.com", 443, true},
		{"deny wins over empty allow", EgressPolicy{Deny: []string{"203.0.113.0/24"}}, "203.0.113.7", 443, false},
		{"exact allow match", EgressPolicy{Allow: []string{"api.example.com"}}, "api.example.com", 443, true},
		{"allow miss", EgressPolicy{Allow: []string{"api.example.com"}}, "other.com", 443, false},
		{"suffix wildcard", EgressPolicy{Allow: []string{".example.com"}}, "a.b.example.com", 443, true},
		{"suffix wildcard non-match", EgressPolicy{Allow: []string{".example.com"}}, "example.org", 443, false},
		{"allow wins over deny (D4)", EgressPolicy{Allow: []string{"203.0.113.0/25"}, Deny: []string{"203.0.113.0/24"}}, "203.0.113.7", 443, true},
		{"cidr in-range", EgressPolicy{Allow: []string{"203.0.113.0/24"}}, "203.0.113.7", 443, true},
		{"cidr out-of-range", EgressPolicy{Allow: []string{"203.0.113.0/24"}}, "198.51.100.7", 443, false},
		{"case-insensitive host", EgressPolicy{Allow: []string{"api.example.com"}}, "API.Example.COM", 443, true},
		// New with the shared grammar.
		{"star wildcard any depth", EgressPolicy{Allow: []string{"*.example.com"}}, "a.b.example.com", 443, true},
		{"star wildcard not the apex (EF-22)", EgressPolicy{Allow: []string{"*.example.com"}}, "example.com", 443, false},
		{"legacy suffix not the apex", EgressPolicy{Allow: []string{".example.com"}}, "example.com", 443, false},
		{"bare host is 80/443 only (EF-45)", EgressPolicy{Allow: []string{"api.example.com"}}, "api.example.com", 8443, false},
		{"host:port allows that port", EgressPolicy{Allow: []string{"api.example.com:8443"}}, "api.example.com", 8443, true},
		{"host:port is not the web ports", EgressPolicy{Allow: []string{"api.example.com:8443"}}, "api.example.com", 443, false},
		{"mixed lists default accept (D4)", EgressPolicy{Allow: []string{"api.example.com"}, Deny: []string{"203.0.113.0/24"}}, "other.com", 443, true},
		{"allow plus deny-all is an allowlist", EgressPolicy{Allow: []string{"api.example.com"}, Deny: []string{"0.0.0.0/0"}}, "other.com", 443, false},
		{"deny-all alone is block-all", EgressPolicy{Deny: []string{"0.0.0.0/0"}}, "other.com", 443, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := mustPolicy(t, tc.p).MatchHostPort(tc.host, tc.port); got != tc.want {
				t.Fatalf("MatchHostPort(%+v, %q, %d) = %v, want %v", tc.p, tc.host, tc.port, got, tc.want)
			}
		})
	}
}

// TestCompileEgressPolicyRejectsHostnameDeny is EF-45's grammar half: a
// hostname in Deny no longer compiles (the service turns it into a 400).
func TestCompileEgressPolicyRejectsHostnameDeny(t *testing.T) {
	_, err := compileEgressPolicy(EgressPolicy{Allow: []string{".example.com"}, Deny: []string{"bad.example.com"}})
	if !errors.Is(err, egresspolicy.ErrInvalid) || !strings.Contains(err.Error(), `"bad.example.com"`) {
		t.Fatalf("err = %v, want ErrInvalid naming the entry", err)
	}
}

// TestIsolateDialGuardBlocks keeps isolate's strict SSRF ranges (D15):
// loopback, link-local, private (RFC 1918 + ULA), unspecified.
func TestIsolateDialGuardBlocks(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback (the sandboxd API)
		"::1",             // loopback v6
		"169.254.169.254", // cloud metadata
		"10.0.0.5",        // RFC1918
		"172.16.0.1",      // RFC1918
		"192.168.1.1",     // RFC1918
		"0.0.0.0",         // unspecified
		"fe80::1",         // link-local v6
		"fc00::1",         // ULA
	}
	for _, s := range blocked {
		if err := isolateDialGuard.Check(nil, egresspolicy.DialTarget{Addr: netip.AddrPortFrom(netip.MustParseAddr(s), 443)}); err == nil {
			t.Errorf("%s allowed, want blocked", s)
		}
	}
	// Strict mode: a policy CIDR does not open a private range on isolate.
	cidr := mustPolicy(t, EgressPolicy{Allow: []string{"10.0.0.0/8"}})
	if err := isolateDialGuard.Check(cidr, egresspolicy.DialTarget{Addr: netip.MustParseAddrPort("10.0.0.5:443")}); err == nil {
		t.Error("CIDR-allowed private address reachable on isolate")
	}
	allowed := []string{"8.8.8.8", "203.0.113.10", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if err := isolateDialGuard.Check(nil, egresspolicy.DialTarget{Addr: netip.AddrPortFrom(netip.MustParseAddr(s), 443)}); err != nil {
			t.Errorf("%s blocked (%v), want allowed (public address)", s, err)
		}
	}
}

// TestProxyEgressBlocksLiteralSSRF proves an isolate whose policy is the default
// allow-all still cannot reach a loopback/metadata IP literal through the proxy.
func TestProxyEgressBlocksLiteralSSRF(t *testing.T) {
	h := &Host{}
	for _, target := range []string{"http://127.0.0.1:21212/v1/sandboxes", "http://169.254.169.254/latest/meta-data/"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		h.proxyEgress(rec, req, "sb-ssrf", mustPolicy(t, EgressPolicy{})) // allow-all policy
		if rec.Code != http.StatusForbidden {
			t.Fatalf("egress to %s = %d, want 403 (blocked)", target, rec.Code)
		}
		if body, _ := io.ReadAll(rec.Result().Body); !strings.Contains(string(body), "blocked") {
			t.Fatalf("egress to %s body = %q, want a 'blocked' denial", target, body)
		}
	}
}

// TestProxyEgressPolicyDeny covers the offline decision branches of proxyEgress:
// a host outside the allowlist is refused, and a request with no destination
// authority is refused (both without touching the network).
func TestProxyEgressPolicyDeny(t *testing.T) {
	h := &Host{}

	// Host not in the allowlist → 403 by policy.
	req := httptest.NewRequest(http.MethodGet, "http://other.example/x", nil)
	rec := httptest.NewRecorder()
	h.proxyEgress(rec, req, "sb-1", mustPolicy(t, EgressPolicy{Allow: []string{"only.example"}}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-allowlisted host = %d, want 403", rec.Code)
	}
	if body, _ := io.ReadAll(rec.Result().Body); !strings.Contains(string(body), "policy") {
		t.Fatalf("deny body = %q, want a policy denial", body)
	}

	// No destination authority → 403 (cannot attribute a target).
	req = httptest.NewRequest(http.MethodGet, "http://x/y", nil)
	req.Host = ""
	req.URL.Host = ""
	rec = httptest.NewRecorder()
	h.proxyEgress(rec, req, "sb-1", mustPolicy(t, EgressPolicy{}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-host = %d, want 403", rec.Code)
	}
}

// TestProxyEgressObserverCapturesHost proves a successful proxy records the
// destination on the EgressObserver (E3a). Denied paths must not fire it.
func TestProxyEgressObserverCapturesHost(t *testing.T) {
	prev := egressTransport
	t.Cleanup(func() { egressTransport = prev })

	egressTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	})

	var got struct {
		sandboxID, network, dest string
		n                        int
	}
	done := make(chan struct{}, 1)
	h := &Host{}
	h.SetEgressObserver(func(sandboxID, network, destination string) {
		got.sandboxID, got.network, got.dest = sandboxID, network, destination
		got.n++
		done <- struct{}{}
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com:8443/v1", nil)
	req.Host = "api.example.com:8443"
	rec := httptest.NewRecorder()
	h.proxyEgress(rec, req, "sb-obs", mustPolicy(t, EgressPolicy{}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("observer not called")
	}
	if got.n != 1 || got.sandboxID != "sb-obs" || got.network != "tcp" || got.dest != "api.example.com:8443" {
		t.Fatalf("observer got %+v", got)
	}

	// Policy deny must not observe.
	got.n = 0
	rec = httptest.NewRecorder()
	h.proxyEgress(rec, httptest.NewRequest(http.MethodGet, "http://other.example/", nil), "sb-obs",
		mustPolicy(t, EgressPolicy{Allow: []string{"only.example"}}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("deny status = %d", rec.Code)
	}
	time.Sleep(20 * time.Millisecond)
	if got.n != 0 {
		t.Fatalf("observer fired on deny: %+v", got)
	}
}

// TestServeEgressSlotFailsClosed proves the per-slot handler denies when the
// slot has no attributed owner (a teardown race) or the owner has no registered
// policy — the socket, not a header, is the attribution.
func TestServeEgressSlotFailsClosed(t *testing.T) {
	h := &Host{idBySlot: []string{""}, egressPolicy: map[string]*egresspolicy.Policy{}}
	// Slot 0 has no owner → forbidden.
	rec := httptest.NewRecorder()
	h.serveEgressSlot(0, rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unowned slot = %d, want 403", rec.Code)
	}
	// Owner present but no policy registered → forbidden (fail-closed).
	h.idBySlot[0] = "sb-x"
	rec = httptest.NewRecorder()
	h.serveEgressSlot(0, rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("owner without policy = %d, want 403 (fail-closed)", rec.Code)
	}
}

// TestProxyEgressDenialsExplainAndReport (P1-13, P1-7): every 403 names the
// destination and why, and every denial for an attributed sandbox reaches
// the denial observer with the shared reason.
func TestProxyEgressDenialsExplainAndReport(t *testing.T) {
	prev := egressTransport
	t.Cleanup(func() { egressTransport = prev })
	egressTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Err: egresspolicy.ErrDialRefused}
	})
	type denial struct{ id, dest, reason string }
	var got []denial
	h := &Host{}
	h.SetEgressDenialObserver(func(id, dest, reason string) { got = append(got, denial{id, dest, reason}) })
	cases := []struct {
		url    string
		p      EgressPolicy
		reason string
		body   string
	}{
		{"http://other.example/x", EgressPolicy{Allow: []string{"only.example"}}, DenyReasonHostNotAllowed, "host other.example not allowed (no rule matches)"},
		{"http://198.51.100.7/x", EgressPolicy{Deny: []string{"198.51.100.0/24"}}, DenyReasonIPNotAllowed, "not allowed (rule 198.51.100.0/24)"},
		{"http://169.254.169.254/x", EgressPolicy{}, DenyReasonBlockedIP, "is a blocked address"},
		{"http://rebind.example/x", EgressPolicy{}, DenyReasonBlockedIP, "resolves to a blocked address"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.proxyEgress(rec, httptest.NewRequest(http.MethodGet, tc.url, nil), "sb-x", mustPolicy(t, tc.p))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), tc.body) || !strings.HasPrefix(rec.Body.String(), "aerolvm egress policy:") {
			t.Fatalf("%s: %d %q, want 403 containing %q", tc.url, rec.Code, rec.Body.String(), tc.body)
		}
		if last := got[len(got)-1]; last.id != "sb-x" || last.reason != tc.reason {
			t.Fatalf("%s: observed %+v, want reason %s", tc.url, last, tc.reason)
		}
	}
	// An unattributed request (empty id) still gets the 403 but no audit.
	n := len(got)
	rec := httptest.NewRecorder()
	h.proxyEgress(rec, httptest.NewRequest(http.MethodGet, "http://other.example/", nil), "", mustPolicy(t, EgressPolicy{Allow: []string{"only.example"}}))
	if rec.Code != http.StatusForbidden || len(got) != n {
		t.Fatal("an unattributed denial must not be reported")
	}
	(*Host)(nil).SetEgressDenialObserver(nil)
}
