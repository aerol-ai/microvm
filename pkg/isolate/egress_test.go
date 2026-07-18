package isolate

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEgressAllowedAndHostMatches(t *testing.T) {
	tests := []struct {
		name string
		p    EgressPolicy
		host string
		want bool
	}{
		{"block-all denies", EgressPolicy{BlockAll: true}, "api.example.com", false},
		{"empty allow = allow all", EgressPolicy{}, "api.example.com", true},
		{"deny wins over empty allow", EgressPolicy{Deny: []string{"evil.com"}}, "evil.com", false},
		{"exact allow match", EgressPolicy{Allow: []string{"api.example.com"}}, "api.example.com", true},
		{"allow miss", EgressPolicy{Allow: []string{"api.example.com"}}, "other.com", false},
		{"suffix wildcard", EgressPolicy{Allow: []string{".example.com"}}, "a.b.example.com", true},
		{"suffix wildcard non-match", EgressPolicy{Allow: []string{".example.com"}}, "example.org", false},
		{"deny precedence over allow", EgressPolicy{Allow: []string{".example.com"}, Deny: []string{"bad.example.com"}}, "bad.example.com", false},
		{"cidr in-range", EgressPolicy{Allow: []string{"203.0.113.0/24"}}, "203.0.113.7", true},
		{"cidr out-of-range", EgressPolicy{Allow: []string{"203.0.113.0/24"}}, "198.51.100.7", false},
		{"case-insensitive host", EgressPolicy{Allow: []string{"api.example.com"}}, "API.Example.COM", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := egressAllowed(tc.p, tc.host); got != tc.want {
				t.Fatalf("egressAllowed(%+v, %q) = %v, want %v", tc.p, tc.host, got, tc.want)
			}
		})
	}
}

func TestIsBlockedEgressIP(t *testing.T) {
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
		if ip := net.ParseIP(s); ip == nil || !isBlockedEgressIP(ip) {
			t.Errorf("isBlockedEgressIP(%s) = false, want true (must be blocked)", s)
		}
	}
	allowed := []string{"8.8.8.8", "203.0.113.10", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if ip := net.ParseIP(s); ip == nil || isBlockedEgressIP(ip) {
			t.Errorf("isBlockedEgressIP(%s) = true, want false (public address)", s)
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
		h.proxyEgress(rec, req, EgressPolicy{}) // allow-all policy
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
	h.proxyEgress(rec, req, EgressPolicy{Allow: []string{"only.example"}})
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
	h.proxyEgress(rec, req, EgressPolicy{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-host = %d, want 403", rec.Code)
	}
}

// TestServeEgressSlotFailsClosed proves the per-slot handler denies when the
// slot has no attributed owner (a teardown race) or the owner has no registered
// policy — the socket, not a header, is the attribution.
func TestServeEgressSlotFailsClosed(t *testing.T) {
	h := &Host{idBySlot: []string{""}, egressPolicy: map[string]EgressPolicy{}}
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
