package isolate

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostMatchesEdges(t *testing.T) {
	if hostMatches("h", "") {
		t.Fatal("empty rule must not match")
	}
	if hostMatches("10.0.0.1", "not-a-cidr/") {
		t.Fatal("invalid CIDR must not match")
	}
	if hostMatches("10.0.0.1", "10.0.0.0/33") { // ParseCIDR rejects /33
		t.Fatal("bogus CIDR must not match")
	}
}

func TestEgressDialControl(t *testing.T) {
	if err := egressDialControl("tcp", "127.0.0.1:80", nil); err == nil {
		t.Fatal("loopback must be denied")
	}
	if err := egressDialControl("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatal("link-local must be denied")
	}
	if err := egressDialControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("public IP must be allowed: %v", err)
	}
	// No port → treat whole address as host.
	if err := egressDialControl("tcp", "10.0.0.1", nil); err == nil {
		t.Fatal("private IP without port must be denied")
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
	h.proxyEgress(rec, req, "sb-proxy", EgressPolicy{})
	if rec.Code != http.StatusTeapot || rec.Body.String() != "proxied" || rec.Header().Get("X-Up") != "1" {
		t.Fatalf("proxy success = %d %q hdr=%v", rec.Code, rec.Body.String(), rec.Header())
	}

	egressTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})
	rec = httptest.NewRecorder()
	h.proxyEgress(rec, httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil), "sb-proxy", EgressPolicy{})
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
