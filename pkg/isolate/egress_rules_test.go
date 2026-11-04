package isolate

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TestProxyEgressRules (P3-1, EF-52 on isolate): the host sees every request
// in plaintext, so method and path rules apply without TLS termination.
func TestProxyEgressRules(t *testing.T) {
	old := egressTransport
	t.Cleanup(func() { egressTransport = old })
	egressTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	h, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t), EgressPoolSize: 1, Logger: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	h.SetEgressPolicy("sb-r", EgressPolicy{Allow: []string{"api.example.com", "other.example.com"}, Rules: []egresspolicy.RuleSpec{
		{Host: "api.example.com", Inspect: true, Methods: []string{"GET"}, Paths: []string{"/repos/acme/*"}},
	}})
	pol := mustPolicy(t, EgressPolicy{Allow: []string{"api.example.com", "other.example.com"}})
	var denials []string
	h.SetEgressDenialObserver(func(_, _, reason string) { denials = append(denials, reason) })
	for _, tc := range []struct {
		method, url string
		want        int
		reason      string
	}{
		{http.MethodGet, "https://api.example.com/repos/acme/widget", http.StatusOK, ""},
		{http.MethodPost, "https://api.example.com/repos/acme/widget", http.StatusForbidden, DenyReasonRuleDenied},
		{http.MethodGet, "https://api.example.com/repos/acme/../../admin", http.StatusForbidden, DenyReasonPathNotCanonical},
		{http.MethodDelete, "https://other.example.com/anything", http.StatusOK, ""},
	} {
		denials = nil
		rec := httptest.NewRecorder()
		h.proxyEgress(rec, httptest.NewRequest(tc.method, tc.url, nil), "sb-r", pol)
		if rec.Code != tc.want || (tc.reason != "" && (len(denials) != 1 || denials[0] != tc.reason)) {
			t.Fatalf("%s %s = %d %q, denials %v", tc.method, tc.url, rec.Code, rec.Body.String(), denials)
		}
	}
	// Credential injection (P3-2): the header is replaced on the way out,
	// and a missing value refuses the request.
	var sent http.Header
	egressTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent = r.Header.Clone()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	inject := egresspolicy.RuleSpec{Host: "api.example.com", Inspect: true, Inject: &egresspolicy.InjectSpec{Header: "Authorization", SecretRef: "env:TOKEN"}}
	h.SetEgressPolicy("sb-i", EgressPolicy{Allow: []string{"api.example.com"}, Rules: []egresspolicy.RuleSpec{inject}, Secrets: map[string]string{"TOKEN": "Bearer real"}})
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	req.Header.Set("Authorization", "Bearer aerolvm-placeholder:TOKEN")
	rec := httptest.NewRecorder()
	h.proxyEgress(rec, req, "sb-i", mustPolicy(t, EgressPolicy{Allow: []string{"api.example.com"}}))
	if rec.Code != 200 || sent.Get("Authorization") != "Bearer real" || len(sent.Values("Authorization")) != 1 {
		t.Fatalf("injected = %d %v", rec.Code, sent)
	}
	h.SetEgressPolicy("sb-i", EgressPolicy{Allow: []string{"api.example.com"}, Rules: []egresspolicy.RuleSpec{inject}})
	denials = nil
	rec = httptest.NewRecorder()
	h.proxyEgress(rec, httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil), "sb-i", mustPolicy(t, EgressPolicy{Allow: []string{"api.example.com"}}))
	if rec.Code != http.StatusForbidden || len(denials) != 1 || denials[0] != DenyReasonSecretMissing {
		t.Fatalf("missing secret = %d %v", rec.Code, denials)
	}

	// A rule set that doesn't compile fails the sandbox closed.
	h.SetEgressPolicy("sb-bad", EgressPolicy{Allow: []string{"api.example.com"}, Rules: []egresspolicy.RuleSpec{{Host: "api.example.com", Ports: []uint16{22}}}})
	h.mu.RLock()
	blocked := h.egressPolicy["sb-bad"].BlockAll()
	h.mu.RUnlock()
	if !blocked {
		t.Fatal("bad rules must block the sandbox")
	}
	if h.Unload("sb-r"); h.egressRules["sb-r"] != nil {
		t.Fatal("unload must drop the rules")
	}
}
