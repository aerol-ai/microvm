package identity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestDisplayNameClaim: the username claim names the caller when it is a
// printable string; otherwise the stable sub does.
func TestDisplayNameClaim(t *testing.T) {
	iss := &Issuer{UsernameClaim: "email"}
	cases := []struct {
		claims string
		want   string
	}{
		{`{"email":"ana@acme.com"}`, "ana@acme.com"},
		{`{"email":"\u0007\n"}`, "00u1"},
		{`{"email":42}`, "00u1"},
		{`{}`, "00u1"},
	}
	for _, tc := range cases {
		c := claimsFrom(t, tc.claims)
		c.sub = "00u1"
		if got := displayNameClaim(c, iss); got != tc.want {
			t.Errorf("displayNameClaim(%s) = %q, want %q", tc.claims, got, tc.want)
		}
	}
}

func TestDecodeUnverified(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	if _, _, ok := decodeUnverified("onlyone"); ok {
		t.Fatal("one segment is malformed")
	}
	if _, _, ok := decodeUnverified("!!!.x.y"); ok {
		t.Fatal("a header that is not base64url is malformed")
	}
	h, claims, ok := decodeUnverified(header + ".!!!.sig")
	if !ok || claims != nil || h.Alg != "RS256" {
		t.Fatalf("payload that is not base64url: ok %v claims %v alg %q", ok, claims, h.Alg)
	}
}

// TestFetchRemoteRefusals: discovery naming a non-https JWKS endpoint, and
// a JWKS endpoint answering something that is not a key set, both leave the
// issuer without keys (503), and the default transport is used when the
// configured client has none.
func TestFetchRemoteRefusals(t *testing.T) {
	var mode atomic.Value
	mode.Store("http-jwks")
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			jwks := srv.URL + "/jwks"
			if mode.Load() == "http-jwks" {
				jwks = "http://insecure.example/jwks"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "jwks_uri": jwks})
		case "/jwks":
			_, _ = io.WriteString(w, "not json")
		}
	}))
	t.Cleanup(srv.Close)
	cfg, err := Parse([]byte(fmt.Sprintf("version: 1\nissuers:\n  - {name: t, url: %q, audiences: [a]}\n", srv.URL)))
	if err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock()
	v := NewVerifier(func() *Config { return cfg }, VerifierOptions{HTTPClient: srv.Client(), Now: clock.Now})
	st, _ := v.current()
	ks := st.issuers[cfg.Issuers[0]].keys
	waitIdle := func() error {
		clock.Advance(2 * DefaultRefetchGap)
		return ks.refresh(t.Context(), DefaultFetchTimeout)
	}
	if err := waitIdle(); err == nil {
		t.Fatal("an http jwks_uri must be refused")
	}
	mode.Store("bad-jwks")
	if err := waitIdle(); err == nil {
		t.Fatal("a JWKS that is not JSON must be refused")
	}
	if ks.ready.Load() {
		t.Fatal("no usable keys: the latch must stay unset")
	}

	// cappedClient falls back to the default transport.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(plain.Close)
	var over atomic.Bool
	resp, err := cappedClient(&http.Client{}, oversizeJWKS, &over).Get(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" || over.Load() {
		t.Fatalf("default transport: %q over %v", body, over.Load())
	}
}

func TestValidSlugAndStringClaim(t *testing.T) {
	for s, want := range map[string]bool{"okta": true, "": false, "a-1": true, "A": false, "x_y": false} {
		if validSlug(s, 63) != want {
			t.Errorf("validSlug(%q) != %v", s, want)
		}
	}
	if validSlug("abcd", 3) {
		t.Error("over the length cap")
	}
	if _, ok := stringClaim(json.RawMessage(`"unterminated`)); ok {
		t.Error("a broken string claim must not read")
	}
	if claimHas(json.RawMessage(`[1,`), "x") || claimHas(json.RawMessage(`{"a":`), "x") {
		t.Error("a broken claim must never match")
	}
	if (*Config)(nil).DiscoveryIssuers() != nil {
		t.Error("no file publishes no issuer")
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("loading a directory must fail")
	}
}
