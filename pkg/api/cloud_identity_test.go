package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func newIssuerServer(t *testing.T, issuer string, withCipher bool) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var cipher *secrets.Cipher
	if withCipher {
		if cipher, err = secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: bytes.Repeat([]byte{3}, 32), Current: true}}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{IdentityIssuerURL: issuer}
	svc := service.New(cfg, discardLogger(), st, nil, nil, nil, cipher, nil, nil)
	return NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil).Handler()
}

// Point 4: discovery and the JWKS are public (no credential), read-only, and
// hold public keys only.
func TestIssuerDocumentsArePublic(t *testing.T) {
	h := newIssuerServer(t, "https://api.example.com", true)
	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		return rr
	}
	rr := get(cloudidentity.DiscoveryPath)
	var doc map[string]any
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &doc) != nil || doc["jwks_uri"] != "https://api.example.com/.well-known/jwks.json" {
		t.Fatalf("discovery = %d %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != identityDocumentMaxAge || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", rr.Header())
	}
	rr = get(cloudidentity.JWKSPath)
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &jwks) != nil || len(jwks.Keys) != 1 {
		t.Fatalf("jwks = %d %s", rr.Code, rr.Body.String())
	}
	if _, private := jwks.Keys[0]["d"]; private {
		t.Fatal("the JWKS publishes a private exponent")
	}
	// Read-only: no other method is served.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(method, cloudidentity.JWKSPath, strings.NewReader("{}")))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s jwks = %d, want 405", method, rr.Code)
		}
	}
}

func TestIssuerDocumentsOffAndUnavailable(t *testing.T) {
	off := newIssuerServer(t, "", true)
	for _, path := range []string{cloudidentity.DiscoveryPath, cloudidentity.JWKSPath} {
		rr := httptest.NewRecorder()
		off.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s with identity off = %d, want 404", path, rr.Code)
		}
	}
	// No server key to seal a first key with: the JWKS says retry, and says
	// nothing about why.
	broken := newIssuerServer(t, "https://api.example.com", false)
	rr := httptest.NewRecorder()
	broken.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, cloudidentity.JWKSPath, nil))
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" || strings.Contains(rr.Body.String(), "server key") {
		t.Fatalf("unavailable jwks = %d %s", rr.Code, rr.Body.String())
	}
	if err := service.ErrIdentityDisabled; err == nil {
		t.Fatal("sentinel missing")
	}
}
