package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/api"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

type fakeIdentityRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeIdentityRecorder) RecordIdentityConfig(s identity.Summary) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, s.Hash)
	return true
}

func (f *fakeIdentityRecorder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

// wiringIdentityFile reads the issuer's keys from jwksPath, so the
// verifier's start-up fetch never reaches the network (the URL is never
// contacted).
func wiringIdentityFile(t *testing.T, displayName string) string {
	t.Helper()
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return "version: 1\nissuers:\n  - name: okta\n    display_name: " + displayName +
		"\n    url: https://acme.okta.com\n    jwks_file: " + jwksPath + "\n    audiences: [cli]\n    clients: {cli: cli}\n"
}

func discoveryOf(t *testing.T, s *api.Server) identitywire.AuthDiscovery {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, identitywire.AuthDiscoveryPath, nil))
	var doc identitywire.AuthDiscovery
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery %d %s", rec.Code, rec.Body.String())
	}
	return doc
}

// TestWireIdentityFile: identity off, or on without a file (tokens-only),
// wires nothing. With a file, the verifier joins the chain, discovery
// publishes the file's issuers, the boot file is handed to the
// identity_config recorder, and a SIGHUP reload shows at once.
func TestWireIdentityFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := &fakeIdentityRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if opts := wireIdentityFile(ctx, config.Config{IdentityFile: "/x"}, rec, logger); opts != nil {
		t.Fatal("identity off must wire nothing")
	}
	if opts := wireIdentityFile(ctx, config.Config{IdentityEnabled: true}, rec, logger); opts != nil {
		t.Fatal("tokens-only mode must wire nothing")
	}

	path := filepath.Join(t.TempDir(), "identity.yaml")
	if err := os.WriteFile(path, []byte(wiringIdentityFile(t, "Acme Okta")), 0o600); err != nil {
		t.Fatal(err)
	}
	// Our own SIGHUP registration first, so the signal sent below can
	// never fall through to the default action (exit).
	guard := make(chan os.Signal, 4)
	signal.Notify(guard, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(guard) })

	cfg := config.Config{IdentityEnabled: true, IdentityFile: path}
	opts := wireIdentityFile(ctx, cfg, rec, logger)
	if len(opts) != 2 {
		t.Fatalf("options = %d, want the verifier and discovery", len(opts))
	}
	server := api.NewServer(logger, nil, nil, nil, cfg, "pat-token", nil, opts...)
	doc := discoveryOf(t, server)
	if !doc.IdentityEnabled || len(doc.Issuers) != 1 || doc.Issuers[0].DisplayName != "Acme Okta" {
		t.Fatalf("discovery = %+v", doc)
	}
	deadline := time.Now().Add(5 * time.Second)
	for rec.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the boot file was never handed to the recorder")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := os.WriteFile(path, []byte(wiringIdentityFile(t, "Acme SSO")), 0o600); err != nil {
		t.Fatal(err)
	}
	for discoveryOf(t, server).Issuers[0].DisplayName != "Acme SSO" {
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP did not reload the identity file")
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(20 * time.Millisecond)
	}
	for rec.count() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the reload was never recorded")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestWireIdentityFileInvalidAtBoot: a broken file does not stop boot; the
// options are still wired (OIDC answers 503 until the file is fixed) and
// discovery lists no issuer.
func TestWireIdentityFileInvalidAtBoot(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	path := filepath.Join(t.TempDir(), "identity.yaml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{IdentityEnabled: true, IdentityFile: path}
	opts := wireIdentityFile(ctx, cfg, &fakeIdentityRecorder{}, logger)
	server := api.NewServer(logger, nil, nil, nil, cfg, "pat-token", nil, opts...)
	if doc := discoveryOf(t, server); len(doc.Issuers) != 0 {
		t.Fatalf("invalid file published issuers: %+v", doc)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer eyJh.eyJz.c2ln")
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("JWT with an invalid identity file = %d, want 503", rr.Code)
	}
}
