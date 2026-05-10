package service

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

// TestEnsureLayer4ReadyRetriesAfterBootFailure exercises the lazy bootstrap
// guarantee: a failing boot-time call must NOT permanently disable L4
// exposures. The first call fails (caddy unreachable), the second succeeds,
// and steady-state calls go through the atomic fast path without hitting
// caddy.
func TestEnsureLayer4ReadyRetriesAfterBootFailure(t *testing.T) {
	var (
		failNext atomic.Bool
		hits     atomic.Int32
	)
	failNext.Store(true)

	mux := http.NewServeMux()
	// pathExists probe + (when missing) the PUT to create the layer4 app.
	mux.HandleFunc("/config/apps/layer4", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if failNext.Load() {
			http.Error(w, "boot race: caddy not ready", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			// Simulate a fresh caddy with no layer4 yet so EnsureLayer4 issues
			// the follow-up PUT below.
			http.Error(w, "not found", http.StatusNotFound)
		case http.MethodPut:
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected method %s on %s", r.Method, r.URL.Path)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	caddyClient := caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddyClient,
	}

	ctx := context.Background()
	if err := svc.EnsureLayer4Ready(ctx); err == nil {
		t.Fatal("first EnsureLayer4Ready should have failed (caddy unavailable)")
	}
	if svc.l4Ready.Load() {
		t.Fatal("ready latch must stay false after a failed bootstrap")
	}

	// Caddy comes up — the next call must succeed and latch.
	failNext.Store(false)
	if err := svc.EnsureLayer4Ready(ctx); err != nil {
		t.Fatalf("retry after caddy recovered: %v", err)
	}
	if !svc.l4Ready.Load() {
		t.Fatal("ready latch must be true after successful bootstrap")
	}

	hitsAfterReady := hits.Load()
	for i := 0; i < 5; i++ {
		if err := svc.EnsureLayer4Ready(ctx); err != nil {
			t.Fatalf("steady-state call %d: %v", i, err)
		}
	}
	if got := hits.Load(); got != hitsAfterReady {
		t.Fatalf("steady-state calls hit caddy %d extra times; expected fast-path skip", got-hitsAfterReady)
	}
}

// TestEnsureLayer4ReadyDisabledCaddyLatchesImmediately verifies that an
// operator who runs sandboxd without caddy doesn't pay the bootstrap cost
// per L4 expose. caddy.Client short-circuits when disabled, returning nil.
func TestEnsureLayer4ReadyDisabledCaddyLatchesImmediately(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	caddyClient := caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		EnableCaddy:       false,
		HTTPClientTimeout: time.Second,
	})
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddyClient,
	}
	if err := svc.EnsureLayer4Ready(context.Background()); err != nil {
		t.Fatalf("EnsureLayer4Ready with disabled caddy: %v", err)
	}
	if called {
		t.Fatal("disabled caddy must not contact admin API at all")
	}
	if !svc.l4Ready.Load() {
		t.Fatal("disabled caddy still latches ready (no work to redo)")
	}
}
