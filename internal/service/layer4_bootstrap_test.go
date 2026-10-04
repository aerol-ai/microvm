package service

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestRepairLayer4ReadyBypassesSuccessLatch(t *testing.T) {
	var repairPosts atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/config/apps/layer4", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s on %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"servers":{}}`)
	})
	mux.HandleFunc("/config/apps/layer4/servers/tls-mux", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"listen":[":443"],"routes":[{"@id":"sandbox-abc-ingress-sni","match":[{"tls":{"sni":["abc.sandbox.example.com"]}}],"handle":[{"handler":"proxy","upstreams":[{"dial":["10.0.0.9:443"]}]}]}]}`)
		case http.MethodPost:
			repairPosts.Add(1)
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
		HTTPClientTimeout: time.Second,
		L4TLSListen:       ":443",
		L4TLSFallback:     "127.0.0.1:8443",
	})
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddyClient,
		cfg: config.Config{
			L4TLSListen:   ":443",
			L4TLSFallback: "127.0.0.1:8443",
		},
	}
	svc.l4Ready.Store(true)

	if err := svc.RepairLayer4Ready(context.Background()); err != nil {
		t.Fatalf("RepairLayer4Ready: %v", err)
	}
	if got := repairPosts.Load(); got != 1 {
		t.Fatalf("repair posts = %d, want 1", got)
	}
	if !svc.l4Ready.Load() {
		t.Fatal("repair should keep the ready latch true after success")
	}
}

// EnsureLayer4 reads the tls-mux server and, when the fallback is missing or
// out of place, POSTs the whole server back. A route another goroutine
// inserted between that GET and that POST used to be overwritten: the ingress
// reconciler's repair and a lifecycle SNI write share one Caddy. The caddy
// client now holds its admin lock across EnsureLayer4's read-modify-write, so
// the concurrent insert waits for the POST and lands after it.
func TestRepairLayer4ReadyKeepsAConcurrentlyInsertedSNIRoute(t *testing.T) {
	const sniRoute = "sandbox-sb-late-ingress-sni"
	e := newEmulatedCaddy(t, 0)
	// tls-mux lost its fallback: the repair must rewrite the server.
	e.outOfBand(t, http.MethodPatch, "/config/apps/layer4/servers/tls-mux/routes", `[]`)

	svc := newLiveIngressService(t, e)
	ctx := context.Background()

	var (
		hooked    atomic.Bool
		arrived   = make(chan struct{})
		arriveOne sync.Once
		insertErr = make(chan error, 1)
	)
	e.setBefore(func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, sniRoute) || r.Method == http.MethodPut {
			arriveOne.Do(func() { close(arrived) })
			return false
		}
		if r.Method != http.MethodGet || r.URL.Path != "/config/apps/layer4/servers/tls-mux" || hooked.Swap(true) {
			return false
		}
		// Read the server as the repair sees it, then give a concurrent
		// lifecycle insert every chance to land before the repair writes.
		stale := httptest.NewRecorder()
		e.apply(stale, r)
		go func() {
			insertErr <- svc.caddy.UpsertSNIPassthroughRoute(ctx, sniRoute, "sb-late.d.test", "10.42.1.108", 443)
		}()
		select {
		case <-arrived:
		case <-time.After(300 * time.Millisecond):
		}
		w.WriteHeader(stale.Code)
		_, _ = w.Write(stale.Body.Bytes())
		return true
	})

	if err := svc.RepairLayer4Ready(ctx); err != nil {
		t.Fatalf("RepairLayer4Ready: %v", err)
	}
	if err := <-insertErr; err != nil {
		t.Fatalf("concurrent SNI insert: %v", err)
	}
	ids := e.tlsMuxRouteIDs(t)
	requireRouteOnce(t, ids, sniRoute)
	if ids[len(ids)-1] != "tls-mux-fallback" {
		t.Fatalf("repair did not put the fallback last: %v", ids)
	}
	if !svc.l4Ready.Load() {
		t.Fatal("a successful repair keeps the ready latch true")
	}
}
