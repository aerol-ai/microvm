package caddy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// ingressRootConfig is an ingress node's config before any sandbox route: the
// Caddyfile's wildcard catch-all and a tls-mux holding only its fallback.
const ingressRootConfig = `{"apps":{
 "http":{"servers":{"srv0":{"routes":[
  {"match":[{"host":["*.d.test"]}],"handle":[{"handler":"static_response","body":"Sandbox not found"}]}]}}},
 "layer4":{"servers":{"tls-mux":{"listen":[":443"],"routes":[
  {"@id":"tls-mux-fallback","handle":[{"handler":"proxy","upstreams":[{"dial":["127.0.0.1:8443"]}]}]}]}}}}}`

// overlapCaddy is a fake admin API over the emulator's config tree that does
// NOT serialize requests itself, so overlapping writes from the client are
// observable: every config write sleeps for delay while counted in flight.
// Like real Caddy, it applies the writes to one config (the emulator's own
// mutex keeps the tree consistent).
type overlapCaddy struct {
	emu       *configEmulator
	delay     time.Duration
	inFlight  atomic.Int32
	peak      atomic.Int32
	writes    atomic.Int32
	conns     atomic.Int32
	intercept func(w http.ResponseWriter, r *http.Request) bool
}

func newOverlapCaddy(t *testing.T, delay time.Duration) (*overlapCaddy, *Client) {
	t.Helper()
	var root any
	if err := json.Unmarshal([]byte(ingressRootConfig), &root); err != nil {
		t.Fatal(err)
	}
	f := &overlapCaddy{emu: newConfigEmulator(root), delay: delay}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			f.conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	c := New(config.Config{
		EnableCaddy: true, CaddyAdminURL: srv.URL, CaddyServerID: "srv0", Domain: "d.test",
		L4TLSListen: ":443", L4TLSFallback: "127.0.0.1:8443", HTTPClientTimeout: 5 * time.Second,
	})
	return f, c
}

func (f *overlapCaddy) serve(w http.ResponseWriter, r *http.Request) {
	if f.intercept != nil && f.intercept(w, r) {
		return
	}
	if mutatesConfig(r.Method) {
		n := f.inFlight.Add(1)
		defer f.inFlight.Add(-1)
		for {
			p := f.peak.Load()
			if n <= p || f.peak.CompareAndSwap(p, n) {
				break
			}
		}
		f.writes.Add(1)
		time.Sleep(f.delay)
	}
	if r.URL.Path == "/load" {
		var next any
		if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.emu.mu.Lock()
		f.emu.root = next
		f.emu.mu.Unlock()
		return
	}
	resp, _ := f.emu.RoundTrip(r)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (f *overlapCaddy) tlsMuxIDs(t *testing.T) []string {
	t.Helper()
	f.emu.mu.Lock()
	defer f.emu.mu.Unlock()
	routes, _ := lookup(f.emu.root, []string{"apps", "layer4", "servers", "tls-mux", "routes"})
	var ids []string
	for _, r := range routes.([]any) {
		id, _ := r.(map[string]any)["@id"].(string)
		ids = append(ids, id)
	}
	return ids
}

func countID(ids []string, id string) int {
	n := 0
	for _, got := range ids {
		if got == id {
			n++
		}
	}
	return n
}

// Every writer in the process shares one client, so the client is where
// overlapping admin writes are stopped. Before the admin lock, the ingress
// reconciler's 8 workers, lifecycle route writes and the L4 bootstrap all
// wrote concurrently; each write restarts Caddy's admin endpoint and the
// writes racing it failed with EOF (cluster-hetero ingress-1, 2026-10-04).
func TestAdminWritesNeverOverlap(t *testing.T) {
	f, c := newOverlapCaddy(t, 2*time.Millisecond)
	ctx := context.Background()

	const workers = 12
	var wg sync.WaitGroup
	errs := make(chan error, workers*8)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sb := fmt.Sprintf("sb-%02d", i)
			sni := IngressPortSNIRouteID(sb, 8080)
			for _, op := range []func() error{
				func() error { return c.UpsertSNIPassthroughRoute(ctx, sni, sb+"-8080.d.test", "10.0.0.9", 443) },
				func() error { return c.UpsertPortRoute(ctx, sb, "10.1.0.2", 8080) },
				func() error { return c.EnsureLayer4(ctx, ":443", "127.0.0.1:8443") },
				// Repeat: the second upsert must PATCH, not insert a copy.
				func() error { return c.UpsertSNIPassthroughRoute(ctx, sni, sb+"-8080.d.test", "10.0.0.9", 443) },
				func() error { return c.DeleteRouteByID(ctx, PortRouteID(sb, 8080)) },
			} {
				if err := op(); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("admin call: %v", err)
	}

	if got := f.peak.Load(); got != 1 {
		t.Fatalf("peak concurrent admin writes = %d, want 1", got)
	}
	ids := f.tlsMuxIDs(t)
	for i := range workers {
		id := IngressPortSNIRouteID(fmt.Sprintf("sb-%02d", i), 8080)
		if n := countID(ids, id); n != 1 {
			t.Fatalf("tls-mux holds %d copies of %s, want 1 (routes: %v)", n, id, ids)
		}
	}
	if ids[len(ids)-1] != tlsFallbackRouteID {
		t.Fatalf("fallback is not last: %v", ids)
	}
}

// Reads cause no reload and stay concurrent: a slow write must not hold up
// a Snapshot.
func TestAdminReadsAreNotSerialized(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	f, c := newOverlapCaddy(t, 0)
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPatch {
			close(started)
			<-release
		}
		return false
	}
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- c.UpsertPortRoute(ctx, "sb", "10.1.0.2", 8080) }()

	<-started // the write now holds the admin lock
	if _, err := c.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot while a write is in flight: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("upsert: %v", err)
	}
}

// Caddy answers a write and then shuts the admin server that served it down
// in the background, closing its idle connections. A pooled connection
// handed to the next write fails with a bare EOF before Caddy sees it, and Go
// does not retry PATCH/PUT/DELETE. Every admin request therefore dials a
// connection of its own.
func TestAdminRequestsNeverReuseAConnection(t *testing.T) {
	f, c := newOverlapCaddy(t, 0)
	ctx := context.Background()
	const writes, reads = 10, 5
	for i := range writes {
		if err := c.UpsertSNIPassthroughRoute(ctx, fmt.Sprintf("sandbox-s%d-ingress-sni", i), fmt.Sprintf("s%d.d.test", i), "10.0.0.9", 443); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	for i := range reads {
		if _, err := c.Snapshot(ctx); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	// Each upsert is a PATCH (404) plus a PUT: two requests.
	if got, want := f.conns.Load(), int32(2*writes+reads); got != want {
		t.Fatalf("admin requests used %d connections, want %d (one per request)", got, want)
	}
}

// Caddy rebuilds its @id index on every load, and /id/<id> can answer 404
// while the route IS in the config. The insert then fails with "duplicate
// ID"; that proves the route exists, so the tls-mux upsert PATCHes it
// instead of failing (upsertRoute already did this for HTTP routes).
func TestUpsertTLSMuxRouteDuplicateIDFallsBackToPatch(t *testing.T) {
	const id = "sandbox-sb-ingress-sni"
	for _, tc := range []struct {
		name       string
		retryPatch int // status of the PATCH after the duplicate-ID insert
		wantErr    bool
	}{
		{"patch after duplicate succeeds", http.StatusOK, false},
		{"patch after duplicate fails", http.StatusInternalServerError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, c := newOverlapCaddy(t, 0)
			ctx := context.Background()
			if err := c.UpsertSNIPassthroughRoute(ctx, id, "sb.d.test", "10.0.0.1", 443); err != nil {
				t.Fatalf("seed: %v", err)
			}
			var patches atomic.Int32
			f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodPatch {
					return false
				}
				switch patches.Add(1) {
				case 1: // the index-rebuild window
					http.Error(w, `{"error":"unknown object ID"}`, http.StatusNotFound)
					return true
				case 2:
					if tc.retryPatch != http.StatusOK {
						http.Error(w, `{"error":"boom"}`, tc.retryPatch)
						return true
					}
				}
				return false
			}
			err := c.UpsertSNIPassthroughRoute(ctx, id, "sb.d.test", "10.0.0.2", 443)
			if (err != nil) != tc.wantErr {
				t.Fatalf("upsert err = %v, wantErr %v", err, tc.wantErr)
			}
			if n := countID(f.tlsMuxIDs(t), id); n != 1 {
				t.Fatalf("tls-mux holds %d copies of %s, want 1", n, id)
			}
		})
	}
}

// Batch takes the admin lock to open and to commit (its /load is a write),
// in the same order as do(): direct writers running alongside batches never
// overlap a load, never deadlock, and never lose a write.
func TestBatchAndDirectWritesShareTheAdminLock(t *testing.T) {
	f, c := newOverlapCaddy(t, time.Millisecond)
	ctx := context.Background()

	stop := make(chan struct{})
	var direct sync.WaitGroup
	var written []string
	var mu sync.Mutex
	for w := range 4 {
		direct.Add(1)
		go func() {
			defer direct.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				id := fmt.Sprintf("sandbox-w%d-%d-ingress-sni", w, i)
				if err := c.UpsertSNIPassthroughRoute(ctx, id, fmt.Sprintf("w%d-%d.d.test", w, i), "10.0.0.9", 443); err != nil {
					t.Errorf("direct write: %v", err)
					return
				}
				mu.Lock()
				written = append(written, id)
				mu.Unlock()
			}
		}()
	}
	for b := range 5 {
		id := fmt.Sprintf("sandbox-batch%d-ingress-sni", b)
		if err := c.Batch(ctx, func() error {
			return c.UpsertSNIPassthroughRoute(ctx, id, fmt.Sprintf("batch%d.d.test", b), "10.0.0.9", 443)
		}); err != nil {
			t.Fatalf("batch %d: %v", b, err)
		}
		mu.Lock()
		written = append(written, id)
		mu.Unlock()
	}
	close(stop)
	direct.Wait()

	if got := f.peak.Load(); got != 1 {
		t.Fatalf("peak concurrent admin writes = %d, want 1", got)
	}
	ids := f.tlsMuxIDs(t)
	for _, id := range written {
		if n := countID(ids, id); n != 1 {
			t.Fatalf("tls-mux holds %d copies of %s, want 1", n, id)
		}
	}
}

func TestWithAdminLockNests(t *testing.T) {
	c := New(config.Config{EnableCaddy: true})
	done := make(chan error, 1)
	go func() {
		done <- c.withAdminLock(context.Background(), func(ctx context.Context) error {
			return c.withAdminLock(ctx, func(ctx context.Context) error {
				if !holdsAdminLock(ctx) {
					return errors.New("inner context lost the lock marker")
				}
				return nil
			})
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nested withAdminLock deadlocked")
	}
	if holdsAdminLock(context.Background()) {
		t.Fatal("a fresh context must not claim the lock")
	}
}

func TestMutatesConfig(t *testing.T) {
	for method, want := range map[string]bool{
		http.MethodGet: false, http.MethodHead: false, http.MethodOptions: false,
		http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	} {
		if got := mutatesConfig(method); got != want {
			t.Errorf("mutatesConfig(%s) = %v, want %v", method, got, want)
		}
	}
}

func TestIsTransientAdminError(t *testing.T) {
	urlErr := &url.Error{Op: "Put", URL: "http://127.0.0.1:2019/config/", Err: io.EOF}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"EOF from the transport", urlErr, true},
		{"wrapped by a helper", fmt.Errorf("delete caddy route: %w", urlErr), true},
		{"connection refused", &url.Error{Op: "Get", URL: "x", Err: errors.New("connect: connection refused")}, true},
		{"caller cancelled", &url.Error{Op: "Get", URL: "x", Err: context.Canceled}, false},
		{"caddy answered with a status", caddyErr("insert caddy route", http.StatusBadRequest, "boom"), false},
		{"plain error", errors.New("route id required"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTransientAdminError(tc.err); got != tc.want {
				t.Fatalf("IsTransientAdminError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestNewAdminTransportDisablesKeepAlives(t *testing.T) {
	tr, ok := newAdminTransport().(*http.Transport)
	if !ok || !tr.DisableKeepAlives {
		t.Fatalf("admin transport = %#v, want an *http.Transport with keep-alives off", tr)
	}
	if tr == http.DefaultTransport {
		t.Fatal("admin transport must be a clone, not the process-wide default")
	}

	orig := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	defer func() { http.DefaultTransport = orig }()
	if tr, ok := newAdminTransport().(*http.Transport); !ok || !tr.DisableKeepAlives {
		t.Fatal("a replaced DefaultTransport must still yield a keep-alive-free transport")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A failed tls-mux upsert names the route and carries Caddy's explanation,
// so a reconcile WARN line ties the failure to a sandbox.
func TestUpsertTLSMuxRouteNamesTheRoute(t *testing.T) {
	f, c := newOverlapCaddy(t, 0)
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		http.Error(w, `{"error":"nope"}`, http.StatusInternalServerError)
		return true
	}
	err := c.UpsertSNIPassthroughRoute(context.Background(), "sandbox-x-ingress-sni", "x.d.test", "10.0.0.1", 443)
	if err == nil || !strings.Contains(err.Error(), "sandbox-x-ingress-sni") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v, want the route id and Caddy's explanation", err)
	}
}
