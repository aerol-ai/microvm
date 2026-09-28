package caddy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// fullCaddy is a fake admin API over a whole config tree (the emulator's
// semantics), counting /load calls separately from per-object writes. Each
// write, and each load, is a full reload in real Caddy.
type fullCaddy struct {
	mu     sync.Mutex
	emu    *configEmulator
	loads  int
	writes int
}

func newFullCaddy(t *testing.T, cfg string) (*fullCaddy, *Client) {
	t.Helper()
	var root any
	if err := json.Unmarshal([]byte(cfg), &root); err != nil {
		t.Fatal(err)
	}
	f := &fullCaddy{emu: newConfigEmulator(root)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/load" {
			var next any
			if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f.loads++
			f.emu = newConfigEmulator(next)
			return
		}
		if r.Method != http.MethodGet {
			f.writes++
		}
		resp, _ := f.emu.RoundTrip(r)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	c := New(config.Config{EnableCaddy: true, CaddyAdminURL: srv.URL, CaddyServerID: "srv0", Domain: "d.test", L4TLSListen: ":443", L4TLSFallback: "127.0.0.1:8443", HTTPClientTimeout: 5 * time.Second})
	return f, c
}

func (f *fullCaddy) counts() (loads, writes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loads, f.writes
}

func (f *fullCaddy) ids(t *testing.T, path string) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := lookup(f.emu.root, splitPath(path))
	if !ok {
		return nil
	}
	var out []string
	for _, r := range v.([]any) {
		id, _ := r.(map[string]any)["@id"].(string)
		out = append(out, id)
	}
	return out
}

const dynamicConfig = `{"apps":{
 "http":{"servers":{"srv0":{"routes":[
   {"@id":"sandbox-a","match":[{"host":["a.d.test"]}]},
   {"@id":"sandbox-a-port-8080","match":[{"host":["a-8080.d.test"]}]},
   {"@id":"sandbox-b-port-3000-wake","match":[{"host":["b-3000.d.test"]}]},
   {"@id":"api","match":[{"host":["d.test"]}]},
   {"handle":[{"handler":"static_response","body":"Sandbox not found"}]}
 ]}}},
 "layer4":{"servers":{
   "tls-mux":{"listen":[":443"],"routes":[
     {"@id":"sandbox-a-port-5432-tls","match":[{"tls":{"sni":["a-5432.d.test"]}}]},
     {"@id":"sandbox-c-ingress-sni","match":[{"tls":{"sni":["c.d.test"]}}]},
     {"@id":"sandbox-c-port-80-ingress-sni","match":[{"tls":{"sni":["c-80.d.test"]}}]},
     {"handle":[{"handler":"proxy","upstreams":[{"dial":["127.0.0.1:8443"]}]}]}
   ]},
   "tcp-port-22001":{"listen":[":22001"]},
   "tcp-port-22002":{"listen":[":22002"]}
 }}}}`

// Flag on: static installs plus the prune are ONE reload, and nothing else
// reaches Caddy.
func TestBatchFlagOnIsOneLoad(t *testing.T) {
	f, c := newFullCaddy(t, dynamicConfig)
	ctx := context.Background()
	var removed int
	err := c.Batch(ctx, func() error {
		if err := c.EnsureStaticSandboxRoute(ctx, testSpec); err != nil {
			return err
		}
		if err := c.EnsureStaticIngressRoutes(ctx, testSpec); err != nil {
			return err
		}
		var err error
		removed, err = c.PruneDynamicRoutes(ctx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if loads, writes := f.counts(); loads != 1 || writes != 0 {
		t.Fatalf("loads=%d writes=%d, want exactly one load and no other write", loads, writes)
	}
	if removed != 7 {
		t.Fatalf("removed %d, want 3 http + 2 ingress-sni + 2 tcp servers", removed)
	}
	if got := strings.Join(f.ids(t, "/apps/http/servers/srv0/routes"), ","); got != "api,"+StaticSandboxRouteID+"," {
		t.Fatalf("http routes = %q: want the apex, then the static route, then the catch-all", got)
	}
	want := StaticLoopbackRouteID + "," + StaticApexSNIRouteID + "," + StaticSNIRouteID + ",sandbox-a-port-5432-tls,"
	if got := strings.Join(f.ids(t, "/apps/layer4/servers/tls-mux/routes"), ","); got != want {
		t.Fatalf("tls-mux = %q, want %q (owner tls routes stay, ingress-sni go)", got, want)
	}
	f.mu.Lock()
	servers, _ := lookup(f.emu.root, splitPath("/apps/layer4/servers"))
	f.mu.Unlock()
	for name := range servers.(map[string]any) {
		if strings.HasPrefix(name, "tcp-port-") {
			t.Fatalf("tcp server %s survived the prune", name)
		}
	}

	// Snapshot never reports static routes, so reconcile GC can't sweep them.
	snap, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range append(snap.HTTPRouteIDs, snap.L4TLSRouteIDs...) {
		if IsStaticRouteID(id) {
			t.Fatalf("snapshot reports static route %s", id)
		}
	}

	// Re-running is idempotent and costs no reload at all.
	if err := c.Batch(ctx, func() error {
		_ = c.EnsureStaticSandboxRoute(ctx, testSpec)
		_ = c.EnsureStaticIngressRoutes(ctx, testSpec)
		_, err := c.PruneDynamicRoutes(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if loads, writes := f.counts(); loads != 1 || writes != 0 {
		t.Fatalf("idempotent re-run: loads=%d writes=%d, want still 1/0", loads, writes)
	}
}

// Flag off: removing the static routes and re-asserting N per-sandbox routes
// is one reload too.
func TestBatchFlagOffReinstallIsOneLoad(t *testing.T) {
	f, c := newFullCaddy(t, `{"apps":{"http":{"servers":{"srv0":{"routes":[{"@id":"api","match":[{"host":["d.test"]}]},{"handle":[]}]}}},"layer4":{"servers":{"tls-mux":{"routes":[{"handle":[]}]}}}}}`)
	ctx := context.Background()
	if err := c.Batch(ctx, func() error {
		_ = c.EnsureStaticSandboxRoute(ctx, testSpec)
		return c.EnsureStaticIngressRoutes(ctx, testSpec)
	}); err != nil {
		t.Fatal(err)
	}
	err := c.Batch(ctx, func() error {
		if err := c.RemoveStaticRoutes(ctx); err != nil {
			return err
		}
		for _, id := range []string{"s1", "s2", "s3"} {
			if err := c.UpsertSandboxRoute(ctx, id, "10.0.0.2", 2280, nil); err != nil {
				return err
			}
			if err := c.UpsertPortRoute(ctx, id, "10.0.0.2", 8080); err != nil {
				return err
			}
		}
		return c.UpsertTCPRoute(ctx, "s1", "10.0.0.2", 5432, 22010)
	})
	if err != nil {
		t.Fatal(err)
	}
	if loads, writes := f.counts(); loads != 2 || writes != 0 {
		t.Fatalf("loads=%d writes=%d, want one load per batch and no other write", loads, writes)
	}
	ids := f.ids(t, "/apps/http/servers/srv0/routes")
	if len(ids) != 8 {
		t.Fatalf("http routes after reinstall = %v, want 6 sandbox routes + apex + catch-all", ids)
	}
	for _, id := range ids {
		if IsStaticRouteID(id) {
			t.Fatalf("static route %s survived flag-off", id)
		}
	}
	if got := f.ids(t, "/apps/layer4/servers/tls-mux/routes"); len(got) != 1 {
		t.Fatalf("tls-mux after flag-off = %v, want only the fallback", got)
	}
}

func TestBatchAbortAndNoopLoadNothing(t *testing.T) {
	f, c := newFullCaddy(t, dynamicConfig)
	ctx := context.Background()
	boom := errors.New("boom")
	if err := c.Batch(ctx, func() error {
		_, _ = c.PruneDynamicRoutes(ctx)
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want fn's error", err)
	}
	if err := c.Batch(ctx, func() error { _, err := c.Snapshot(ctx); return err }); err != nil {
		t.Fatal(err)
	}
	if loads, writes := f.counts(); loads != 0 || writes != 0 {
		t.Fatalf("aborted/read-only batches: loads=%d writes=%d", loads, writes)
	}
	if got := f.ids(t, "/apps/http/servers/srv0/routes"); len(got) != 5 {
		t.Fatalf("an aborted batch changed Caddy: %v", got)
	}
}

// Another goroutine's write during the window lands in the batch, not
// straight in Caddy, where the load would silently overwrite it.
func TestBatchCapturesConcurrentWriters(t *testing.T) {
	f, c := newFullCaddy(t, dynamicConfig)
	ctx := context.Background()
	inside := make(chan struct{})
	done := make(chan error, 1)
	err := c.Batch(ctx, func() error {
		go func() {
			<-inside
			done <- c.UpsertSandboxRoute(ctx, "late", "10.0.0.9", 2280, nil)
		}()
		close(inside)
		if err := <-done; err != nil {
			return err
		}
		_, err := c.PruneDynamicRoutes(ctx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if loads, writes := f.counts(); loads != 1 || writes != 0 {
		t.Fatalf("loads=%d writes=%d", loads, writes)
	}
	for _, id := range f.ids(t, "/apps/http/servers/srv0/routes") {
		if id == "sandbox-late" {
			t.Fatal("the concurrent write escaped the batch's prune")
		}
	}

	// After the batch, writes go to Caddy again.
	if err := c.UpsertSandboxRoute(ctx, "after", "10.0.0.9", 2280, nil); err != nil {
		t.Fatal(err)
	}
	if _, writes := f.counts(); writes == 0 {
		t.Fatal("write after the batch did not reach Caddy")
	}
}

func TestBatchDisabledRunsFnOnly(t *testing.T) {
	c := New(config.Config{EnableCaddy: false})
	ran := false
	if err := c.Batch(context.Background(), func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
}

func TestBatchLoadAndFetchErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/config/" && r.Header.Get("X-Fail") == "":
			_, _ = w.Write([]byte(`{"apps":{}}`))
		case r.URL.Path == "/load":
			http.Error(w, `{"error":"bad config"}`, http.StatusBadRequest)
		default:
			http.Error(w, "no", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	c := New(config.Config{EnableCaddy: true, CaddyAdminURL: srv.URL, CaddyServerID: "srv0", Domain: "d.test", HTTPClientTimeout: time.Second})
	ctx := context.Background()
	err := c.Batch(ctx, func() error { return c.UpsertSandboxRoute(ctx, "x", "10.0.0.2", 2280, nil) })
	if err == nil || !strings.Contains(err.Error(), "bad config") {
		t.Fatalf("err = %v, want the load failure with Caddy's detail", err)
	}

	dead := New(config.Config{EnableCaddy: true, CaddyAdminURL: "http://127.0.0.1:1", HTTPClientTimeout: time.Second})
	if err := dead.Batch(ctx, func() error { t.Fatal("fn ran without a base config"); return nil }); err == nil {
		t.Fatal("want fetch error")
	}
}

func TestConfigEmulatorSemantics(t *testing.T) {
	var root any
	_ = json.Unmarshal([]byte(`{"a":{"list":[{"@id":"x","v":1},{"v":2}],"k":1}}`), &root)
	e := newConfigEmulator(root)
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/config/a/list/0/v", "", 200},
		{"GET", "/config/a/nope", "", 404},
		{"GET", "/config/a/list/9", "", 404},
		{"GET", "/id/missing", "", 404},
		{"GET", "/id/x/v", "", 200},
		{"PUT", "/config/a/k", `2`, 409},
		{"PUT", "/config/a/new", `3`, 200},
		{"PUT", "/config/a/list/9", `{}`, 400},
		{"PUT", "/config/a/list/x", `{}`, 400},
		{"PUT", "/config/a/list/0", `{"@id":"x"}`, 400}, // duplicate @id, rolled back
		{"PUT", "/config/a/list/0", `{"@id":"y"}`, 200},
		{"POST", "/config/a/list", `{"@id":"z"}`, 200},
		{"POST", "/config/a/list/1", `{"@id":"x2"}`, 200},
		{"POST", "/config/a/list/99", `{}`, 404},
		{"POST", "/config/b/c/d", `{"deep":true}`, 200},
		{"PATCH", "/id/y", `{"@id":"y","v":9}`, 200},
		{"PATCH", "/config/a/missing", `1`, 404},
		{"PATCH", "/config/a/list/99", `1`, 404},
		{"DELETE", "/id/z", "", 200},
		{"DELETE", "/config/a/list/99", "", 404},
		{"DELETE", "/config/a/missing", "", 404},
		{"DELETE", "/config/zz/yy", "", 404},
		{"GET", "/config/a/k/deeper", "", 404},
		{"PUT", "/config/a/k/deeper", `1`, 400},
		{"PUT", "/config/a", `{"bad":`, 400},
		{"HEAD", "/config/a/k", "", 405},
		{"HEAD", "/config/a/list/0", "", 405},
		{"GET", "/elsewhere", "", 404},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, "http://caddy"+tc.path, strings.NewReader(tc.body))
		resp, err := e.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != tc.want {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("%s %s = %d (%s), want %d", tc.method, tc.path, resp.StatusCode, raw, tc.want)
		}
	}
	list, _ := lookup(e.root, splitPath("/a/list"))
	var ids []string
	for _, r := range list.([]any) {
		id, _ := r.(map[string]any)["@id"].(string)
		ids = append(ids, id)
	}
	if got := strings.Join(ids, ","); got != "y,x2," {
		t.Fatalf("list ids = %q", got)
	}
	if !e.changed() {
		t.Fatal("changed() = false after writes")
	}
	// Whole-config writes.
	for _, m := range []string{"DELETE", "POST"} {
		req := httptest.NewRequest(m, "http://caddy/config/", strings.NewReader(`{"fresh":1}`))
		if resp, _ := e.RoundTrip(req); resp.StatusCode != 200 {
			t.Fatalf("%s /config/ = %d", m, resp.StatusCode)
		}
	}
	if err := setAt(&e.root, []string{"fresh", "x"}, 1); err == nil {
		t.Fatal("setAt through a scalar: want error")
	}
	var nilRoot any
	if err := setAt(&nilRoot, []string{"a", "b"}, 1); err != nil {
		t.Fatal(err)
	}
	arrRoot := any([]any{map[string]any{}})
	if err := setAt(&arrRoot, []string{"0", "k"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := setAt(&arrRoot, []string{"0"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := setAt(&arrRoot, []string{"7"}, 2); err == nil {
		t.Fatal("setAt out of range: want error")
	}
}
