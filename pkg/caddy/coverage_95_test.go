package caddy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestL4RouteSliceAndTLSMuxHelpers(t *testing.T) {
	if got := l4RouteSlice(nil); got != nil {
		t.Fatalf("nil = %v", got)
	}
	if got := l4RouteSlice("bad"); got != nil {
		t.Fatalf("bad type = %v", got)
	}

	asAny := []any{map[string]any{"@id": "r1"}}
	if len(l4RouteSlice(asAny)) != 1 {
		t.Fatal("[]any branch")
	}
	asMap := []map[string]any{{"@id": "r2"}}
	if len(l4RouteSlice(asMap)) != 1 {
		t.Fatal("[]map branch")
	}

	if !isTLSMuxFallbackRoute(map[string]any{"@id": tlsFallbackRouteID}) {
		t.Fatal("id match")
	}
	if !isTLSMuxFallbackRoute(map[string]any{"handle": []any{}}) {
		t.Fatal("no-match clause")
	}
	if isTLSMuxFallbackRoute(map[string]any{"match": []any{}}) {
		t.Fatal("matched route should not be fallback")
	}

	server := map[string]any{
		"listen": []string{":8443"},
		"routes": []map[string]any{
			{"@id": tlsFallbackRouteID, "handle": []any{}},
			{"match": []any{map[string]any{
				"tls": map[string]any{"sni": []string{"x"}},
			}}},
		},
	}
	updated, changed := ensureTLSMuxFallback(server, ":443", "127.0.0.1:8443")
	if !changed {
		t.Fatal("expected server mutation")
	}
	listen, _ := updated["listen"].([]string)
	if len(listen) != 1 || listen[0] != ":443" {
		t.Fatalf("listen = %v", updated["listen"])
	}
}

func TestGetConfigMapAndPathExists(t *testing.T) {
	ctx := context.Background()

	t.Run("not-found", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if _, ok, err := c.getConfigMap(ctx, "/missing"); err != nil || ok {
			t.Fatalf("getConfigMap = ok=%v err=%v", ok, err)
		}
		if exists, err := c.pathExists(ctx, "/missing"); err != nil || exists {
			t.Fatalf("pathExists = %v, %v", exists, err)
		}
	})

	t.Run("null-body", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("null"))
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if _, ok, err := c.getConfigMap(ctx, "/null"); err != nil || ok {
			t.Fatalf("getConfigMap null = ok=%v err=%v", ok, err)
		}
		if exists, err := c.pathExists(ctx, "/null"); err != nil || exists {
			t.Fatalf("pathExists null = %v, %v", exists, err)
		}
	})

	t.Run("bad-json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json"))
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if _, _, err := c.getConfigMap(ctx, "/bad"); err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("server-error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if _, _, err := c.getConfigMap(ctx, "/err"); err == nil {
			t.Fatal("expected status error")
		}
		if _, err := c.pathExists(ctx, "/err"); err == nil {
			t.Fatal("expected pathExists status error")
		}
	})
}

func TestHasOnDemandPolicyBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("not-found", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		ok, err := c.hasOnDemandPolicy(ctx)
		if err != nil || ok {
			t.Fatalf("hasOnDemandPolicy = %v, %v", ok, err)
		}
	})

	t.Run("null-body", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("null"))
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		ok, err := c.hasOnDemandPolicy(ctx)
		if err != nil || ok {
			t.Fatalf("hasOnDemandPolicy null = %v, %v", ok, err)
		}
	})

	t.Run("existing-policy", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{"on_demand": true}})
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		ok, err := c.hasOnDemandPolicy(ctx)
		if err != nil || !ok {
			t.Fatalf("hasOnDemandPolicy existing = %v, %v", ok, err)
		}
	})

	t.Run("no-on-demand-entry", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{"issuers": []any{}}})
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		ok, err := c.hasOnDemandPolicy(ctx)
		if err != nil || ok {
			t.Fatalf("hasOnDemandPolicy absent = %v, %v", ok, err)
		}
	})

	t.Run("bad-json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{")
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if _, err := c.hasOnDemandPolicy(ctx); err == nil {
			t.Fatal("expected decode error")
		}
	})
}

func TestEnsureLayer4UpdatesExistingMuxServer(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	fake.layer4Exists = true
	fake.l4Servers[tlsMuxServerID] = map[string]any{
		"listen": []string{":8443"},
		"routes": []map[string]any{
			{"@id": tlsFallbackRouteID, "handle": []any{map[string]any{"handler": "proxy"}}},
		},
	}
	client := &Client{enabled: true, serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
	if err := client.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err != nil {
		t.Fatalf("EnsureLayer4: %v", err)
	}
	server := fake.l4Servers[tlsMuxServerID]
	switch listen := server["listen"].(type) {
	case []string:
		if len(listen) != 1 || listen[0] != ":443" {
			t.Fatalf("listen not updated: %v", listen)
		}
	case []any:
		if len(listen) != 1 || listen[0] != ":443" {
			t.Fatalf("listen not updated: %v", listen)
		}
	default:
		t.Fatalf("unexpected listen type %T: %v", server["listen"], server["listen"])
	}
}

func TestEnsureLayer4SkipsWhenMuxAlreadyCurrent(t *testing.T) {
	ctx := context.Background()
	fallback := tlsMuxFallbackRoute("127.0.0.1:8443")
	fake := newFakeCaddy(t)
	fake.layer4Exists = true
	fake.l4Servers[tlsMuxServerID] = map[string]any{
		"listen": []string{":443"},
		"routes": []any{fallback},
	}
	client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
	before := len(fake.records)
	if err := client.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err != nil {
		t.Fatalf("EnsureLayer4: %v", err)
	}
	for _, rec := range fake.records[before:] {
		if strings.Contains(rec.Path, tlsMuxServerID) && rec.Method != http.MethodGet {
			t.Fatalf("unexpected mux mutation: %+v", rec)
		}
	}
}

func TestPingNetworkError(t *testing.T) {
	c := &Client{
		enabled:    true,
		baseURL:    "http://127.0.0.1:1",
		httpClient: &http.Client{Timeout: 50 * time.Millisecond},
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected ping error")
	}
}

func TestPingAdminErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected status error")
	}
}

func TestEnsureOnDemandTLSValidationAndDisabled(t *testing.T) {
	ctx := context.Background()
	disabled := &Client{enabled: false}
	if err := disabled.EnsureOnDemandTLS(ctx, "http://ask", 1, time.Minute); err != nil {
		t.Fatalf("disabled: %v", err)
	}
	enabled := &Client{enabled: true}
	for _, tc := range []struct {
		name     string
		ask      string
		burst    int
		interval time.Duration
	}{
		{name: "empty-ask", ask: "", burst: 1, interval: time.Minute},
		{name: "bad-burst", ask: "http://ask", burst: 0, interval: time.Minute},
		{name: "bad-interval", ask: "http://ask", burst: 1, interval: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := enabled.EnsureOnDemandTLS(ctx, tc.ask, tc.burst, tc.interval); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestEnsureOnDemandTLSFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("put-fails", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if err := c.EnsureOnDemandTLS(ctx, "http://ask", 1, time.Minute); err == nil {
			t.Fatal("expected PUT failure")
		}
	})

	t.Run("policy-post-fails", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPut:
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[]`))
			case r.Method == http.MethodPost:
				w.WriteHeader(http.StatusBadRequest)
			default:
				http.NotFound(w, r)
			}
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if err := c.EnsureOnDemandTLS(ctx, "http://ask", 1, time.Minute); err == nil {
			t.Fatal("expected POST failure")
		}
	})

	t.Run("skips-when-policy-present", func(t *testing.T) {
		var posted bool
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPut:
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]map[string]any{{"on_demand": true}})
			case r.Method == http.MethodPost:
				posted = true
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if err := c.EnsureOnDemandTLS(ctx, "http://ask", 1, time.Minute); err != nil {
			t.Fatalf("EnsureOnDemandTLS: %v", err)
		}
		if posted {
			t.Fatal("should not POST when policy already exists")
		}
	})
}

func TestHasOnDemandPolicyRequestErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("server-error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if _, err := c.hasOnDemandPolicy(ctx); err == nil {
			t.Fatal("expected status error")
		}
	})

	t.Run("read-body-error", func(t *testing.T) {
		c := &Client{
			enabled: true,
			baseURL: "http://example.test",
			httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       errReadCloser{err: io.ErrUnexpectedEOF},
					Header:     make(http.Header),
				}, nil
			})},
		}
		if _, err := c.hasOnDemandPolicy(ctx); err == nil {
			t.Fatal("expected read error")
		}
	})
}

func TestEnsureLayer4ErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("empty-tls-listen", func(t *testing.T) {
		fake := newFakeCaddy(t)
		c := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
		if err := c.EnsureLayer4(ctx, "", ""); err != nil {
			t.Fatalf("empty tls listen: %v", err)
		}
	})

	t.Run("create-layer4-fails", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if err := c.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err == nil {
			t.Fatal("expected layer4 create failure")
		}
	})

	t.Run("mux-update-fails", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/config/apps/layer4":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"servers": map[string]any{}})
			case r.Method == http.MethodGet && strings.Contains(r.URL.Path, tlsMuxServerID):
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"listen": []string{":8443"},
					"routes": []map[string]any{{"@id": "other"}},
				})
			case r.Method == http.MethodPost && strings.Contains(r.URL.Path, tlsMuxServerID):
				w.WriteHeader(http.StatusInternalServerError)
			default:
				http.NotFound(w, r)
			}
		}))
		defer ts.Close()
		c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
		if err := c.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err == nil {
			t.Fatal("expected mux update failure")
		}
	})
}

func TestPathExistsAndGetConfigMapReadErrors(t *testing.T) {
	ctx := context.Background()
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errReadCloser{err: io.ErrUnexpectedEOF},
			Header:     make(http.Header),
		}, nil
	})
	c := &Client{
		enabled:    true,
		baseURL:    "http://example.test",
		httpClient: &http.Client{Transport: rt},
	}
	if _, err := c.pathExists(ctx, "/config/apps/layer4"); err == nil {
		t.Fatal("expected pathExists read error")
	}
	if _, _, err := c.getConfigMap(ctx, "/config/apps/layer4/servers/mux"); err == nil {
		t.Fatal("expected getConfigMap read error")
	}
}

func TestUpsertRouteErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("patch-non-404", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		c := &Client{enabled: true, serverID: "srv0", baseURL: ts.URL, httpClient: ts.Client()}
		if err := c.upsertRoute(ctx, "rt-err", map[string]any{"@id": "rt-err"}); err == nil {
			t.Fatal("expected patch failure")
		}
	})

	t.Run("insert-after-404-fails", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPatch:
				w.WriteHeader(http.StatusNotFound)
			case http.MethodPut:
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer ts.Close()
		c := &Client{enabled: true, serverID: "srv0", baseURL: ts.URL, httpClient: ts.Client()}
		if err := c.upsertRoute(ctx, "rt-new", map[string]any{"@id": "rt-new"}); err == nil {
			t.Fatal("expected insert failure")
		}
	})
}

func TestUpsertSandboxRouteCustomDomains(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	c := &Client{
		enabled:    true,
		domain:     "sandbox.example.com",
		serverID:   "srv0",
		baseURL:    fake.URL,
		httpClient: fake.Client,
	}
	customs := []CustomHostnameRoute{
		{Hostname: "API.Custom.example.com", TargetPort: 3000, MaskRequestHost: "api"},
		{Hostname: "  ", TargetPort: 0},
	}
	if err := c.UpsertSandboxRoute(ctx, "sb-1", "10.0.0.5", 8080, customs); err != nil {
		t.Fatalf("UpsertSandboxRoute: %v", err)
	}
}

func TestDeleteHelpersNetworkAndStatusErrors(t *testing.T) {
	ctx := context.Background()
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	baseURL := closed.URL
	closed.Close()
	c := &Client{enabled: true, serverID: "srv0", baseURL: baseURL, httpClient: closed.Client()}
	if err := c.DeleteRouteByID(ctx, "rt-1"); err == nil {
		t.Fatal("expected delete route network error")
	}
	if err := c.DeleteTCPServer(ctx, "tcp-port-1"); err == nil {
		t.Fatal("expected delete tcp server network error")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c = &Client{enabled: true, serverID: "srv0", baseURL: ts.URL, httpClient: ts.Client()}
	if err := c.DeleteRouteByID(ctx, "rt-1"); err == nil {
		t.Fatal("expected delete route status error")
	}
	if err := c.DeleteTCPServer(ctx, "tcp-port-1"); err == nil {
		t.Fatal("expected delete tcp server status error")
	}
	if err := c.DeleteTCPRoute(ctx, 1234); err == nil {
		t.Fatal("expected delete tcp route status error")
	}
}

func TestSnapshotErrors(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if _, err := c.Snapshot(ctx); err == nil {
		t.Fatal("expected snapshot error")
	}
}

func TestSendJSONAndUpsertNetworkErrors(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	baseURL := srv.URL
	srv.Close()
	c := &Client{
		enabled:    true,
		domain:     "sandbox.example.com",
		serverID:   "srv0",
		baseURL:    baseURL,
		httpClient: srv.Client(),
	}
	if err := c.EnsureOnDemandTLS(ctx, "http://ask", 1, time.Minute); err == nil {
		t.Fatal("EnsureOnDemandTLS network error")
	}
	if err := c.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err == nil {
		t.Fatal("EnsureLayer4 network error")
	}
	if err := c.UpsertTCPRoute(ctx, "sb", "10.0.0.1", 8080, 1234); err == nil {
		t.Fatal("UpsertTCPRoute network error")
	}
	if err := c.UpsertWakeTCPRoute(ctx, "sb", 8080, 1234, "127.0.0.1:9090"); err == nil {
		t.Fatal("UpsertWakeTCPRoute network error")
	}
	if err := c.UpsertTCPProxyRoute(ctx, "sb", 8080, 1234, "10.0.0.1", 8080); err == nil {
		t.Fatal("UpsertTCPProxyRoute network error")
	}
	if err := c.UpsertTLSSNIRoute(ctx, "sb", "sni.host", "10.0.0.1", 443); err == nil {
		t.Fatal("UpsertTLSSNIRoute network error")
	}
	if err := c.UpsertWakeTLSSNIRoute(ctx, "sb", "sni.host", "/tmp/sock", 443); err == nil {
		t.Fatal("UpsertWakeTLSSNIRoute network error")
	}
	if err := c.UpsertSNIPassthroughRoute(ctx, "sb", "sni.host", "peer.host", 443); err == nil {
		t.Fatal("UpsertSNIPassthroughRoute network error")
	}
}

func TestUpsertPortRouteWithRetryZeroDuration(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	c := &Client{
		enabled:    true,
		domain:     "sandbox.example.com",
		serverID:   "srv0",
		baseURL:    fake.URL,
		httpClient: fake.Client,
	}
	if err := c.UpsertPortRouteWithRetry(ctx, "sb", "10.0.0.1", 8080, 0); err != nil {
		t.Fatalf("UpsertPortRouteWithRetry(0): %v", err)
	}
}

func TestUpsertSandboxRouteCustomDomainError(t *testing.T) {
	ctx := context.Background()
	var patchCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			patchCalls++
			if patchCalls >= 2 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			http.NotFound(w, r)
		case http.MethodPut:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	c := &Client{
		enabled:    true,
		domain:     "sandbox.example.com",
		serverID:   "srv0",
		baseURL:    ts.URL,
		httpClient: ts.Client(),
	}
	err := c.UpsertSandboxRoute(ctx, "sb", "10.0.0.1", 8080, []CustomHostnameRoute{{Hostname: "api.example.com"}})
	if err == nil || !strings.Contains(err.Error(), "install custom-domain route") {
		t.Fatalf("UpsertSandboxRoute custom domain err = %v", err)
	}
}

func TestConfigHelpersRequestErrors(t *testing.T) {
	ctx := context.Background()
	bad := &Client{enabled: true, baseURL: "://bad", httpClient: http.DefaultClient}
	if _, err := bad.pathExists(ctx, "/config"); err == nil {
		t.Fatal("pathExists request error")
	}
	if _, _, err := bad.getConfigMap(ctx, "/config"); err == nil {
		t.Fatal("getConfigMap request error")
	}
	if err := bad.DeleteRouteByID(ctx, "rt"); err == nil {
		t.Fatal("deleteRoute request error")
	}
	if err := bad.DeleteTCPServer(ctx, "tcp-port-1"); err == nil {
		t.Fatal("DeleteTCPServer request error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type errReadCloser struct{ err error }

func (e errReadCloser) Read([]byte) (int, error) { return 0, e.err }
func (e errReadCloser) Close() error             { return nil }

func TestEnsureOnDemandTLSInstallsPolicyWhenAbsent(t *testing.T) {
	ctx := context.Background()
	var posted bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/on_demand"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/policies"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/policies"):
			posted = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	client := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if err := client.EnsureOnDemandTLS(ctx, "http://ask", 5, time.Minute); err != nil {
		t.Fatalf("EnsureOnDemandTLS: %v", err)
	}
	if !posted {
		t.Fatal("expected on-demand policy POST")
	}
}

func TestCaddyClientErrorPaths(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	client := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client(), serverID: "srv0", domain: "sandbox.example.com"}

	calls := []struct {
		name string
		run  func() error
	}{
		{"Ping", func() error { return client.Ping(ctx) }},
		{"UpsertSandboxRoute", func() error { return client.UpsertSandboxRoute(ctx, "abc", "10.0.0.1", 8080, nil) }},
		{"UpsertPortRouteWithRetry", func() error {
			return client.UpsertPortRouteWithRetry(ctx, "abc", "10.0.0.1", 8080, time.Millisecond)
		}},
		{"UpsertTCPRoute", func() error { return client.UpsertTCPRoute(ctx, "abc", "10.0.0.1", 8080, 8080) }},
		{"UpsertWakeTCPRoute", func() error { return client.UpsertWakeTCPRoute(ctx, "abc", 8080, 8080, "127.0.0.1:1") }},
		{"UpsertTCPProxyRoute", func() error { return client.UpsertTCPProxyRoute(ctx, "abc", 8080, 8080, "10.0.0.1", 8080) }},
		{"DeleteTCPRoute", func() error { return client.DeleteTCPRoute(ctx, 8080) }},
		{"UpsertTLSSNIRoute", func() error { return client.UpsertTLSSNIRoute(ctx, "abc", "sni.host", "10.0.0.1", 443) }},
		{"UpsertWakeTLSSNIRoute", func() error { return client.UpsertWakeTLSSNIRoute(ctx, "abc", "sni.host", "/tmp/s", 443) }},
		{"UpsertSNIPassthroughRoute", func() error { return client.UpsertSNIPassthroughRoute(ctx, "abc", "sni.host", "peer", 443) }},
		{"Snapshot", func() error { _, err := client.Snapshot(ctx); return err }},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
		})
	}
}

func TestCaddySNIRoutesAgainstFake(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	fake.layer4Exists = true
	fake.l4Servers[tlsMuxServerID] = map[string]any{
		"listen": []string{":443"},
		"routes": []any{},
	}
	client := &Client{enabled: true, serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}

	if err := client.UpsertTLSSNIRoute(ctx, "abc", "abc.sandbox.example.com", "10.0.0.1", 443); err != nil {
		t.Fatalf("UpsertTLSSNIRoute: %v", err)
	}
	if err := client.UpsertWakeTLSSNIRoute(ctx, "abc", "abc.sandbox.example.com", "127.0.0.1:8443", 443); err != nil {
		t.Fatalf("UpsertWakeTLSSNIRoute: %v", err)
	}
	if err := client.UpsertSNIPassthroughRoute(ctx, "abc", "passthrough.example.com", "peer.internal", 443); err != nil {
		t.Fatalf("UpsertSNIPassthroughRoute: %v", err)
	}
	if err := client.DeleteTLSSNIRoute(ctx, "abc", 443); err != nil {
		t.Fatalf("DeleteTLSSNIRoute: %v", err)
	}
}

func TestEnsureLayer4CreatesAppAndMux(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
	if err := client.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err != nil {
		t.Fatalf("EnsureLayer4 fresh: %v", err)
	}
	if !fake.layer4Exists {
		t.Fatal("layer4 app should exist")
	}
	if _, ok := fake.l4Servers[tlsMuxServerID]; !ok {
		t.Fatal("tls-mux server should be created")
	}
}

func TestHasOnDemandPolicyHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if _, err := c.hasOnDemandPolicy(context.Background()); err == nil {
		t.Fatal("expected policies fetch error")
	}
}

func TestPathExistsReadBodyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if _, err := c.pathExists(context.Background(), "/config/apps/layer4"); err == nil {
		t.Fatal("expected read body error")
	}
}

func TestGetConfigMapReadBodyError(t *testing.T) {
	c := &Client{
		enabled: true,
		baseURL: "http://example.test",
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errReadCloser{err: io.ErrUnexpectedEOF},
				Header:     make(http.Header),
			}, nil
		})},
	}
	if _, _, err := c.getConfigMap(context.Background(), "/x"); err == nil {
		t.Fatal("expected read error")
	}
}

func TestEnsureOnDemandTLSSkipsPolicyWhenPresent(t *testing.T) {
	ctx := context.Background()
	var posted bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/on_demand"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/policies"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{"on_demand": true}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/policies"):
			posted = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if err := c.EnsureOnDemandTLS(ctx, "http://ask", 5, time.Minute); err != nil {
		t.Fatalf("EnsureOnDemandTLS: %v", err)
	}
	if posted {
		t.Fatal("should not POST when policy already present")
	}
}

func TestUpsertPortRouteWithDialAgainstFake(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	c := &Client{enabled: true, serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client, domain: "sandbox.example.com"}
	if err := c.UpsertPortRouteWithDial(ctx, "abc", 8080, "10.0.0.1:8080"); err != nil {
		t.Fatalf("UpsertPortRouteWithDial: %v", err)
	}
}

func TestDeletePortRouteAgainstFake(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	c := &Client{enabled: true, serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client, domain: "sandbox.example.com"}
	if err := c.UpsertPortRouteWithDial(ctx, "abc", 8080, "10.0.0.1:8080"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := c.DeletePortRoute(ctx, "abc", 8080); err != nil {
		t.Fatalf("DeletePortRoute: %v", err)
	}
	if err := c.DeleteWakeHTTPPortRoute(ctx, "abc", 8080); err != nil {
		t.Fatalf("DeleteWakeHTTPPortRoute: %v", err)
	}
}

func TestUpsertSNIPassthroughRouteInsertThenPatch(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	fake.layer4Exists = true
	fake.l4Servers[tlsMuxServerID] = map[string]any{"listen": []string{":443"}, "routes": []any{}}
	c := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
	routeID := IngressCustomDomainSNIRouteID("abc", "peer.example.com")

	if err := c.UpsertSNIPassthroughRoute(ctx, routeID, "peer.example.com", "10.0.0.2", 443); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := c.UpsertSNIPassthroughRoute(ctx, routeID, "peer.example.com", "10.0.0.3", 443); err != nil {
		t.Fatalf("patch: %v", err)
	}
}

func TestUpsertTLSSNIRouteInsertThenPatch(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	fake.layer4Exists = true
	fake.l4Servers[tlsMuxServerID] = map[string]any{"listen": []string{":443"}, "routes": []any{}}
	c := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}

	if err := c.UpsertTLSSNIRoute(ctx, "abc", "abc.sandbox.example.com", "10.0.0.1", 443); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := c.UpsertTLSSNIRoute(ctx, "abc", "abc.sandbox.example.com", "10.0.0.2", 443); err != nil {
		t.Fatalf("patch: %v", err)
	}
}

func TestEnsureLayer4PutLayer4AppError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/layer4" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/config/apps/layer4" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if err := c.EnsureLayer4(context.Background(), "", ""); err == nil {
		t.Fatal("expected layer4 create error")
	}
}

func TestEnsureOnDemandTLSPolicyPostError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/on_demand"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/policies"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/policies"):
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if err := c.EnsureOnDemandTLS(context.Background(), "http://ask", 5, time.Minute); err == nil {
		t.Fatal("expected policy post error")
	}
}

func TestEnsureOnDemandTLSPolicyLookupFailure(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if err := c.EnsureOnDemandTLS(ctx, "http://ask", 1, time.Minute); err == nil {
		t.Fatal("expected policy lookup failure")
	}
}

func TestUpsertRouteInsertNetworkError(t *testing.T) {
	ctx := context.Background()
	c := &Client{
		enabled:  true,
		serverID: "srv0",
		baseURL:  "http://example.test",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodPatch {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			}
			return nil, io.ErrClosedPipe
		})},
	}
	if err := c.upsertRoute(ctx, "rt-new", map[string]any{"@id": "rt-new"}); err == nil {
		t.Fatal("expected insert network error")
	}
}

func TestEnsureLayer4MuxConfigLookupFailure(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config/apps/layer4":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"servers":{}}`))
		default:
			if strings.Contains(r.URL.Path, tlsMuxServerID) {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	c := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}
	if err := c.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err == nil {
		t.Fatal("expected mux config lookup failure")
	}
}

func TestGetConfigMapNetworkError(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	c := &Client{enabled: true, baseURL: url, httpClient: srv.Client()}
	if _, _, err := c.getConfigMap(ctx, "/config/apps/layer4"); err == nil {
		t.Fatal("expected getConfigMap network error")
	}
}

func TestSnapshotNetworkError(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	c := &Client{enabled: true, baseURL: url, httpClient: srv.Client()}
	if _, err := c.Snapshot(ctx); err == nil {
		t.Fatal("expected snapshot network error")
	}
}

func TestDeleteTCPRouteNetworkError(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	c := &Client{enabled: true, baseURL: url, httpClient: srv.Client()}
	if err := c.DeleteTCPRoute(ctx, 1234); err == nil {
		t.Fatal("expected delete tcp route network error")
	}
}

func TestHasOnDemandPolicyNetworkError(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	c := &Client{enabled: true, baseURL: url, httpClient: srv.Client()}
	if _, err := c.hasOnDemandPolicy(ctx); err == nil {
		t.Fatal("expected hasOnDemandPolicy network error")
	}
}
