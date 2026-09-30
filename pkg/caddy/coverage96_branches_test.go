package caddy

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scriptedReply is one admin API answer: either a transport error or a
// status with a body.
type scriptedReply struct {
	status int
	body   string
	err    error
}

// scriptedClient builds a Client whose admin calls are answered by fn,
// keyed on "METHOD /path". It lets a test fail exactly one step of a
// multi-call helper (e.g. PATCH 404 then PUT transport error).
func scriptedClient(fn func(key string) scriptedReply) *Client {
	return &Client{
		enabled:     true,
		serverID:    "srv0",
		domain:      "d.test",
		l4TLSListen: ":443",
		baseURL:     "http://caddy.test",
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			rep := fn(r.Method + " " + r.URL.Path)
			if rep.err != nil {
				return nil, rep.err
			}
			return &http.Response{
				StatusCode: rep.status,
				Body:       io.NopCloser(strings.NewReader(rep.body)),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		})},
	}
}

func TestBatchFetchConfigFailures(t *testing.T) {
	ctx := context.Background()
	noop := func() error { t.Fatal("fn must not run when the config fetch fails"); return nil }

	t.Run("bad-url", func(t *testing.T) {
		c := &Client{enabled: true, baseURL: "http://bad\x7f", httpClient: http.DefaultClient}
		if err := c.Batch(ctx, noop); err == nil {
			t.Fatal("expected request build error")
		}
	})
	t.Run("transport-error", func(t *testing.T) {
		c := scriptedClient(func(string) scriptedReply { return scriptedReply{err: io.ErrClosedPipe} })
		if err := c.Batch(ctx, noop); err == nil || !strings.Contains(err.Error(), "get caddy config") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("status-500", func(t *testing.T) {
		c := scriptedClient(func(string) scriptedReply { return scriptedReply{status: 500} })
		if err := c.Batch(ctx, noop); err == nil || !strings.Contains(err.Error(), "failed: 500") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad-json", func(t *testing.T) {
		c := scriptedClient(func(string) scriptedReply { return scriptedReply{status: 200, body: "{not json"} })
		if err := c.Batch(ctx, noop); err == nil || !strings.Contains(err.Error(), "decode caddy config") {
			t.Fatalf("err = %v", err)
		}
	})
}

// A fresh Caddy answers GET /config/ with "null"; the batch must treat that
// as an empty object and still load what fn wrote.
func TestBatchNullConfigLoadsWrites(t *testing.T) {
	var loaded map[string]any
	c := &Client{enabled: true, baseURL: "http://caddy.test", httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := "null"
		if r.URL.Path == "/load" {
			_ = json.NewDecoder(r.Body).Decode(&loaded)
			body = ""
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}
	ctx := context.Background()
	err := c.Batch(ctx, func() error {
		return c.UpsertTCPRoute(ctx, "sb", "10.0.0.1", 22, 22001)
	})
	if err != nil {
		t.Fatalf("Batch: %v", err)
	}
	servers, _ := lookup(any(loaded), []string{"apps", "layer4", "servers", "tcp-port-22001"})
	if servers == nil {
		t.Fatalf("loaded config missing tcp server: %v", loaded)
	}
}

func TestBatchCommitFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("load-transport-error", func(t *testing.T) {
		c := scriptedClient(func(key string) scriptedReply {
			if key == "POST /load" {
				return scriptedReply{err: io.ErrClosedPipe}
			}
			return scriptedReply{status: 200, body: `{}`}
		})
		err := c.Batch(ctx, func() error { return c.UpsertTCPRoute(ctx, "sb", "10.0.0.1", 22, 22001) })
		if err == nil || !strings.Contains(err.Error(), "/load") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unmarshalable-config", func(t *testing.T) {
		c := scriptedClient(func(key string) scriptedReply {
			if key == "POST /load" {
				t.Fatal("nothing should be loaded when the config cannot be marshalled")
			}
			return scriptedReply{status: 200, body: `{}`}
		})
		err := c.Batch(ctx, func() error {
			c.batch.root.(map[string]any)["bad"] = math.NaN()
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "marshal batched caddy config") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSendDirectBadTarget(t *testing.T) {
	c := &Client{httpClient: http.DefaultClient}
	if _, _, err := c.sendDirect(context.Background(), http.MethodPost, "http://bad\x7f/load", nil); err == nil {
		t.Fatal("expected request build error")
	}
}

func TestConfigEmulatorEdgeCases(t *testing.T) {
	do := func(rt http.RoundTripper, method, path, body string) int {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rd)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp.StatusCode
	}

	t.Run("exported-constructor", func(t *testing.T) {
		rt := NewConfigEmulator(map[string]any{"a": 1.0})
		if got := do(rt, http.MethodGet, "/config/a", ""); got != 200 {
			t.Fatalf("GET = %d", got)
		}
	})

	t.Run("body-read-error", func(t *testing.T) {
		emu := newConfigEmulator(map[string]any{})
		req := httptest.NewRequest(http.MethodPost, "/config/a", nil)
		req.Body = errReadCloser{err: io.ErrUnexpectedEOF}
		if _, err := emu.RoundTrip(req); err == nil {
			t.Fatal("expected body read error")
		}
	})

	t.Run("patch-existing-key", func(t *testing.T) {
		emu := newConfigEmulator(map[string]any{"a": map[string]any{"b": 1.0}})
		if got := do(emu, http.MethodPatch, "/config/a/b", `2`); got != 200 {
			t.Fatalf("PATCH = %d", got)
		}
		if v, _ := lookup(emu.root, []string{"a", "b"}); v != 2.0 {
			t.Fatalf("a.b = %v", v)
		}
	})

	t.Run("nil-root-creates-parent", func(t *testing.T) {
		emu := newConfigEmulator(nil)
		if got := do(emu, http.MethodPost, "/config/apps", `{"x":1}`); got != 200 {
			t.Fatalf("POST = %d", got)
		}
		if v, ok := lookup(emu.root, []string{"apps", "x"}); !ok || v != 1.0 {
			t.Fatalf("apps.x = %v %v", v, ok)
		}
	})

	t.Run("missing-parent-through-scalar", func(t *testing.T) {
		emu := newConfigEmulator(map[string]any{"a": "scalar"})
		if got := do(emu, http.MethodPost, "/config/a/b/c", `1`); got != http.StatusBadRequest {
			t.Fatalf("POST through scalar = %d, want 400", got)
		}
	})
}

func TestEnsureStaticIngressRoutesPropagatesError(t *testing.T) {
	c := scriptedClient(func(string) scriptedReply { return scriptedReply{status: 500} })
	err := c.EnsureStaticIngressRoutes(context.Background(), testSpec)
	if err == nil || !strings.Contains(err.Error(), "patch static route") {
		t.Fatalf("err = %v", err)
	}
}

func TestRemoveStaticRoutesTransportError(t *testing.T) {
	c := scriptedClient(func(string) scriptedReply { return scriptedReply{err: io.ErrClosedPipe} })
	if err := c.RemoveStaticRoutes(context.Background()); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestEnsureRouteAtFailureSteps(t *testing.T) {
	ctx := context.Background()
	route := map[string]any{"@id": "static-x"}
	first := func([]map[string]any) int { return 0 }
	const routes = "/config/apps/http/servers/srv0/routes"

	cases := []struct {
		name    string
		reply   func(key string) scriptedReply
		wantErr string
	}{
		{"patch-transport", func(string) scriptedReply { return scriptedReply{err: io.ErrClosedPipe} }, "PATCH"},
		{"list-transport", func(key string) scriptedReply {
			if strings.HasPrefix(key, "PATCH") {
				return scriptedReply{status: 404}
			}
			return scriptedReply{err: io.ErrClosedPipe}
		}, "get " + routes},
		{"put-transport", func(key string) scriptedReply {
			switch {
			case strings.HasPrefix(key, "PATCH"):
				return scriptedReply{status: 404}
			case strings.HasPrefix(key, "GET"):
				return scriptedReply{status: 200, body: `[]`}
			}
			return scriptedReply{err: io.ErrClosedPipe}
		}, "PUT"},
		{"put-status", func(key string) scriptedReply {
			switch {
			case strings.HasPrefix(key, "PATCH"):
				return scriptedReply{status: 404}
			case strings.HasPrefix(key, "GET"):
				return scriptedReply{status: 200, body: `[]`}
			}
			return scriptedReply{status: 400, body: `{"error":"nope"}`}
		}, "insert static route static-x at 0 failed: 400"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := scriptedClient(tc.reply)
			err := c.ensureRouteAt(ctx, "static-x", routes, route, first)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("unmarshalable-route", func(t *testing.T) {
		c := scriptedClient(func(string) scriptedReply { t.Fatal("no request expected"); return scriptedReply{} })
		err := c.ensureRouteAt(ctx, "static-x", routes, map[string]any{"bad": math.Inf(1)}, first)
		if err == nil || !strings.Contains(err.Error(), "marshal static route") {
			t.Fatalf("err = %v", err)
		}
	})

	// A missing routes list (404) inserts at index 0.
	t.Run("list-404-inserts-at-zero", func(t *testing.T) {
		var putPath string
		c := scriptedClient(func(key string) scriptedReply {
			switch {
			case strings.HasPrefix(key, "PATCH"):
				return scriptedReply{status: 404}
			case strings.HasPrefix(key, "GET"):
				return scriptedReply{status: 404}
			}
			putPath = key
			return scriptedReply{status: 200}
		})
		if err := c.ensureRouteAt(ctx, "static-x", routes, route, func([]map[string]any) int { return 5 }); err != nil {
			t.Fatal(err)
		}
		if putPath != "PUT "+routes+"/0" {
			t.Fatalf("PUT = %q", putPath)
		}
	})
}

func TestGetRouteListResponses(t *testing.T) {
	ctx := context.Background()
	const path = "/config/apps/http/servers/srv0/routes"

	t.Run("bad-url", func(t *testing.T) {
		c := &Client{enabled: true, baseURL: "http://bad\x7f", httpClient: http.DefaultClient}
		if _, err := c.getRouteList(ctx, path); err == nil {
			t.Fatal("expected request build error")
		}
	})
	t.Run("null", func(t *testing.T) {
		c := scriptedClient(func(string) scriptedReply { return scriptedReply{status: 200, body: " null \n"} })
		routes, err := c.getRouteList(ctx, path)
		if err != nil || routes != nil {
			t.Fatalf("routes=%v err=%v", routes, err)
		}
	})
	t.Run("bad-json", func(t *testing.T) {
		c := scriptedClient(func(string) scriptedReply { return scriptedReply{status: 200, body: `{"not":"a list"}`} })
		if _, err := c.getRouteList(ctx, path); err == nil || !strings.Contains(err.Error(), "decode") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("read-error", func(t *testing.T) {
		c := &Client{enabled: true, baseURL: "http://caddy.test", httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: errReadCloser{err: io.ErrUnexpectedEOF}, Header: make(http.Header)}, nil
		})}}
		if _, err := c.getRouteList(ctx, path); err == nil || !strings.Contains(err.Error(), "read") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestPruneDynamicRoutesFailureSteps(t *testing.T) {
	ctx := context.Background()
	cfg := func(extra string) string {
		return `{"apps":{"http":{"servers":{"srv0":{"routes":[` + extra + `]}}},
		"layer4":{"servers":{
		  "tls-mux":{"routes":[{"@id":"sandbox-a-port-5432-tls"},{"@id":"sandbox-c-ingress-sni"}]},
		  "tcp-port-22001":{"routes":[]}}}}}`
	}

	t.Run("snapshot-error", func(t *testing.T) {
		c := scriptedClient(func(string) scriptedReply { return scriptedReply{status: 500} })
		if n, err := c.PruneDynamicRoutes(ctx); err == nil || n != 0 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	})

	cases := []struct {
		name      string
		httpRoute string
		failOn    string
		wantN     int
	}{
		{"http-route-delete", `{"@id":"sandbox-a"}`, "DELETE /id/sandbox-a", 0},
		{"ingress-sni-delete", ``, "DELETE /id/sandbox-c-ingress-sni", 0},
		{"tcp-server-delete", `{"@id":"sandbox-a"}`, "DELETE /config/apps/layer4/servers/tcp-port-22001", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var deleted []string
			c := scriptedClient(func(key string) scriptedReply {
				if key == "GET /config/" {
					return scriptedReply{status: 200, body: cfg(tc.httpRoute)}
				}
				if key == tc.failOn {
					return scriptedReply{status: 500}
				}
				deleted = append(deleted, key)
				return scriptedReply{status: 200}
			})
			n, err := c.PruneDynamicRoutes(ctx)
			if err == nil {
				t.Fatal("expected delete failure")
			}
			if n != tc.wantN {
				t.Fatalf("removed = %d, want %d (deleted %v)", n, tc.wantN, deleted)
			}
			for _, d := range deleted {
				if strings.Contains(d, "5432-tls") {
					t.Fatalf("owner tls route must survive a prune: %v", deleted)
				}
			}
		})
	}
}

func TestUpsertRouteEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("unmarshalable-route", func(t *testing.T) {
		c := scriptedClient(func(string) scriptedReply { t.Fatal("no request expected"); return scriptedReply{} })
		if err := c.upsertRoute(ctx, "rt", map[string]any{"bad": math.NaN()}); err == nil || !strings.Contains(err.Error(), "marshal caddy route") {
			t.Fatalf("err = %v", err)
		}
	})

	// PATCH 404 → PUT "duplicate ID" → re-PATCH; the retry's transport
	// error must surface rather than be swallowed.
	t.Run("duplicate-id-repatch-transport-error", func(t *testing.T) {
		patches := 0
		c := scriptedClient(func(key string) scriptedReply {
			switch {
			case strings.HasPrefix(key, "PATCH"):
				patches++
				if patches == 1 {
					return scriptedReply{status: 404}
				}
				return scriptedReply{err: io.ErrClosedPipe}
			case strings.HasPrefix(key, "PUT"):
				return scriptedReply{status: 400, body: `{"error":"duplicate ID 'rt' found"}`}
			}
			return scriptedReply{status: 200}
		})
		if err := c.upsertRoute(ctx, "rt", map[string]any{"@id": "rt"}); err == nil {
			t.Fatal("expected re-PATCH transport error")
		}
		if patches != 2 {
			t.Fatalf("patches = %d, want 2", patches)
		}
	})
}

// An error status whose body cannot be read still reports the status.
func TestSendJSONDetailUnreadableErrorBody(t *testing.T) {
	c := &Client{enabled: true, baseURL: "http://caddy.test", httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 502, Body: errReadCloser{err: io.ErrUnexpectedEOF}, Header: make(http.Header)}, nil
	})}}
	status, detail, err := c.sendJSONDetail(context.Background(), http.MethodPost, c.baseURL+"/x", nil)
	if err != nil || status != 502 || detail != "" {
		t.Fatalf("status=%d detail=%q err=%v", status, detail, err)
	}
}

func TestEnsureOnDemandTLSPolicyPostTransportError(t *testing.T) {
	c := scriptedClient(func(key string) scriptedReply {
		switch key {
		case "PUT /config/apps/tls/automation/on_demand":
			return scriptedReply{status: 200}
		case "GET /config/apps/tls/automation/policies":
			return scriptedReply{status: 404}
		}
		return scriptedReply{err: io.ErrClosedPipe}
	})
	if err := c.EnsureOnDemandTLS(context.Background(), "http://ask", 1, 1); err == nil {
		t.Fatal("expected policy POST transport error")
	}
}

func TestBadBaseURLRequestBuildErrors(t *testing.T) {
	ctx := context.Background()
	c := &Client{enabled: true, baseURL: "http://bad\x7f", httpClient: http.DefaultClient}
	if _, err := c.hasOnDemandPolicy(ctx); err == nil {
		t.Fatal("hasOnDemandPolicy: expected request build error")
	}
	if _, err := c.Snapshot(ctx); err == nil {
		t.Fatal("Snapshot: expected request build error")
	}
}

func TestDeleteTCPRouteNonPositivePortIsNoop(t *testing.T) {
	c := scriptedClient(func(string) scriptedReply { t.Fatal("no request expected"); return scriptedReply{} })
	for _, p := range []int{0, -1} {
		if err := c.DeleteTCPRoute(context.Background(), p); err != nil {
			t.Fatalf("DeleteTCPRoute(%d) = %v", p, err)
		}
	}
}

func TestEnsureLayer4WriteTransportErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("create-app", func(t *testing.T) {
		c := scriptedClient(func(key string) scriptedReply {
			if key == "GET /config/apps/layer4" {
				return scriptedReply{status: 404}
			}
			return scriptedReply{err: io.ErrClosedPipe}
		})
		if err := c.EnsureLayer4(ctx, "", ""); err == nil {
			t.Fatal("expected PUT layer4 transport error")
		}
	})
	t.Run("create-mux", func(t *testing.T) {
		c := scriptedClient(func(key string) scriptedReply {
			switch key {
			case "GET /config/apps/layer4":
				return scriptedReply{status: 200, body: `{"servers":{}}`}
			case "GET /config/apps/layer4/servers/" + tlsMuxServerID:
				return scriptedReply{status: 404}
			}
			return scriptedReply{err: io.ErrClosedPipe}
		})
		if err := c.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err == nil {
			t.Fatal("expected PUT tls-mux transport error")
		}
	})
}

// A second EnsureLayer4 against an already-correct tls-mux must not write:
// every admin write is a full Caddy reload.
func TestEnsureLayer4IsNoWriteWhenMuxCurrent(t *testing.T) {
	f, c := newFullCaddy(t, `{"apps":{}}`)
	ctx := context.Background()
	if err := c.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	_, before := f.counts()
	if err := c.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	if _, after := f.counts(); after != before {
		t.Fatalf("writes %d -> %d, want no write on a current mux", before, after)
	}
}

func TestSNIUpsertsInsertFailures(t *testing.T) {
	ctx := context.Background()
	upserts := []struct {
		name string
		run  func(c *Client) error
	}{
		{"tls-sni", func(c *Client) error { return c.UpsertTLSSNIRoute(ctx, "sb", "sb.d.test", "10.0.0.1", 443) }},
		{"wake-tls-sni", func(c *Client) error { return c.UpsertWakeTLSSNIRoute(ctx, "sb", "sb.d.test", "/tmp/wake.sock", 443) }},
		{"sni-passthrough", func(c *Client) error {
			return c.UpsertSNIPassthroughRoute(ctx, "sandbox-sb-ingress-sni", "sb.d.test", "10.0.0.2", 443)
		}},
	}
	puts := []struct {
		name    string
		reply   scriptedReply
		wantErr string
	}{
		{"put-transport", scriptedReply{err: io.ErrClosedPipe}, "PUT"},
		{"put-status", scriptedReply{status: 500}, "insert"},
	}
	for _, u := range upserts {
		for _, p := range puts {
			t.Run(u.name+"/"+p.name, func(t *testing.T) {
				c := scriptedClient(func(key string) scriptedReply {
					if strings.HasPrefix(key, "PATCH") {
						return scriptedReply{status: 404}
					}
					return p.reply
				})
				err := u.run(c)
				if err == nil || !strings.Contains(err.Error(), p.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, p.wantErr)
				}
			})
		}
	}
}
