package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every admin-API write that changes the config is a full Caddy reload, and a
// reload closes each WebSocket a reverse_proxy carries with close code 1001
// unless stream_close_delay is set (#712). Live 2026-10-16
// (cluster-hetero-lite-secrets): UC-68's exec stream failed with "stream
// closed before exit: close code=1001" because another sandbox's route
// changed while it was open. These tests hold every reverse_proxy sandboxd
// writes to the delay.

// TestReverseProxyBuildersSetStreamCloseDelay calls every route builder and
// checks every reverse_proxy handler in what it sends to Caddy, wherever the
// route nests it.
func TestReverseProxyBuildersSetStreamCloseDelay(t *testing.T) {
	const domain = "sandbox.example.com"
	cases := []struct {
		name   string
		domain string // "" = IP (path) mode, where the *ToPeer builders apply
		build  func(context.Context, *Client) error
	}{
		{"sandbox route with a custom domain", domain, func(ctx context.Context, c *Client) error {
			return c.UpsertSandboxRoute(ctx, "abc", "10.0.0.2", 2280, []CustomHostnameRoute{{Hostname: "app.example.org", TargetPort: 3000}})
		}},
		{"sandbox route to a peer", "", func(ctx context.Context, c *Client) error {
			return c.UpsertSandboxRouteToPeer(ctx, "abc", "10.0.0.9", nil)
		}},
		{"port route", domain, func(ctx context.Context, c *Client) error {
			return c.UpsertPortRoute(ctx, "abc", "10.0.0.2", 3000)
		}},
		{"port route with a masked Host", domain, func(ctx context.Context, c *Client) error {
			return c.UpsertPortRoute(ctx, "abc", "10.0.0.2", 3000, HTTPRouteOptions{MaskRequestHost: "localhost"})
		}},
		{"port route with an explicit dial", domain, func(ctx context.Context, c *Client) error {
			return c.UpsertPortRouteWithDial(ctx, "abc", 3000, "127.0.0.1:41000")
		}},
		{"port route with a retry window", domain, func(ctx context.Context, c *Client) error {
			return c.UpsertPortRouteWithRetry(ctx, "abc", "10.0.0.2", 3000, 2*time.Second)
		}},
		{"port route to a peer", "", func(ctx context.Context, c *Client) error {
			return c.UpsertPortRouteToPeer(ctx, "abc", 3000, "10.0.0.9")
		}},
		{"custom-domain route", domain, func(ctx context.Context, c *Client) error {
			return c.UpsertCustomDomainHTTPRouteWithDial(ctx, "abc", "app.example.org", "10.0.0.2:3000")
		}},
		{"wake-aware port route", domain, func(ctx context.Context, c *Client) error {
			return c.UpsertWakeHTTPPortRoute(ctx, "abc", "127.0.0.1:21213", 3000)
		}},
		{"static sandbox route", domain, func(ctx context.Context, c *Client) error {
			return c.EnsureStaticSandboxRoute(ctx, testSpec)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, writes := newWriteRecorder(t, tc.domain)
			if err := tc.build(context.Background(), c); err != nil {
				t.Fatalf("build: %v", err)
			}
			proxies := 0
			for _, body := range writes() {
				for _, h := range reverseProxyHandlers(t, body) {
					proxies++
					if got := h["stream_close_delay"]; got != streamCloseDelay {
						t.Errorf("reverse_proxy stream_close_delay = %v, want %q (a reload would close its WebSockets with 1001):\n%s", got, streamCloseDelay, body)
					}
				}
			}
			if proxies == 0 {
				t.Fatal("the builder wrote no reverse_proxy handler; this row checks nothing")
			}
		})
	}
}

// TestNoReverseProxyBuiltWithoutStreamCloseDelay catches a builder the table
// above does not know about yet: every "reverse_proxy" string in the daemon's
// Go source must be the "handler" of a map literal that also sets
// "stream_close_delay". A handler built any other way fails here until it
// sets the delay and this test learns its shape.
func TestNoReverseProxyBuiltWithoutStreamCloseDelay(t *testing.T) {
	handlers := 0
	for _, root := range []string{"../../cmd", "../../internal", "../../pkg"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(src, []byte(`"reverse_proxy"`)) {
				return err
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				return err
			}
			covered := map[token.Pos]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				var handler *ast.BasicLit
				hasDelay := false
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					switch stringLit(kv.Key) {
					case `"handler"`:
						if v, ok := kv.Value.(*ast.BasicLit); ok && v.Value == `"reverse_proxy"` {
							handler = v
						}
					case `"stream_close_delay"`:
						hasDelay = true
					}
				}
				if handler != nil {
					handlers++
					covered[handler.Pos()] = true
					if !hasDelay {
						t.Errorf("%s: a reverse_proxy handler without stream_close_delay; a Caddy reload would close its WebSockets with 1001 (#712)", fset.Position(handler.Pos()))
					}
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Value == `"reverse_proxy"` && !covered[lit.Pos()] {
					t.Errorf("%s: \"reverse_proxy\" outside a handler map literal; set stream_close_delay on that handler and extend this test to see it", fset.Position(lit.Pos()))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if handlers == 0 {
		t.Fatal("found no reverse_proxy handler literal at all; the source walk is broken and would pass vacuously")
	}
	t.Logf("checked %d reverse_proxy handler literals", handlers)
}

func stringLit(e ast.Expr) string {
	if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		return lit.Value
	}
	return ""
}

// newWriteRecorder is a Caddy admin API that keeps the body of every write.
// PATCH /id/<x> answers 404, so each builder also takes its insert path, and
// a route list reads as empty.
func newWriteRecorder(t *testing.T, domain string) (*Client, func() [][]byte) {
	t.Helper()
	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, "[]")
			return
		case http.MethodDelete:
			return
		}
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		if r.Method == http.MethodPatch {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := &Client{enabled: true, domain: domain, publicHost: "203.0.113.10", serverID: "srv0", baseURL: srv.URL, httpClient: srv.Client()}
	return c, func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return append([][]byte(nil), bodies...)
	}
}

// reverseProxyHandlers returns every reverse_proxy handler object anywhere in
// a JSON document.
func reverseProxyHandlers(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode admin write %q: %v", body, err)
	}
	var out []map[string]any
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if v["handler"] == "reverse_proxy" {
				out = append(out, v)
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	return out
}
