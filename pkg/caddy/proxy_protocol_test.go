package caddy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// fallbackHandler returns the first handler of a route's handle list.
func fallbackHandler(t *testing.T, route map[string]any) map[string]any {
	t.Helper()
	switch handle := route["handle"].(type) {
	case []map[string]any:
		return handle[0]
	case []any:
		h, _ := handle[0].(map[string]any)
		return h
	}
	t.Fatalf("route has no handler list: %v", route)
	return nil
}

// TestTLSFallbackProxyProtocol pins CEO review D12 at the route builders:
// every tls-mux route that hands a connection to the local HTTPS site sends
// a PROXY v2 header when SB_L4_FALLBACK_PROXY_PROTOCOL is on, and none when
// it is off (the default), so a binary-only upgrade never sends a header to
// a site without the listener wrapper.
func TestTLSFallbackProxyProtocol(t *testing.T) {
	for _, on := range []bool{false, true} {
		c := New(config.Config{EnableCaddy: true, Domain: "d.test", L4TLSListen: ":443", L4TLSFallback: "127.0.0.1:8443", L4FallbackProxyProtocol: on})
		routes := map[string]map[string]any{"tls-mux-fallback": tlsMuxFallbackRoute(c.l4TLSFallback, c.l4FallbackProxyProtocol)}
		for _, r := range c.StaticIngressRoutes(StaticRouteSpec{LocalIP: "127.0.0.1"}) {
			routes[r["@id"].(string)] = r
		}
		for id, route := range routes {
			h := fallbackHandler(t, route)
			got, has := h["proxy_protocol"]
			switch {
			case id == StaticSNIRouteID:
				// Route 2 dials the owner through the route responder, not
				// the local site: it never speaks PROXY protocol.
				if has {
					t.Errorf("flag=%v: %s sends proxy_protocol %v, want none", on, id, got)
				}
			case on && got != "v2":
				t.Errorf("flag on: %s proxy_protocol = %v, want v2", id, got)
			case !on && has:
				t.Errorf("flag off: %s sends proxy_protocol %v, want none (L8)", id, got)
			}
		}
	}
}

// TestEnsureLayer4RewritesFallbackOnlyWhenTheFlagChanges: the fallback route
// is compared like the rest of tls-mux, so a restart with the flag flipped
// rewrites it once and a restart with the flag unchanged writes nothing.
func TestEnsureLayer4RewritesFallbackOnlyWhenTheFlagChanges(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	fake.layer4Exists = true
	fake.l4Servers[tlsMuxServerID] = map[string]any{
		"listen": []string{":443"},
		"routes": []any{tlsMuxFallbackRoute("127.0.0.1:8443", false)},
	}
	muxWrites := func() int {
		n := 0
		for _, rec := range fake.records {
			if strings.Contains(rec.Path, tlsMuxServerID) && rec.Method != http.MethodGet {
				n++
			}
		}
		return n
	}
	off := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
	if err := off.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	if n := muxWrites(); n != 0 {
		t.Fatalf("flag unchanged (off): %d tls-mux writes, want 0", n)
	}
	on := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client, l4FallbackProxyProtocol: true}
	if err := on.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	if n := muxWrites(); n != 1 {
		t.Fatalf("flag flipped on: %d tls-mux writes, want exactly 1", n)
	}
	routes := l4RouteSlice(fake.l4Servers[tlsMuxServerID]["routes"])
	last, _ := routes[len(routes)-1].(map[string]any)
	if got := fallbackHandler(t, last)["proxy_protocol"]; got != "v2" {
		t.Fatalf("rewritten fallback proxy_protocol = %v, want v2", got)
	}
}
