package caddy

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// TestWildcardCatchAllClosesConnection: on a domain install, caddy-l4 routes
// a TLS connection to a sandbox by SNI once, when the connection opens; an
// SNI with no route falls through to the wildcard site's "Sandbox not found"
// 404. A client that connects in the gap between expose returning and the
// ingress route landing (up to one reconcile tick on a dedicated ingress
// node) is pinned to that 404, and a keep-alive client then reuses the
// pinned connection for every retry. Live 2026-10-04 (cluster-hetero): a
// preview URL answered 404 for 90 s although its route had been installed
// 2.3 s after expose. The catch-all must close the connection so the next
// attempt dials again and is routed afresh.
func TestWildcardCatchAllClosesConnection(t *testing.T) {
	for _, file := range []string{"../../scripts/install.sh", "../../packaging/Caddyfile.template"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		checked := 0
		inWildcard := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasSuffix(trimmed, "{") && strings.Contains(trimmed, "://") {
				inWildcard = strings.Contains(trimmed, "://*.") || strings.Contains(trimmed, "WILDCARD_SITE_ADDRESS")
			}
			if !inWildcard || !strings.HasPrefix(trimmed, `respond "Sandbox not found" 404`) {
				continue
			}
			checked++
			next := ""
			if i+1 < len(lines) {
				next = strings.TrimSpace(lines[i+1])
			}
			if !strings.HasSuffix(trimmed, "{") || next != "close" {
				t.Errorf("%s:%d: the wildcard catch-all must close the connection:\n\t%s\n\t%s", file, i+1, trimmed, next)
			}
		}
		if checked == 0 {
			t.Errorf("%s: found no wildcard \"Sandbox not found\" responder; the check would pass vacuously", file)
		}
	}
}

// TestCaddyfileProxiesKeepStreamsAcrossReloads: the API site's reverse_proxy
// carries every exec stream, aerolvm shell and session attach. Every admin-API
// route write reloads Caddy, and a reload closes each WebSocket a
// reverse_proxy carries with close code 1001 unless stream_close_delay is set
// (#712), so one user exposing a port cut every other user's open streams.
// Every reverse_proxy in the domain-mode Caddyfile must set the delay
// pkg/caddy sets on the routes sandboxd writes.
func TestCaddyfileProxiesKeepStreamsAcrossReloads(t *testing.T) {
	want := "stream_close_delay " + streamCloseDelay
	for _, file := range []string{"../../scripts/install.sh", "../../packaging/Caddyfile.template"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		apiProxies := 0
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "reverse_proxy ") {
				continue
			}
			if strings.HasPrefix(trimmed, "reverse_proxy 127.0.0.1:21212") {
				apiProxies++
			}
			if !strings.HasSuffix(trimmed, "{") || !slices.Contains(caddyfileBlock(lines[i+1:]), want) {
				t.Errorf("%s:%d: reverse_proxy must set %q in its block, or a Caddy reload closes its WebSockets with 1001:\n\t%s", file, i+1, want, trimmed)
			}
		}
		if apiProxies == 0 {
			t.Errorf("%s: found no API site reverse_proxy to 127.0.0.1:21212; the check would pass vacuously", file)
		}
	}
}

// caddyfileBlock returns the directives of the Caddyfile block whose opening
// brace ends the line just before lines, up to its closing brace. Comments
// are skipped.
func caddyfileBlock(lines []string) []string {
	var out []string
	depth := 1
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}"); depth <= 0 {
			return out
		}
		out = append(out, trimmed)
	}
	return out
}
