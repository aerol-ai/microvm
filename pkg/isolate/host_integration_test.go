//go:build integration

package isolate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

// TestHostEndToEnd is the Phase-2 proof: spawn a real workerd group host,
// dynamically load two distinct sandboxes through the controller + HOST
// bundle-server, and assert each serves its own bundle. Tag-gated (needs a
// real workerd via SB_ISOLATE_WORKERD_PATH); mirrors the wasm-integration
// precedent. This is the test that says "isolates actually run code."
func TestHostEndToEnd(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}

	h, err := NewHost(HostConfig{
		WorkerdPath:  workerd,
		GroupKey:     "acme",
		RunDir:       t.TempDir(),
		StartTimeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("start host: %v", err)
	}
	defer h.Stop()

	mkBundle := func(body string) *jsbundle.Bundle {
		b, err := jsbundle.BuildFromSource("m.js",
			`export default { async fetch(r) { return new Response(`+quote(body)+`); } };`, "")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	if err := h.Load("sb-alpha", mkBundle("alpha-body")); err != nil {
		t.Fatal(err)
	}
	if err := h.Load("sb-beta", mkBundle("beta-body")); err != nil {
		t.Fatal(err)
	}

	invoke := func(id string) (int, string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ctrl/", nil)
		resp, err := h.Invoke(ctx, id, req)
		if err != nil {
			t.Fatalf("invoke %s: %v", id, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	if code, body := invoke("sb-alpha"); code != 200 || body != "alpha-body" {
		t.Fatalf("alpha invoke = %d %q, want 200 alpha-body", code, body)
	}
	if code, body := invoke("sb-beta"); code != 200 || body != "beta-body" {
		t.Fatalf("beta invoke = %d %q, want 200 beta-body", code, body)
	}
	// Warm re-hit still routes to the right isolate.
	if code, body := invoke("sb-alpha"); code != 200 || body != "alpha-body" {
		t.Fatalf("alpha re-invoke = %d %q", code, body)
	}

	// A sandbox that was never pinned → the controller's bundle probe 404s →
	// clean 404 (no such sandbox), distinct from a 502 bundle-server error or
	// the isolate's own fetch response.
	if code, _ := invoke("sb-never-loaded"); code != http.StatusNotFound {
		t.Fatalf("never-loaded invoke = %d, want 404", code)
	}
}

// quote renders s as a JSON string literal for embedding into worker source.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
