package wasm

import (
	"context"
	"io"
	"net/http"
	"testing"
)

func TestEnsureHTTPListenerIdempotent(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()

	dial1, err := g.EnsureHTTPListener(ctx, "sb-1", 8080)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}
	dial2, err := g.EnsureHTTPListener(ctx, "sb-1", 8080)
	if err != nil {
		t.Fatalf("EnsureHTTPListener retry: %v", err)
	}
	if dial1 != dial2 {
		t.Fatalf("expected same dial addr, got %q and %q", dial1, dial2)
	}
}

func TestHTTPListenerAllowlist(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	dial, err := g.EnsureHTTPListener(ctx, "sb-1", 3000)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}

	resp, err := http.Get("http://" + dial + "/")
	if err != nil {
		t.Fatalf("GET before allow: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("before sync status = %d", resp.StatusCode)
	}

	g.SyncAllowedPorts("sb-1", []int{3000})
	resp, err = http.Get("http://" + dial + "/")
	if err != nil {
		t.Fatalf("GET after allow: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("after sync status = %d", resp.StatusCode)
	}
}

func TestReleaseHTTPListener(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	dial, err := g.EnsureHTTPListener(ctx, "sb-1", 4000)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}
	g.SyncAllowedPorts("sb-1", []int{4000})
	g.ReleaseHTTPListener("sb-1", 4000)

	resp, err := http.Get("http://" + dial + "/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected connection failure after release")
	}
}
