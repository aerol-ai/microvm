package wasm

import (
	"context"
	"io"
	"net/http"
	"strings"
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
	g.SetHTTPProxy(func(_ string, _ int, w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("guest-ok"))
		return nil
	})
	resp, err = http.Get("http://" + dial + "/")
	if err != nil {
		t.Fatalf("GET after allow: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after sync status = %d", resp.StatusCode)
	}
	if string(body) != "guest-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestNetworkByteCounters(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	dial, err := g.EnsureHTTPListener(ctx, "sb-bytes", 5000)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}
	g.SyncAllowedPorts("sb-bytes", []int{5000})

	body := "hello-ingress"
	resp, err := http.Post("http://"+dial+"/", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	deltas := g.DrainNetworkByteCounters()
	d := deltas["sb-bytes"]
	if d.BytesIn < int64(len(body)) {
		t.Fatalf("bytes in = %d, want >= %d", d.BytesIn, len(body))
	}
	if d.BytesOut == 0 {
		t.Fatalf("expected non-zero egress bytes for error response")
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
