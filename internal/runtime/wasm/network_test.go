package wasm

import (
	"context"
	"fmt"
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

func TestEnsureHTTPListenerInvalidRequest(t *testing.T) {
	g := newNetworkGateway()
	if _, err := g.EnsureHTTPListener(context.Background(), "", 8080); err == nil {
		t.Fatal("empty sandbox id expected error")
	}
	if _, err := g.EnsureHTTPListener(context.Background(), "sb", 0); err == nil {
		t.Fatal("invalid port expected error")
	}
}

func TestNetworkBlocksIngressAndEgress(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	dial, err := g.EnsureHTTPListener(ctx, "sb-block", 9000)
	if err != nil {
		t.Fatal(err)
	}
	g.SyncAllowedPorts("sb-block", []int{9000})

	g.SetNetworkBlocks("sb-block", true, false)
	resp, err := http.Get("http://" + dial + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ingress block status = %d", resp.StatusCode)
	}

	g.SetNetworkBlocks("sb-block", false, true)
	g.SetHTTPProxy(func(_ string, _ int, w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	resp, err = http.Get("http://" + dial + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("egress block status = %d", resp.StatusCode)
	}
}

func TestServeHTTPWithoutProxy(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	dial, err := g.EnsureHTTPListener(ctx, "sb-noproxy", 7000)
	if err != nil {
		t.Fatal(err)
	}
	g.SyncAllowedPorts("sb-noproxy", []int{7000})
	resp, err := http.Get("http://" + dial + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestServeHTTPProxyError(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	dial, err := g.EnsureHTTPListener(ctx, "sb-proxyerr", 7100)
	if err != nil {
		t.Fatal(err)
	}
	g.SyncAllowedPorts("sb-proxyerr", []int{7100})
	g.SetHTTPProxy(func(_ string, _ int, _ http.ResponseWriter, _ *http.Request) error {
		return fmt.Errorf("proxy failed")
	})
	resp, err := http.Get("http://" + dial + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestReleaseSandboxClearsState(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()
	if _, err := g.EnsureHTTPListener(ctx, "sb-rel", 7200); err != nil {
		t.Fatal(err)
	}
	g.SyncAllowedPorts("sb-rel", []int{7200})
	g.SetNetworkBlocks("sb-rel", true, true)
	g.ReleaseSandbox("sb-rel")
	if got := g.DrainNetworkByteCounters(); got != nil {
		t.Fatalf("expected empty usage after release, got %+v", got)
	}
}

func TestDriverPortsNilNet(t *testing.T) {
	d := &Driver{}
	d.ReleaseHTTPListener("sb", 80)
	d.SyncAllowedPorts("sb", []int{80})
}

func TestUsageForCreatesEntry(t *testing.T) {
	g := newNetworkGateway()
	u := g.usageFor("sb-usage")
	if u == nil {
		t.Fatal("usageFor should allocate counter")
	}
	u.bytesIn.Add(3)
	deltas := g.DrainNetworkByteCounters()
	if deltas["sb-usage"].BytesIn != 3 {
		t.Fatalf("bytes in = %d", deltas["sb-usage"].BytesIn)
	}
}

func TestSyncAllowedPortsSkipsInvalid(t *testing.T) {
	g := newNetworkGateway()
	g.SyncAllowedPorts("", []int{80})
	g.SyncAllowedPorts("sb", []int{0, 99999})
	if len(g.allowed["sb"]) != 0 {
		t.Fatalf("allowed = %#v", g.allowed["sb"])
	}
}

func TestSetNetworkBlocksEmptySandbox(t *testing.T) {
	g := newNetworkGateway()
	g.SetNetworkBlocks("", true, true)
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
