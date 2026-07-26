package isolate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPortGatewayEnsureAndProxy(t *testing.T) {
	d := New(Config{}, nil)
	d.net.SetHTTPProxy(func(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
		_, _ = w.Write([]byte("hello-" + sandboxID))
		return nil
	})
	ctx := context.Background()
	addr, err := d.EnsureHTTPListener(ctx, "sb-1", 8080)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("addr = %q", addr)
	}
	d.SyncAllowedPorts("sb-1", []int{8080})

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "hello-sb-1" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}

	// Port not allowed → 403.
	d.SyncAllowedPorts("sb-1", nil)
	resp, err = http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	d.ReleaseHTTPListener("sb-1", 8080)
}

func TestEgressPolicyAllowDeny(t *testing.T) {
	if egressAllowed(EgressPolicy{BlockAll: true}, "example.com") {
		t.Fatal("BlockAll should deny")
	}
	if !egressAllowed(EgressPolicy{}, "example.com") {
		t.Fatal("empty allow should allow-all")
	}
	if egressAllowed(EgressPolicy{Allow: []string{"api.example.com"}}, "evil.com") {
		t.Fatal("non-allowlisted host should deny")
	}
	if !egressAllowed(EgressPolicy{Allow: []string{"api.example.com"}}, "api.example.com") {
		t.Fatal("allowlisted host should allow")
	}
	if egressAllowed(EgressPolicy{Deny: []string{"evil.com"}}, "evil.com") {
		t.Fatal("deny should win")
	}
}

func TestAsPortGateway(t *testing.T) {
	d := New(Config{}, nil)
	pg, ok := AsPortGateway(d)
	if !ok || pg == nil {
		t.Fatal("Driver should implement PortGateway")
	}
	_ = httptest.NewRecorder()
}

func TestNetworkGatewayEdgeCases(t *testing.T) {
	g := newNetworkGateway()
	ctx := context.Background()

	t.Run("invalid_listener_request", func(t *testing.T) {
		if _, err := g.EnsureHTTPListener(ctx, "", 8080); err == nil {
			t.Fatal("empty sandbox id should error")
		}
		if _, err := g.EnsureHTTPListener(ctx, "sb-1", 0); err == nil {
			t.Fatal("zero port should error")
		}
		if _, err := g.EnsureHTTPListener(ctx, "sb-1", 70000); err == nil {
			t.Fatal("invalid port should error")
		}
	})

	t.Run("reuse_existing_listener", func(t *testing.T) {
		addr1, err := g.EnsureHTTPListener(ctx, "sb-1", 3000)
		if err != nil {
			t.Fatal(err)
		}
		addr2, err := g.EnsureHTTPListener(ctx, "sb-1", 3000)
		if err != nil || addr1 != addr2 {
			t.Fatalf("reuse addr1=%q addr2=%q err=%v", addr1, addr2, err)
		}
	})

	t.Run("sync_allowed_ports_filters", func(t *testing.T) {
		g.SyncAllowedPorts("", []int{8080})
		g.SyncAllowedPorts("sb-1", []int{0, 8080, 70000, 443})
		g.mu.Lock()
		set := g.allowed["sb-1"]
		g.mu.Unlock()
		if len(set) != 2 {
			t.Fatalf("allowed ports = %d, want 2", len(set))
		}
	})

	t.Run("release_sandbox", func(t *testing.T) {
		_, _ = g.EnsureHTTPListener(ctx, "sb-2", 8080)
		g.SyncAllowedPorts("sb-2", []int{8080})
		g.SetNetworkBlocks("sb-2", true, true)
		g.usage["sb-2"] = &sandboxNetUsage{}
		g.ReleaseSandbox("sb-2")
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.listeners["sb-2"] != nil || g.allowed["sb-2"] != nil || g.usage["sb-2"] != nil {
			t.Fatal("ReleaseSandbox should clear state")
		}
	})

	t.Run("close_listener_noop", func(t *testing.T) {
		g.closeListenerLocked("missing", 8080)
		g.closeListenerLocked("sb-3", 8080)
	})
}

func TestNetworkBlocksAndByteCounters(t *testing.T) {
	d := New(Config{}, nil)
	d.net.SetHTTPProxy(func(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
		_, _ = w.Write([]byte("body"))
		return nil
	})
	ctx := context.Background()
	addr, err := d.EnsureHTTPListener(ctx, "sb-1", 8080)
	if err != nil {
		t.Fatal(err)
	}
	d.SyncAllowedPorts("sb-1", []int{8080})

	t.Run("ingress_blocked", func(t *testing.T) {
		d.SetNetworkBlocks("sb-1", true, false)
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("ingress block status = %d", resp.StatusCode)
		}
		d.SetNetworkBlocks("sb-1", false, false)
	})

	t.Run("egress_blocked", func(t *testing.T) {
		d.SetNetworkBlocks("sb-1", false, true)
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("egress block status = %d", resp.StatusCode)
		}
		d.SetNetworkBlocks("sb-1", false, false)
	})

	t.Run("no_proxy", func(t *testing.T) {
		d2 := New(Config{}, nil)
		d2.net.SetHTTPProxy(nil)
		addr2, err := d2.EnsureHTTPListener(ctx, "sb-x", 8080)
		if err != nil {
			t.Fatal(err)
		}
		d2.SyncAllowedPorts("sb-x", []int{8080})
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr2+"/", strings.NewReader("in"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("no proxy status = %d", resp.StatusCode)
		}
	})

	t.Run("proxy_error", func(t *testing.T) {
		d3 := New(Config{}, nil)
		d3.net.SetHTTPProxy(func(string, int, http.ResponseWriter, *http.Request) error {
			return errors.New("proxy boom")
		})
		addr3, err := d3.EnsureHTTPListener(ctx, "sb-y", 8080)
		if err != nil {
			t.Fatal(err)
		}
		d3.SyncAllowedPorts("sb-y", []int{8080})
		resp, err := http.Get("http://" + addr3 + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("proxy error status = %d", resp.StatusCode)
		}
	})

	t.Run("byte_counters", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		got := d.DrainNetworkByteCounters()
		if got == nil || got["sb-1"].BytesOut == 0 {
			t.Fatalf("expected egress byte count, got %v", got)
		}
		if drained := d.DrainNetworkByteCounters(); drained == nil {
			t.Fatal("usage map still tracks sandbox after first drain")
		}
		for _, v := range d.DrainNetworkByteCounters() {
			if v.BytesIn != 0 || v.BytesOut != 0 {
				t.Fatalf("second drain should return zero deltas, got %+v", v)
			}
		}
		d.SetNetworkBlocks("", true, true) // no-op for empty id
	})
}
