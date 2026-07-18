package isolate

import (
	"context"
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
