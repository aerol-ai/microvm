package cluster

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestInternalTransportPoolSizing pins the idle-pool sizing on the transports
// New and NewAgent install this transport for leader RPCs and node-pinned
// owner proxies, so the two paths cannot drift apart.
func TestInternalTransportPoolSizing(t *testing.T) {
	t.Parallel()
	tr := newInternalTransport(&tls.Config{}) //nolint:gosec // sizing test only
	if tr.MaxIdleConns != 64 || tr.MaxIdleConnsPerHost != 16 {
		t.Fatalf("internal pool = %d/%d, want 64/16 (Tier 1 Phase 4)", tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
	if tr.DisableKeepAlives {
		t.Fatal("internal transport must keep keep-alives on")
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Fatalf("internal IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("internal transport must carry the mTLS client config")
	}
}

// TestInternalTransportIdlePoolReuse proves the constructor-built transport
// actually reuses connections: N sequential requests must dial (and TLS
// handshake) exactly once. This is the behavior that fixed the
// leader_forward p90 tail (warm-create-latency Tier 1 Phase 4).
func TestInternalTransportIdlePoolReuse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	tr := newInternalTransport(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only
	var dials atomic.Int64
	dialer := &net.Dialer{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return dialer.DialContext(ctx, network, addr)
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	const n = 8
	for i := range n {
		resp, err := client.Get(srv.URL + "/ping")
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d for %d sequential requests, want 1 (idle pool reuse)", got, n)
	}
}
