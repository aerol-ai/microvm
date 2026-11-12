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

// TestInternalTransportBoundsDeadPeers pins the dead-peer bounds (Phase 3
// zone-loss drill): without them a call to a peer that dropped off the
// network waited for whatever sat above it, 3 minutes for a forwarded create.
func TestInternalTransportBoundsDeadPeers(t *testing.T) {
	t.Parallel()
	tr := newInternalTransport(&tls.Config{}) //nolint:gosec // settings test only
	if tr.DialContext == nil {
		t.Fatal("internal transport must dial through newInternalDialer, not net's unbounded default")
	}
	if tr.TLSHandshakeTimeout != internalTLSHandshakeTimeout || internalTLSHandshakeTimeout != 5*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 5s", tr.TLSHandshakeTimeout)
	}
	d := newInternalDialer()
	if d.Timeout != 3*time.Second {
		t.Fatalf("dial timeout = %v, want 3s", d.Timeout)
	}
	want := net.KeepAliveConfig{Enable: true, Idle: 5 * time.Second, Interval: 5 * time.Second, Count: 3}
	if d.KeepAliveConfig != want {
		t.Fatalf("keepalive = %+v, want %+v", d.KeepAliveConfig, want)
	}
	if d.Control == nil {
		t.Fatal("dialer must set TCP_USER_TIMEOUT before connecting")
	}
}

// TestNeverReachedPeerSeesThroughTheHTTPClient: the control-plane loop
// moves on only when the call never left this node. A dial failure, as
// http.Client wraps it, counts; a peer that took the request and then
// dropped the connection does not, since it may have applied it.
func TestNeverReachedPeerSeesThroughTheHTTPClient(t *testing.T) {
	t.Parallel()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := closed.Addr().String()
	_ = closed.Close()

	took := make(chan struct{}, 4)
	dropper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		took <- struct{}{}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("no hijacker")
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer dropper.Close()

	client := &http.Client{Transport: newInternalTransport(nil), Timeout: 5 * time.Second}
	_, err = client.Post("http://"+refused+"/apply", "application/json", nil)
	if !neverReachedPeer(err) {
		t.Fatalf("refused connect: neverReachedPeer(%v) = false, want true", err)
	}
	_, err = client.Post(dropper.URL+"/apply", "application/json", nil)
	if err == nil {
		t.Fatal("dropped connection: want an error")
	}
	<-took
	if neverReachedPeer(err) {
		t.Fatalf("dropped after the request arrived: neverReachedPeer(%v) = true, want false", err)
	}
	if neverReachedPeer(nil) || neverReachedPeer(statusError{status: http.StatusInternalServerError}) {
		t.Fatal("nil and HTTP status errors must not count as never reached")
	}
}
