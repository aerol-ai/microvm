package cluster

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeForwarder is the minimal *Cluster shape ForwardHTTP relies on. The real
// struct has dozens of dependencies (raft, gossip, deadOwners, ...) we don't
// need to drive a forwarding-channel-selection test; building one inline keeps
// these regression tests honest without bringing up a 3-node raft cluster.
//
// The internal client is deliberately non-TLS in unit tests unless supplied
// by httptest.NewTLSServer; production wraps it with node-SAN verification.
func newForwardingCluster(t *testing.T, mtlsTransport http.RoundTripper) *Cluster {
	t.Helper()
	if mtlsTransport == nil {
		return &Cluster{}
	}
	return &Cluster{
		internalClient: &http.Client{Transport: mtlsTransport},
		mtlsProxies:    newProxyCache(),
	}
}

func newNodeBoundForwardServer(t *testing.T, clientNodeID, serverNodeID string, h http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	dirs := writeTestClusterTLSDirs(t, clientNodeID, serverNodeID)
	return newNodeBoundForwardServerWithDirs(t, dirs, clientNodeID, serverNodeID, h)
}

func newNodeBoundForwardServerWithDirs(t *testing.T, dirs map[string]string, clientNodeID, serverNodeID string, h http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	clientTLS, err := loadClusterTLS(dirs[clientNodeID])
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := loadClusterTLS(dirs[serverNodeID])
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = serverTLS.serverConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: newInternalTransport(clientTLS.clientConfig())}
	t.Cleanup(client.CloseIdleConnections)
	return srv, client
}

// TestForwardHTTPPrefersInternalURLWhenAvailable pins the B3 fix: when the
// caller has TLS material AND the target advertises an InternalURL, the
// reverse-proxy rides the mTLS channel. Without this, owner API forwarding
// would silently keep using the public APIURL+PAT path that the
// release-blocker plan flagged as a security/operability mismatch.
func TestForwardHTTPPrefersInternalURLWhenAvailable(t *testing.T) {
	hits := make(chan string, 2)
	publicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- "public"
		w.WriteHeader(http.StatusOK)
	}))
	defer publicSrv.Close()
	internalSrv, internalClient := newNodeBoundForwardServer(t, "caller-1", "owner-1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- "internal"
		w.WriteHeader(http.StatusOK)
	}))

	c := newForwardingCluster(t, internalClient.Transport)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	c.ForwardHTTP(Endpoint{NodeID: "owner-1", InternalURL: internalSrv.URL, APIURL: publicSrv.URL}, rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	got := <-hits
	if got != "internal" {
		t.Fatalf("forward landed on %q server, expected the mTLS-internal one", got)
	}
}

func TestForwardHTTPRejectsWrongNodeCertificate(t *testing.T) {
	hit := make(chan struct{}, 1)
	server, internalClient := newNodeBoundForwardServer(t, "caller-1", "owner-1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	c := newForwardingCluster(t, internalClient.Transport)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	c.ForwardHTTP(Endpoint{NodeID: "owner-2", InternalURL: server.URL}, rr, r)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for wrong node certificate", rr.Code)
	}
	select {
	case <-hit:
		t.Fatal("handler ran despite wrong node certificate")
	default:
	}
}

func TestForwardHTTPFailsClosedWithoutTLS(t *testing.T) {
	hits := make(chan string, 1)
	publicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- "public"
		w.WriteHeader(http.StatusOK)
	}))
	defer publicSrv.Close()

	c := newForwardingCluster(t, nil)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	c.ForwardHTTP(Endpoint{NodeID: "owner-1", InternalURL: "https://example:7002", APIURL: publicSrv.URL}, rr, r)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	select {
	case got := <-hits:
		t.Fatalf("forward landed on %q; want no public downgrade", got)
	default:
	}
}

// TestForwardHTTPFailClosedWhenInternalEmpty pins mTLS fail-closed: when this
// node has TLS (mtlsProxies != nil) but the peer has no InternalURL, we must
// 503 rather than silently downgrade to APIURL+PAT.
func TestForwardHTTPFailClosedWhenInternalEmpty(t *testing.T) {
	hits := make(chan string, 1)
	publicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- "public"
		w.WriteHeader(http.StatusOK)
	}))
	defer publicSrv.Close()

	c := newForwardingCluster(t, http.DefaultTransport)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	c.ForwardHTTP(Endpoint{NodeID: "owner-1", InternalURL: "", APIURL: publicSrv.URL}, rr, r)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	select {
	case got := <-hits:
		t.Fatalf("forward landed on %q; want no public dial when InternalURL empty", got)
	default:
	}
}

// TestForwardHTTPRejectsLoop keeps the existing 421 loop-detection behavior
// honest after the channel-selection rewrite. Without this, a stale placement
// view on two peers could ping-pong forever — exactly the scenario the
// X-Cluster-Forwarded header was introduced to defuse.
func TestForwardHTTPRejectsLoop(t *testing.T) {
	c := newForwardingCluster(t, http.DefaultTransport)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	r.Header.Set("X-Cluster-Forwarded", "1")
	c.ForwardHTTP(Endpoint{NodeID: "owner-1", InternalURL: "https://example:7002", APIURL: "http://example:21212"}, rr, r)
	if rr.Code != http.StatusMisdirectedRequest {
		body, _ := io.ReadAll(rr.Result().Body)
		t.Fatalf("status = %d, want 421 (loop detected); body=%q", rr.Code, body)
	}
}

// TestForwardHTTP503WhenNoUsableEndpoint catches the misconfiguration case
// (placement record has neither InternalURL nor APIURL — e.g. a peer that
// died before announcing). 503 is the documented signal for clients to retry
// against a refreshed placement; 5xx would mask the cause.
func TestForwardHTTP503WhenNoUsableEndpoint(t *testing.T) {
	c := newForwardingCluster(t, nil)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	c.ForwardHTTP(Endpoint{}, rr, r)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}
