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
// The two proxyCache fields are the load-bearing knobs that ForwardHTTP
// inspects to pick the channel: mtlsProxies non-nil + Endpoint.InternalURL
// set ⇒ mTLS path; else public APIURL path. The transports point at the test
// servers so we can observe which one received the request.
func newForwardingCluster(t *testing.T, publicTransport, mtlsTransport http.RoundTripper) *Cluster {
	t.Helper()
	c := &Cluster{}
	c.publicProxies = newProxyCache(publicTransport)
	if mtlsTransport != nil {
		c.mtlsProxies = newProxyCache(mtlsTransport)
	}
	return c
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
	internalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- "internal"
		w.WriteHeader(http.StatusOK)
	}))
	defer internalSrv.Close()

	c := newForwardingCluster(t, http.DefaultTransport, http.DefaultTransport)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	c.ForwardHTTP(Endpoint{InternalURL: internalSrv.URL, APIURL: publicSrv.URL}, rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	got := <-hits
	if got != "internal" {
		t.Fatalf("forward landed on %q server, expected the mTLS-internal one", got)
	}
}

// TestForwardHTTPFallsBackToAPIURLWithoutTLS covers the legacy/mixed-cluster
// case: a node without SB_CLUSTER_TLS_DIR has no mtlsProxies; ForwardHTTP MUST
// still work by using the public APIURL+PAT path. This is the contract that
// keeps rolling upgrades unbroken.
func TestForwardHTTPFallsBackToAPIURLWithoutTLS(t *testing.T) {
	hits := make(chan string, 1)
	publicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- "public"
		w.WriteHeader(http.StatusOK)
	}))
	defer publicSrv.Close()

	// mtlsProxies nil simulates the no-TLS node.
	c := newForwardingCluster(t, http.DefaultTransport, nil)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	// Even when InternalURL is set on the target, a node without TLS can't
	// dial it — must fall through to APIURL.
	c.ForwardHTTP(Endpoint{InternalURL: "https://example:7002", APIURL: publicSrv.URL}, rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := <-hits; got != "public" {
		t.Fatalf("forward landed on %q server, expected fallback to public", got)
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

	c := newForwardingCluster(t, http.DefaultTransport, http.DefaultTransport)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	c.ForwardHTTP(Endpoint{InternalURL: "", APIURL: publicSrv.URL}, rr, r)

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
	c := newForwardingCluster(t, http.DefaultTransport, http.DefaultTransport)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	r.Header.Set("X-Cluster-Forwarded", "1")
	c.ForwardHTTP(Endpoint{InternalURL: "https://example:7002", APIURL: "http://example:21212"}, rr, r)
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
	c := newForwardingCluster(t, http.DefaultTransport, nil)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/sandboxes/sb-1", nil)
	c.ForwardHTTP(Endpoint{}, rr, r)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}
