package cluster

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// proxyCache caches one ReverseProxy per peer URL. Building a fresh proxy per
// request is cheap but allocating its underlying http.Transport pool every
// time would defeat connection reuse. The cache key is the peer's base URL
// string; entries are never evicted because the peer set is small (~10K
// members worst case). One cache per transport (public plaintext vs. mTLS
// pinned) so a peer that participates on both channels gets two independent
// proxies — keepalive state and TLS sessions never mix.
type proxyCache struct {
	mu        sync.RWMutex
	proxies   map[string]*httputil.ReverseProxy
	transport http.RoundTripper
}

func newProxyCache(rt http.RoundTripper) *proxyCache {
	return &proxyCache{proxies: make(map[string]*httputil.ReverseProxy), transport: rt}
}

func (pc *proxyCache) get(baseURL string) (*httputil.ReverseProxy, error) {
	pc.mu.RLock()
	if p, ok := pc.proxies[baseURL]; ok {
		pc.mu.RUnlock()
		return p, nil
	}
	pc.mu.RUnlock()

	pc.mu.Lock()
	defer pc.mu.Unlock()
	if p, ok := pc.proxies[baseURL]; ok {
		return p, nil
	}
	target, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			// Mark forwarded so the receiving node can detect a forwarding
			// loop (would happen if its placement view is stale and it
			// thinks the request belongs back at us). Receiver returns 421
			// if it sees the header AND would forward again.
			req.Header.Set("X-Cluster-Forwarded", "1")
		},
		Transport: pc.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "cluster: forward to "+baseURL+" failed: "+err.Error(), http.StatusBadGateway)
		},
	}
	pc.proxies[baseURL] = rp
	return rp, nil
}

// defaultPublicTransport is the plaintext/public-API transport shared by every
// Cluster instance (the underlying pool is the only state worth sharing). The
// mTLS transport lives per-Cluster because it needs the per-cluster CA + node
// cert from ClusterTLS.
var defaultPublicTransport http.RoundTripper = &http.Transport{
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 10,
	IdleConnTimeout:     90 * time.Second,
}

// ForwardHTTP reverse-proxies r to target and writes the response into w. The
// PAT bearer header is preserved (httputil.ReverseProxy passes through
// headers by default; we only strip hop-by-hop ones).
//
// Channel selection: when this node has TLS material loaded AND
// target.InternalURL is non-empty, the proxy rides the cluster-internal mTLS
// channel — the receiving node's mTLS listener serves the same v1 API mux as
// the public port (see AttachInternalHandler), so handlers run identically.
// Falling back to target.APIURL (public, PAT-only) when either side lacks
// TLS keeps mixed/legacy clusters working.
//
// Forwarding loops are detected by the X-Cluster-Forwarded header and returned
// as 421 Misdirected Request so clients retry against a refreshed placement.
//
// IMPORTANT: a hard network/TLS failure on the internal channel must NOT
// silently fall back to the public path — that would defeat the cert-pinned
// security promise B3 is meant to enforce. The reverse proxy's ErrorHandler
// surfaces such failures as 502 to the original caller, who can then retry
// against a different peer.
func (c *Cluster) ForwardHTTP(target Endpoint, w http.ResponseWriter, r *http.Request) {
	forwardHTTPWithMetrics(c.mtlsProxies, c.publicProxies, target, w, r)
}

func forwardHTTPWithMetrics(mtlsProxies *proxyCache, publicProxies *proxyCache, target Endpoint, w http.ResponseWriter, r *http.Request) {
	var err error
	done := beginOwnerForward()
	defer func() { done(err) }()
	if r.Header.Get("X-Cluster-Forwarded") == "1" {
		// Loop detection: someone forwarded to us, and we're about to forward
		// onward. Return 421 so the original client retries with fresh
		// placement info instead of bouncing forever.
		err = errors.New("cluster: forwarding loop detected")
		RecordOwnerForwardStale()
		http.Error(w, "cluster: forwarding loop detected", http.StatusMisdirectedRequest)
		return
	}
	if mtlsProxies != nil && target.InternalURL != "" {
		err = serveProxy(mtlsProxies, target.InternalURL, w, r)
		return
	}
	if target.APIURL == "" {
		err = errors.New("cluster: peer API URL unknown")
		recordOwnerForwardTargetMiss("api_url_unknown")
		http.Error(w, "cluster: peer API URL unknown", http.StatusServiceUnavailable)
		return
	}
	err = serveProxy(publicProxies, target.APIURL, w, r)
}

func serveProxy(cache *proxyCache, baseURL string, w http.ResponseWriter, r *http.Request) error {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		http.Error(w, "cluster: peer URL must include scheme", http.StatusBadGateway)
		return errors.New("cluster: peer URL must include scheme")
	}
	proxy, err := cache.get(baseURL)
	if err != nil {
		http.Error(w, "cluster: invalid peer URL: "+err.Error(), http.StatusBadGateway)
		return err
	}
	proxy.ServeHTTP(w, r)
	return nil
}
