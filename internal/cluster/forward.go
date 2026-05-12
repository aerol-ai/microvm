package cluster

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// proxyCache caches one ReverseProxy per peer URL. Building a fresh proxy per
// request is cheap but allocating its underlying http.Transport pool every
// time would defeat connection reuse. The cache key is the peer's API base
// URL string; entries are never evicted because the peer set is small (~10K
// members worst case).
type proxyCache struct {
	mu      sync.RWMutex
	proxies map[string]*httputil.ReverseProxy
}

func newProxyCache() *proxyCache {
	return &proxyCache{proxies: make(map[string]*httputil.ReverseProxy)}
}

func (pc *proxyCache) get(peerAPIURL string) (*httputil.ReverseProxy, error) {
	pc.mu.RLock()
	if p, ok := pc.proxies[peerAPIURL]; ok {
		pc.mu.RUnlock()
		return p, nil
	}
	pc.mu.RUnlock()

	pc.mu.Lock()
	defer pc.mu.Unlock()
	if p, ok := pc.proxies[peerAPIURL]; ok {
		return p, nil
	}
	target, err := url.Parse(peerAPIURL)
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
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "cluster: forward to "+peerAPIURL+" failed: "+err.Error(), http.StatusBadGateway)
		},
	}
	pc.proxies[peerAPIURL] = rp
	return rp, nil
}

// Cluster's forward cache is built lazily on first use.
var forwardCache = newProxyCache()

// ForwardHTTP reverse-proxies r to peerAPIURL and writes the response into w.
// The PAT bearer header is preserved (httputil.ReverseProxy passes through
// headers by default; we only strip hop-by-hop ones). Forwarding loops are
// detected by the X-Cluster-Forwarded header and returned as 421
// Misdirected Request so clients retry.
func (c *Cluster) ForwardHTTP(peerAPIURL string, w http.ResponseWriter, r *http.Request) {
	if peerAPIURL == "" {
		http.Error(w, "cluster: peer API URL unknown", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("X-Cluster-Forwarded") == "1" {
		// Loop detection: someone forwarded to us, and we're about to forward
		// onward. Return 421 so the original client retries with fresh
		// placement info instead of bouncing forever.
		http.Error(w, "cluster: forwarding loop detected", http.StatusMisdirectedRequest)
		return
	}
	if !strings.HasPrefix(peerAPIURL, "http://") && !strings.HasPrefix(peerAPIURL, "https://") {
		http.Error(w, "cluster: peer API URL must include scheme", http.StatusBadGateway)
		return
	}
	proxy, err := forwardCache.get(peerAPIURL)
	if err != nil {
		http.Error(w, "cluster: invalid peer URL: "+err.Error(), http.StatusBadGateway)
		return
	}
	proxy.ServeHTTP(w, r)
}
