package cluster

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

// proxyCache caches one ReverseProxy per peer identity and URL. The transport
// is supplied by the node-pinned HTTP client cache so connection reuse never
// crosses peer identities.
type proxyCache struct {
	mu      sync.RWMutex
	proxies map[string]*httputil.ReverseProxy
}

func newProxyCache() *proxyCache {
	return &proxyCache{proxies: make(map[string]*httputil.ReverseProxy)}
}

// getForPeer keeps the cache identity-bound: the same URL reached for a
// different expected node must not reuse a transport pinned to another leaf.
func (pc *proxyCache) getForPeer(nodeID, baseURL string, rt http.RoundTripper) (*httputil.ReverseProxy, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, errors.New("cluster: peer node id required")
	}
	if err := validatePeerInternalURL(baseURL); err != nil {
		return nil, err
	}
	if rt == nil {
		return nil, errors.New("cluster: peer mTLS transport unavailable")
	}
	cacheKey := strings.TrimSpace(nodeID) + "\x00" + baseURL
	pc.mu.RLock()
	if p, ok := pc.proxies[cacheKey]; ok {
		pc.mu.RUnlock()
		return p, nil
	}
	pc.mu.RUnlock()

	pc.mu.Lock()
	defer pc.mu.Unlock()
	if p, ok := pc.proxies[cacheKey]; ok {
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
		Transport: rt,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "cluster: forward to "+baseURL+" failed: "+err.Error(), http.StatusBadGateway)
		},
	}
	pc.proxies[cacheKey] = rp
	return rp, nil
}

// ForwardHTTP reverse-proxies r to target and writes the response into w. The
// PAT bearer header is preserved (httputil.ReverseProxy passes through
// headers by default; we only strip hop-by-hop ones).
//
// NodeID and InternalURL are required. The proxy transport is taken from the
// per-peer client cache, which pins the TLS leaf to node:<NodeID>.
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
	SetPeerNodeIDHeader(r, c.nodeID)
	forwardHTTPWithMetrics(c.mtlsProxies, c.ClientForPeer, target, w, r)
}

func forwardHTTPWithMetrics(mtlsProxies *proxyCache, peerClient func(string) *http.Client, target Endpoint, w http.ResponseWriter, r *http.Request) {
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
	if mtlsProxies == nil || peerClient == nil || strings.TrimSpace(target.NodeID) == "" || strings.TrimSpace(target.InternalURL) == "" {
		err = ErrPeerInternalURLRequired
		recordOwnerForwardTargetMiss("node_bound_internal_url_required")
		http.Error(w, ErrPeerInternalURLRequired.Error(), http.StatusServiceUnavailable)
		return
	}
	client := peerClient(target.NodeID)
	if client == nil || client.Transport == nil {
		err = errors.New("cluster: node-pinned mTLS client unavailable")
		recordOwnerForwardTargetMiss("peer_client_unavailable")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	err = servePeerProxy(mtlsProxies, target.NodeID, target.InternalURL, client.Transport, w, r)
}

func servePeerProxy(cache *proxyCache, nodeID, baseURL string, transport http.RoundTripper, w http.ResponseWriter, r *http.Request) error {
	if err := validatePeerInternalURL(baseURL); err != nil {
		http.Error(w, ErrPeerInternalURLInvalid.Error(), http.StatusBadGateway)
		return err
	}
	proxy, err := cache.getForPeer(nodeID, baseURL, transport)
	if err != nil {
		http.Error(w, "cluster: invalid peer URL: "+err.Error(), http.StatusBadGateway)
		return err
	}
	proxy.ServeHTTP(w, r)
	return nil
}
