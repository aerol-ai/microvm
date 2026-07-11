package cluster

import (
	"crypto/tls"
	"net/http"
	"time"
)

// newInternalTransport is the mTLS transport behind Cluster.internalClient
// and Agent.internalClient — the follower→leader commit channel. Keep-alives
// stay on and the idle pool is sized for concurrent promote fan-in so creates
// don't re-handshake mTLS under burst (warm-create-latency Tier 1 Phase 4).
// New and NewAgent both build from here so the two call sites can't drift;
// transport_pool_test.go pins the sizing.
func newInternalTransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   false,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	}
}

// newMTLSProxyTransport backs the owner API forwards (ReverseProxy). Same TLS
// config as the commit channel but a higher per-host idle pool — forwards are
// the steady-state hot path across cluster-internal hops, not the bursty raft
// leader-forward.
func newMTLSProxyTransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
}
