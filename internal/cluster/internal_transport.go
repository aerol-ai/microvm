package cluster

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Dead-peer bounds for the internal channel (Phase 3 zone-loss drill). A
// peer in a zone that drops off the network answers nothing: no RST, no
// FIN, so without these a call to it waits for whatever sits above it.
// Live on kind, a create forwarded to a worker one second before gossip
// marked it dead waited 3 minutes on a pooled connection, and a
// reservation sent to a cut server took the whole 5 s commit budget.
//
//   - internalDialTimeout: a peer in the cell answers a SYN in
//     milliseconds; 3 s leaves a slow machine plenty and still lets a
//     control-plane call move on to the next server inside its budget.
//   - internalTLSHandshakeTimeout: the same for the mTLS handshake.
//   - internalUserTimeout (TCP_USER_TIMEOUT, Linux): a connection whose sent
//     bytes go unacknowledged this long is closed by the kernel. A live
//     peer acknowledges at once even while it works on a long create, so
//     this only ends connections to a peer that is gone.
//   - internalKeepAlive: probes an idle connection (a forward waiting on a
//     long create, an exec stream) so one to a vanished peer fails in about
//     Idle + Interval*Count instead of the kernel's two hours.
const (
	internalDialTimeout         = 3 * time.Second
	internalTLSHandshakeTimeout = 5 * time.Second
	internalUserTimeout         = 15 * time.Second
)

var internalKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 5 * time.Second, Interval: 5 * time.Second, Count: 3}

// newInternalDialer is the dialer behind every internal-channel connection.
func newInternalDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:         internalDialTimeout,
		KeepAliveConfig: internalKeepAlive,
		Control:         setInternalUserTimeout,
	}
}

// newInternalTransport is the mTLS transport behind Cluster.internalClient
// and Agent.internalClient — the follower→leader commit channel. Keep-alives
// stay on and the idle pool is sized for concurrent fan-in so creates don't
// re-handshake mTLS under burst (warm-create-latency Tier 1 Phase 4).
//
// Sizing (C18, bench-full-5): a gateway at its share of a 500-worker cell's
// creates holds 40 to 170 requests at once to each server. With 16 idle
// per host, every connection past the 16th was closed on return and the
// next burst handshook again: 8% of a gateway's CPU, and 6% of the Raft
// leader's for the server side. 128 per host keeps them. The total bounds
// memory (an idle TLS connection is tens of KB, so about 50 MB at worst)
// while a gateway also proxies to many workers, a few connections each.
// New and NewAgent both build from here so the two call sites can't drift;
// transport_pool_test.go pins the sizing.
func newInternalTransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig:     tlsCfg,
		DialContext:         newInternalDialer().DialContext,
		TLSHandshakeTimeout: internalTLSHandshakeTimeout,
		DisableKeepAlives:   false,
		MaxIdleConns:        internalMaxIdleConns,
		MaxIdleConnsPerHost: internalMaxIdleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
	}
}

const (
	internalMaxIdleConns        = 1024
	internalMaxIdleConnsPerHost = 128
)
