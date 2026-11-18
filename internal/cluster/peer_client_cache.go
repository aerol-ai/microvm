package cluster

import (
	"net/http"
	"strings"
	"sync"
)

// peerClientCache holds per-node mTLS HTTP clients so VerifyPeerCertificate
// transport clones are built once per peer instead of on every dial.
type peerClientCache struct {
	m sync.Map // nodeID -> *http.Client
}

func (c *peerClientCache) get(base *http.Client, nodeID string) *http.Client {
	return c.getWith(base, nodeID, ClientForPeer)
}

// getWith is get for a cache whose clients make builds.
func (c *peerClientCache) getWith(base *http.Client, nodeID string, make func(*http.Client, string) *http.Client) *http.Client {
	if c == nil {
		return make(base, nodeID)
	}
	nodeID = strings.TrimSpace(nodeID)
	if base == nil || nodeID == "" {
		return base
	}
	if v, ok := c.m.Load(nodeID); ok {
		if client, ok := v.(*http.Client); ok {
			return client
		}
	}
	client := make(base, nodeID)
	if client == nil || client == base {
		return client
	}
	actual, _ := c.m.LoadOrStore(nodeID, client)
	if cached, ok := actual.(*http.Client); ok {
		return cached
	}
	return client
}

func (c *peerClientCache) invalidate(nodeID string) {
	if c == nil {
		return
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	if cached, ok := c.m.LoadAndDelete(nodeID); ok {
		if client, ok := cached.(*http.Client); ok && client != nil {
			client.CloseIdleConnections()
		}
	}
}
