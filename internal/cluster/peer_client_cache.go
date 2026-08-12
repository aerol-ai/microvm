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

func (c *peerClientCache) get(base *http.Client, nodeID string, rejectLegacy bool) *http.Client {
	if c == nil {
		return ClientForPeer(base, nodeID, rejectLegacy)
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
	client := ClientForPeer(base, nodeID, rejectLegacy)
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
	c.m.Delete(nodeID)
}
