package v1

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
)

func clusterMemberSupportsRuntime(m cluster.Member, runtimeName string) bool {
	runtimeName = strings.TrimSpace(runtimeName)
	if runtimeName == "" || len(m.Capacity.SupportedRuntimes) == 0 {
		return true
	}
	for _, r := range m.Capacity.SupportedRuntimes {
		if r == runtimeName {
			return true
		}
	}
	return false
}

func clusterSelfCanOwnSandbox(c cluster.Client) bool {
	if c == nil {
		return true
	}
	selfID := c.SelfNodeID()
	for _, m := range c.Members() {
		if m.NodeID == selfID {
			return clusterMemberCanOwnSandbox(m.Role)
		}
	}
	return true
}

func clusterPeerURL(apiURL, requestURI string) string {
	return strings.TrimRight(apiURL, "/") + requestURI
}

func copyHeaderValues(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
