package v1

import (
	"errors"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
)

type clusterPeerDialer interface {
	PeerDialMember(cluster.Member) (*http.Client, string, error)
}

func dialClusterPeer(c cluster.Client, member cluster.Member) (*http.Client, string, error) {
	dialer, ok := c.(clusterPeerDialer)
	if !ok {
		return nil, "", cluster.ErrPeerInternalURLRequired
	}
	client, base, err := dialer.PeerDialMember(member)
	if err != nil {
		return nil, "", err
	}
	if client == nil || strings.TrimSpace(base) == "" {
		return nil, "", errors.New("cluster: peer mTLS client unavailable")
	}
	return client, strings.TrimRight(base, "/"), nil
}

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

func copyHeaderValues(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
