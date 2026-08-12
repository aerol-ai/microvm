package cluster

import (
	"errors"
	"net/http"
	"strings"
)

// ErrPeerInternalURLRequired is returned when local TLS is configured but the
// peer has no InternalURL. Callers must not fall back to public APIURL+PAT.
var ErrPeerInternalURLRequired = errors.New("cluster: peer InternalURL required (mTLS fail-closed)")

// PeerDial selects the peer HTTP client and base URL. When internalClient is
// non-nil (cluster TLS loaded), dial is fail-closed: InternalURL is required
// and the public APIURL is never used. This is the single selection rule for
// list, secret replication, audit, and other peer RPCs.
//
// Prefer PeerDialCached (or Cluster/Agent.PeerDialMember) so mTLS VerifyPeer
// transport clones are reused per node.
func PeerDial(m Member, publicClient, internalClient *http.Client) (client *http.Client, base string, err error) {
	// Legacy shared-SAN-only certs are refused for all cluster peer dials.
	return PeerDialCached(m, publicClient, internalClient, nil, true)
}

// PeerDialCached is PeerDial with an optional prebuilt per-peer mTLS client.
// When cached is non-nil it is returned as-is (no transport clone). Otherwise
// a VerifyPeerCertificate client is built via ClientForPeer. rejectLegacy
// should be true for production peer traffic (legacy shared-SAN-only certs
// are refused).
func PeerDialCached(m Member, publicClient, internalClient, cached *http.Client, rejectLegacy bool) (client *http.Client, base string, err error) {
	internalURL := strings.TrimSpace(m.InternalURL)
	apiURL := strings.TrimSpace(m.APIURL)
	if internalClient != nil {
		if internalURL == "" {
			return nil, "", ErrPeerInternalURLRequired
		}
		if cached != nil {
			return cached, internalURL, nil
		}
		// Bind dial verification to the expected gossip node id when the peer
		// cert carries DNS:node:<id>.
		return ClientForPeer(internalClient, m.NodeID, rejectLegacy), internalURL, nil
	}
	if publicClient != nil && apiURL != "" {
		return publicClient, apiURL, nil
	}
	if apiURL != "" {
		return &http.Client{}, apiURL, nil
	}
	return nil, "", errors.New("cluster: no reachable peer URL")
}

// PeerDialPath is PeerDial plus a path suffix (e.g. /v1/cluster/internal/secrets).
func PeerDialPath(m Member, publicClient, internalClient *http.Client, path string) (*http.Client, string, error) {
	client, base, err := PeerDial(m, publicClient, internalClient)
	if err != nil {
		return nil, "", err
	}
	return client, strings.TrimRight(base, "/") + path, nil
}

// PeerDialPathCached is PeerDialCached plus a path suffix.
func PeerDialPathCached(m Member, publicClient, internalClient, cached *http.Client, rejectLegacy bool, path string) (*http.Client, string, error) {
	client, base, err := PeerDialCached(m, publicClient, internalClient, cached, rejectLegacy)
	if err != nil {
		return nil, "", err
	}
	return client, strings.TrimRight(base, "/") + path, nil
}
