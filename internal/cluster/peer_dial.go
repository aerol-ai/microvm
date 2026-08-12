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
func PeerDial(m Member, publicClient, internalClient *http.Client) (client *http.Client, base string, err error) {
	internalURL := strings.TrimSpace(m.InternalURL)
	apiURL := strings.TrimSpace(m.APIURL)
	if internalClient != nil {
		if internalURL == "" {
			return nil, "", ErrPeerInternalURLRequired
		}
		// Bind dial verification to the expected gossip node id when the peer
		// cert carries DNS:node:<id> (legacy-only certs remain soft-compat).
		return ClientForPeer(internalClient, m.NodeID), internalURL, nil
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
