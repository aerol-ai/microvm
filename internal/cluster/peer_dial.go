package cluster

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ErrPeerInternalURLRequired is returned when local TLS is configured but the
// peer has no InternalURL. Callers must not fall back to public APIURL+PAT.
var ErrPeerInternalURLRequired = errors.New("cluster: peer InternalURL required (mTLS fail-closed)")

// ErrPeerInternalURLInvalid is returned before any credentials are attached
// when gossip advertises a non-HTTPS or malformed internal endpoint.
var ErrPeerInternalURLInvalid = errors.New("cluster: peer InternalURL must be an absolute https URL")

// PeerDial selects the peer HTTP client and internal URL. Cluster peer RPCs
// are always mTLS and fail closed when either side is missing.
//
// Prefer PeerDialCached (or Cluster/Agent.PeerDialMember) so mTLS VerifyPeer
// transport clones are reused per node.
func PeerDial(m Member, internalClient *http.Client) (client *http.Client, base string, err error) {
	return PeerDialCached(m, internalClient, nil)
}

// PeerDialCached is PeerDial with an optional prebuilt per-peer mTLS client.
// When cached is non-nil it is returned as-is (no transport clone). Otherwise
// a VerifyPeerCertificate client is built via ClientForPeer.
func PeerDialCached(m Member, internalClient, cached *http.Client) (client *http.Client, base string, err error) {
	internalURL := strings.TrimSpace(m.InternalURL)
	if internalClient == nil || internalURL == "" {
		return nil, "", ErrPeerInternalURLRequired
	}
	if err := validatePeerInternalURL(internalURL); err != nil {
		return nil, "", ErrPeerInternalURLInvalid
	}
	if cached != nil {
		return cached, internalURL, nil
	}
	// Bind dial verification to the expected gossip node id when the peer cert
	// carries DNS:node:<id>.
	return ClientForPeer(internalClient, m.NodeID), internalURL, nil
}

func validatePeerInternalURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") || strings.TrimSpace(u.Host) == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return ErrPeerInternalURLInvalid
	}
	return nil
}

// PeerDialPath is PeerDial plus a path suffix (e.g. /v1/cluster/internal/secrets).
func PeerDialPath(m Member, internalClient *http.Client, path string) (*http.Client, string, error) {
	client, base, err := PeerDial(m, internalClient)
	if err != nil {
		return nil, "", err
	}
	return client, strings.TrimRight(base, "/") + path, nil
}
