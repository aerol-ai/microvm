package cluster

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The admitted-key rule on internal calls (plans/kubectl-style-cluster-ops.md
// §5, Codex CEO finding 6).
//
//	server ─► every 7002 request: deny set (node ID) ─► tombstones (cert key)
//	                              ─► admitted key for the node ID, when it has one
//	worker ─► every 7002 request: deny set ─► tombstones (both mirrored)
//
// A worker mirrors only the tombstones, not every admitted key: a join on a
// 2,000-node fleet would otherwise push the whole admitted table to every
// worker. Tombstones are enough for the case that matters, an old cert of a
// reused node ID: a join can take an ID only after `aerolvm delete node`
// (opAdmitNode refuses an ID held by another key), and the delete
// tombstones the admitted key and, by identity, every cert for the ID
// issued before it. The second covers a node deleted before it was ever
// admitted, whose key nobody knows (J7).

// denyHitKey counts internal calls refused for their cert key.
const denyHitKey = "key"

// PeerKeyChecker reports whether a peer's cert key may make internal calls.
// Implemented by Cluster (admitted keys + tombstones) and Agent
// (tombstones). Not part of Client: Noop has no peers.
type PeerKeyChecker interface {
	CheckPeerKey(nodeID string, leaf *x509.Certificate) error
}

// RefusePeerKey runs c's key check for the public API's internal routes.
func RefusePeerKey(c Client, nodeID string, leaf *x509.Certificate) error {
	checker, ok := c.(PeerKeyChecker)
	if !ok || leaf == nil {
		return nil
	}
	return checker.CheckPeerKey(strings.TrimSpace(nodeID), leaf)
}

// CheckPeerKey is the server's rule: tombstones, then the admitted key.
func (c *Cluster) CheckPeerKey(nodeID string, leaf *x509.Certificate) error {
	if c == nil || c.fsm == nil {
		return nil
	}
	if err := c.fsm.peerTrustSnapshot().checkPeerCert(nodeID, leaf, time.Now().UnixNano()); err != nil {
		c.denyHits.hit(denyHitKey, nodeID)
		return err
	}
	return nil
}

// CheckPeerKey is the worker's rule: the mirrored tombstones, by key and
// by identity (a cert for the ID issued before its node was deleted).
func (a *Agent) CheckPeerKey(nodeID string, leaf *x509.Certificate) error {
	if a == nil || leaf == nil {
		return nil
	}
	now := time.Now().UnixNano()
	if a.deny.revokedKey(CertKeyHash(leaf), now) || a.deny.oldCert(nodeID, leaf.NotBefore, now) {
		a.denyHits.hit(denyHitKey, nodeID)
		return ErrPeerKeyRevoked
	}
	return nil
}

// peerKeyCheck is the internal listener's form of the check.
type peerKeyCheck func(nodeID string, leaf *x509.Certificate) error

// SetPeerKeyCheck installs the cert-key check; nil removes it.
func (s *internalServer) SetPeerKeyCheck(fn peerKeyCheck) {
	if s == nil {
		return
	}
	if fn == nil {
		s.peerKey.Store(nil)
		return
	}
	s.peerKey.Store(&fn)
}

// AdmittedNode returns nodeID's admitted record from this server's FSM.
func (c *Cluster) AdmittedNode(nodeID string) (AdmittedNode, bool) {
	if c == nil || c.fsm == nil {
		return AdmittedNode{}, false
	}
	return c.fsm.admittedNode(strings.TrimSpace(nodeID))
}

// peerJoinSentinels are restored from a peer's error answer, so the
// renewer and adopt can tell "try another server" from "stop".
var peerJoinSentinels = []error{
	ErrNoCASigner, ErrNotAdmitted, ErrPeerNotServer, ErrJoinKeyRevoked, ErrJoinKeyInUse,
	ErrRekeyConflict, ErrPeerKeyRevoked, ErrPeerKeyNotAdmitted, ErrPeerDeleted, ErrClusterVersion,
	ErrJoinTTLNeedsWrappedCustody, ErrJoinTTLInvalid, ErrJoinBadRequest,
}

// peerJoinError restores a sentinel from a peer's status and message.
func peerJoinError(status int, message string) error {
	message = strings.TrimSpace(message)
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(message), &body) == nil && body.Error != "" {
		message = body.Error
	}
	for _, sentinel := range peerJoinSentinels {
		if strings.Contains(message, sentinel.Error()) {
			return fmt.Errorf("%w (%s)", sentinel, message)
		}
	}
	return statusError{status: status, message: message}
}

// postPeerJSON posts in to endpoint with this node's PAT over mTLS and
// decodes a 2xx body into out.
func postPeerJSON(ctx context.Context, client *http.Client, endpoint, selfID, pat string, in, out any) error {
	if client == nil {
		return ErrPeerInternalURLRequired
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cluster: build peer request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	SetPeerNodeIDHeader(req, selfID)
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cluster: peer request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return peerJoinError(resp.StatusCode, string(msg))
	}
	return decodeControlPlaneJSON(resp.Body, out)
}

// isPeerRetryable reports whether another server may answer what this one
// refused: it holds no CA key, or it is not ready.
func isPeerRetryable(err error) bool {
	var se statusError
	return errors.Is(err, ErrNoCASigner) || errors.Is(err, ErrNotLeader) ||
		(errors.As(err, &se) && se.status == http.StatusServiceUnavailable)
}
