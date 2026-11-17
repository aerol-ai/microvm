package cluster

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
)

// Who writes cluster-wide settings on the internal write routes (node
// certificates get only what their role needs, peer_role.go):
//
//	API tokens        servers and gateways (IsTokenWritePeer)
//	egress profiles   servers and gateways
//	team quotas       servers and gateways
//	warm pools        servers and gateways (a gateway's agent-sandbox API
//	                  also keeps its warm depths there)
//	identity          servers and gateways; a worker only keeps the
//	                  signing keys: it makes the deployment's first key,
//	                  and reseals the keys onto a new server key
//
// A gateway is the API edge: it takes these calls from callers it
// authenticated, as it does token writes. A worker sends its callers'
// writes on to a server with the caller's own credential (pkg/api/v1
// server_tier.go), so its own certificate needs none of them. Only a
// server answers these routes; a worker or gateway that receives one
// refuses it rather than send it on as itself.

// ErrIdentityWriterRefused is an identity write a node may not send: a
// role write or a key change other than the first key or a reseal, from a
// node that is not a server or a gateway.
var ErrIdentityWriterRefused = errors.New("cluster: only servers and gateways write identity roles and rotate keys")

// identityCodeWriterRefused carries ErrIdentityWriterRefused in a 200 body.
const identityCodeWriterRefused = "writer_refused"

// IsSettingsWritePeer reports whether peerID, whose verified certificate is
// leaf, may write cluster-wide settings: a server or a gateway by its
// admitted role (PeerRole).
func (c *Cluster) IsSettingsWritePeer(peerID string, leaf *x509.Certificate) bool {
	switch PeerRole(c, peerID, leaf) {
	case JoinRoleServer, JoinRoleIngress:
		return true
	}
	return false
}

// CheckIdentityWriter refuses an identity write peerID may not send. A
// server or gateway may send any. Anyone else may only keep the signing
// keys (identityKeyUpkeep), judged against this server's key set at the
// write's expected generation: the set at a generation is the same on every
// server, and the leader's compare-and-set applies the write only on top of
// that generation. A server that has not caught up to it answers a keys
// conflict, so the writer reads the set again, as it does after any lost
// compare-and-set.
func (c *Cluster) CheckIdentityWriter(peerID string, leaf *x509.Certificate, req IdentityWriteRequest) error {
	if c.IsSettingsWritePeer(peerID, leaf) {
		return nil
	}
	if c == nil || c.fsm == nil {
		return fmt.Errorf("%w: node holds no placement state", ErrIdentityWriterRefused)
	}
	err := identityKeyUpkeep(c.fsm.identityKeys(), req)
	if err != nil && errors.Is(err, ErrIdentityWriterRefused) && c.logger != nil {
		c.logger.Warn("cluster: refused an identity write from a node that is not a server or gateway",
			"peer", strings.TrimSpace(peerID), "role", PeerRole(c, peerID, leaf))
	}
	return err
}

// identityKeyUpkeep allows the two key writes a worker makes
// (internal/service identity.go and identity_push.go): the deployment's
// first signing key when cur has no active key, and a reseal, which keeps
// every key, its id, public key and times, and changes only the sealed
// private part. Anything else, and every role write, is refused.
func identityKeyUpkeep(cur cloudidentity.KeySet, req IdentityWriteRequest) error {
	if req.Keys == nil || req.Role != nil || req.DeleteRole {
		return fmt.Errorf("%w: this node may not write identity roles", ErrIdentityWriterRefused)
	}
	if req.Keys.ExpectedGeneration != cur.Generation {
		return fmt.Errorf("%w: generation %d, this server has %d", ErrIdentityKeysConflict, req.Keys.ExpectedGeneration, cur.Generation)
	}
	next := req.Keys.Keys
	if _, ok := cur.Active(); !ok {
		if len(next) == 1 && next[0].Active() {
			return nil
		}
		return fmt.Errorf("%w: a first key write holds exactly one active key", ErrIdentityWriterRefused)
	}
	if len(next) != len(cur.Keys) {
		return fmt.Errorf("%w: this node may only reseal the signing keys", ErrIdentityWriterRefused)
	}
	for i, k := range next {
		was := cur.Keys[i]
		if k.ID != was.ID || !bytes.Equal(k.PublicJWK, was.PublicJWK) ||
			k.CreatedUnixNano != was.CreatedUnixNano || k.RetiredUnixNano != was.RetiredUnixNano {
			return fmt.Errorf("%w: this node may only reseal the signing keys", ErrIdentityWriterRefused)
		}
	}
	return nil
}
