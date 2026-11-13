package cluster

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
)

// Join by certificate (external-CA mode, C23, plan §15.2.1). The pod's
// certificate comes from the bank's issuer through cert-manager, so there
// is no token: the certificate is the credential.
//
//	pod ─► POST JoinByCertPath on the join port (7003), with its certificate
//	server: the handshake chained it to the bank's CA
//	      ─► node:<id> and exactly one aerolvm-role:<role> ─► build version
//	      ─► dial-back ─► opAdmitNodeByCert (key pinned; a revoked key or an
//	         ID holding another key is refused) ─► the bundle, without a
//	         certificate or a CA key (none exists in this mode)
//
// A server joins Raft the way a token-joined one does: once it is in
// gossip, the leader's voter auto-join adds it.

var (
	// ErrExternalCAMode refuses what needs a CA key in external-CA mode: a
	// token join, a new join token, a certificate renewal.
	ErrExternalCAMode = errors.New("cluster: this cluster takes its certificates from an external CA (cert-manager), so it signs none; join by certificate")
	// ErrJoinByCertOff is a join by certificate on a cluster that is not in
	// external-CA mode.
	ErrJoinByCertOff = errors.New("cluster: join by certificate needs the external-CA mode")
	// ErrJoinCertRequired is a join by certificate with no client
	// certificate the cluster's CA signed.
	ErrJoinCertRequired = errors.New("cluster: a join by certificate needs a client certificate the cluster's CA signed")
)

// JoinByCertRequest is the body of a join by certificate: what a token join
// sends but the token, the node ID and role (the certificate's) and the CSR
// (the certificate is already signed).
type JoinByCertRequest struct {
	Version       string     `json:"version"`
	Ports         *JoinPorts `json:"ports,omitempty"`
	FSMOpsVersion int        `json:"fv,omitempty"`
}

// certJoinIdentity reads the node ID and its one role from a certificate.
func certJoinIdentity(leaf *x509.Certificate) (string, string, error) {
	if leaf == nil {
		return "", "", fmt.Errorf("%w: no client certificate", ErrJoinBadRequest)
	}
	nodeID := ExtractPeerNodeID(leaf)
	if !ValidJoinNodeID(nodeID) {
		return "", "", fmt.Errorf("%w: the certificate names no valid node:<id> (%q)", ErrJoinNodeIDInvalid, nodeID)
	}
	roles := ExtractCertRoles(leaf)
	if len(roles) != 1 {
		return "", "", fmt.Errorf("%w: the certificate must name exactly one %s<role>, not %d", ErrJoinBadRequest, certRoleSANprefix, len(roles))
	}
	if !ValidJoinRole(roles[0]) {
		return "", "", fmt.Errorf("%w: role %q", ErrJoinBadRequest, roles[0])
	}
	return nodeID, roles[0], nil
}

// JoinByCert admits the node whose verified certificate is leaf. The join
// port's handshake already chained it to the bank's CA.
func (c *Cluster) JoinByCert(ctx context.Context, leaf *x509.Certificate, req JoinByCertRequest, source netip.Addr) (JoinResponse, error) {
	if !c.cfg.ClusterExternalCA {
		return JoinResponse{}, ErrJoinByCertOff
	}
	nodeID, role, err := certJoinIdentity(leaf)
	if err != nil {
		return JoinResponse{}, err
	}
	if !c.joinVersionAllowed(req.Version, req.FSMOpsVersion) {
		return JoinResponse{}, fmt.Errorf("%w: %q (cluster runs %s)", ErrJoinVersion, req.Version, c.joinVersion())
	}
	keyHash, err := PublicKeyHash(leaf.PublicKey)
	if err != nil {
		return JoinResponse{}, fmt.Errorf("%w: %v", ErrJoinBadRequest, err)
	}
	ports, err := dialBackPorts(role, req.Ports)
	if err != nil {
		return JoinResponse{}, err
	}
	results, ok := dialBack(ctx, c.joinDial, source, ports)
	if !ok {
		return JoinResponse{}, &JoinDialBackError{Results: results}
	}
	written, err := c.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteAdmitByCert, Admit: &JoinAdmitCommand{
		NodeID: nodeID, Role: role, KeyHash: keyHash, NotAfterUnixNano: leaf.NotAfter.UnixNano(),
	}})
	if err != nil {
		return JoinResponse{}, err
	}
	admitted := JoinAdmitResult{Node: AdmittedNode{NodeID: nodeID, Role: role}}
	if written.Admit != nil {
		admitted = *written.Admit
	}
	out := JoinResponse{
		NodeID: nodeID, Role: admitted.Node.Role, ClusterID: c.externalCAClusterID(),
		GossipKey: c.cfg.ClusterGossipSecretKey, BootstrapPeers: c.bootstrapPeers(), JoinURLs: c.joinURLs(),
		Credentials: c.credentialBundle(), NotAfter: leaf.NotAfter.UTC(), Version: c.joinVersion(),
		Replay: admitted.Replay, DialBack: results,
	}
	c.addJoinPAT(&out, admitted.Node.IsServer())
	if c.logger != nil {
		c.logger.Info("cluster: node joined by certificate", "node_id", nodeID, "role", out.Role,
			"source", source.String(), "replay", admitted.Replay, "replaced_deny", admitted.ReplacedDeny)
	}
	return out, nil
}

// externalCAClusterID names the cluster by its CA, as a token join does:
// the first certificate of the bank's CA bundle.
func (c *Cluster) externalCAClusterID() string {
	if c.tls == nil {
		return ""
	}
	block, _ := pem.Decode(c.tls.caPEM)
	if block == nil {
		return ""
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return CACertHash(ca)
}

// refuseInExternalCAMode answers the paths that need a CA key.
func (c *Cluster) refuseInExternalCAMode() error {
	if c != nil && c.cfg.ClusterExternalCA {
		return ErrExternalCAMode
	}
	return nil
}

// adoptSelfByCert is Adopt in external-CA mode: there is no CA key to
// fetch, and every other node joins by its own certificate, so the seed
// admits itself the same way, by the certificate it serves. The operator
// calls it once the seed leads; running it again changes nothing.
func (c *Cluster) adoptSelfByCert(ctx context.Context) (AdoptResponse, error) {
	out := AdoptResponse{ClusterID: c.externalCAClusterID(), CASource: "external", Admitted: []string{}, Already: []string{}, Skipped: map[string]string{}}
	if c.tls == nil {
		return out, ErrJoinCertRequired
	}
	pair, err := c.tls.certificateForHandshake()
	if err != nil {
		return out, err
	}
	leaf, err := leafCertificate(pair)
	if err != nil {
		return out, err
	}
	nodeID, role, err := certJoinIdentity(leaf)
	if err != nil {
		return out, err
	}
	keyHash, err := PublicKeyHash(leaf.PublicKey)
	if err != nil {
		return out, err
	}
	written, err := c.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteAdmitByCert, Admit: &JoinAdmitCommand{
		NodeID: nodeID, Role: role, KeyHash: keyHash, NotAfterUnixNano: leaf.NotAfter.UnixNano(),
	}})
	if err != nil {
		return out, err
	}
	if written.Admit != nil && written.Admit.Replay {
		out.Already = append(out.Already, nodeID)
	} else {
		out.Admitted = append(out.Admitted, nodeID)
	}
	if c.logger != nil {
		c.logger.Info("cluster: seed admitted by its certificate", "node_id", nodeID, "role", role, "already", len(out.Already) > 0)
	}
	return out, nil
}

// selfKeyHash is the key hash of the certificate this server serves with,
// or "" when it has none.
func (c *Cluster) selfKeyHash() string {
	if c.tls == nil {
		return ""
	}
	pair, err := c.tls.certificateForHandshake()
	if err != nil {
		return ""
	}
	leaf, err := leafCertificate(pair)
	if err != nil {
		return ""
	}
	h, err := PublicKeyHash(leaf.PublicKey)
	if err != nil {
		return ""
	}
	return h
}
