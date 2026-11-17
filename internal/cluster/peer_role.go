package cluster

import (
	"crypto/x509"
	"strings"
)

// Node certificates get only what their role needs (least privilege). A
// peer that calls as itself is a node principal (pkg/api), and what it may
// do depends on the role it was admitted with:
//
//	server (and mixed)   the operator's powers, under its own name
//	worker, ingress      the node-to-node routes, and the few public routes
//	                     that grant its role (pkg/api/v1 routes.go)
//	unknown              the same as worker and ingress
//
// The role is read from what the cluster signed or decided, never from
// gossip, which any member can claim anything in:
//
//	server node  ─► its FSM's admitted record ─► Raft membership ─► the cert
//	other nodes  ─► the cert (they hold no FSM)
//
// The certificate's role is the cluster CA's DNS:role:<role>, which the
// join service signs from the join token's role, or an external CA's one
// aerolvm-role:<role> URI (ExtractPeerRole). A certificate signed before
// roles were (cluster-sign-node.sh) names none: on a server, the admitted
// record or Raft membership still names the role; elsewhere it is unknown,
// and unknown gets the least.

// PeerRoleReader is what a server node knows about a peer's role beyond
// its certificate: its admitted record and Raft membership. Implemented by
// Cluster; an Agent holds neither, so it reads the certificate alone.
type PeerRoleReader interface {
	AdmittedPeerRole(nodeID string) (string, bool)
}

// PeerRole returns the role nodeID was admitted with, as this node can
// tell: JoinRoleServer, JoinRoleWorker, JoinRoleIngress, or "" when
// nothing says. leaf is the peer's verified certificate.
func PeerRole(c Client, nodeID string, leaf *x509.Certificate) string {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ""
	}
	if reader, ok := c.(PeerRoleReader); ok {
		if role, ok := reader.AdmittedPeerRole(nodeID); ok {
			return role
		}
	}
	return ExtractPeerRole(leaf)
}

// AdmittedPeerRole is a server's answer: the admitted record's role when
// there is one (it is what every server-only check reads, Codex eng
// finding 1), else server for a configured Raft server (a scripted cluster
// before adopt, whose certificates name no role). It reports false when
// neither says, and PeerRole falls back to the certificate.
func (c *Cluster) AdmittedPeerRole(nodeID string) (string, bool) {
	if c == nil || c.fsm == nil {
		return "", false
	}
	if rec, ok := c.fsm.admittedNode(nodeID); ok && ValidJoinRole(rec.Role) {
		return rec.Role, true
	}
	if c.raft == nil || c.raft.raft == nil {
		return "", false
	}
	if _, ok := c.configuredServer(nodeID); ok {
		return JoinRoleServer, true
	}
	return "", false
}

// PeerIsServer reports whether PeerRole names nodeID a server.
func PeerIsServer(c Client, nodeID string, leaf *x509.Certificate) bool {
	return PeerRole(c, nodeID, leaf) == JoinRoleServer
}
