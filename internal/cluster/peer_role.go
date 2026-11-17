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
//	server node  ─► server only while a configured Raft server; otherwise
//	                the admitted record's role, else the certificate's
//	other nodes  ─► the certificate (they hold no FSM and no Raft view)
//
// On a server, the server role always needs Raft membership: an admitted
// record or a certificate that says server, for a node Raft does not
// count, reads as no role. Raft membership is what every server-only check
// already binds to (peerIsServer), and it cannot be claimed in gossip.
//
// The certificate's role is the cluster CA's DNS:role:<role>, which the
// join service signs from the join token's role, or an external CA's
// aerolvm-role:<role> URI (ExtractPeerRole; both forms must agree). A
// certificate signed before roles were (cluster-sign-node.sh) names none:
// on a server, the admitted record or Raft membership still names the
// role; elsewhere it is unknown, and unknown gets the least.

// PeerRoleReader is what a server node knows about a peer beyond its
// certificate: its admitted record and Raft membership. Implemented by
// Cluster; an Agent holds neither, so it reads the certificate alone.
type PeerRoleReader interface {
	PeerRoleFor(nodeID, certRole string) string
}

// PeerRole returns the role nodeID was admitted with, as this node can
// tell: JoinRoleServer, JoinRoleWorker, JoinRoleIngress, or "" when
// nothing says. leaf is the peer's verified certificate.
func PeerRole(c Client, nodeID string, leaf *x509.Certificate) string {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ""
	}
	certRole := ExtractPeerRole(leaf)
	if reader, ok := c.(PeerRoleReader); ok {
		return reader.PeerRoleFor(nodeID, certRole)
	}
	return certRole
}

// PeerRoleFor is a server's answer (see the table above): server only for
// a configured Raft server whose admitted record, if any, says server; the
// admitted record's other roles as they are; otherwise the certificate's
// role, never server.
func (c *Cluster) PeerRoleFor(nodeID, certRole string) string {
	if c == nil || c.fsm == nil {
		return ""
	}
	nodeID = strings.TrimSpace(nodeID)
	inRaft := c.raft != nil && c.raft.raft != nil
	if inRaft {
		_, inRaft = c.configuredServer(nodeID)
	}
	if rec, ok := c.fsm.admittedNode(nodeID); ok && ValidJoinRole(rec.Role) {
		if rec.Role == JoinRoleServer && !inRaft {
			return ""
		}
		return rec.Role
	}
	if inRaft {
		return JoinRoleServer
	}
	if certRole == JoinRoleServer {
		return ""
	}
	return certRole
}

// PeerIsServer reports whether PeerRole names nodeID a server.
func PeerIsServer(c Client, nodeID string, leaf *x509.Certificate) bool {
	return PeerRole(c, nodeID, leaf) == JoinRoleServer
}
