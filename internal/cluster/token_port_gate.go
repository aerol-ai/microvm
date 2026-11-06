package cluster

// The token-port gate (plans/agent-sandbox-feature-parity.md A2).
//
// A port exposed with visibility "token" keeps that visibility in the
// cluster's port record (opAddExposedPort), so a failover recreate gates it
// again. An older build decodes the record without the field: a failover
// through it would recreate the port as public, failing open. So a port may
// become token-gated only once every live member, any role, advertises a
// build that keeps the field (tokenPortFSMOpsVersion). The boot-window rule
// of liveMembersAtLeast applies: a node that has just restarted and knows
// only itself refuses too.

// TokenPortGate is implemented by the cluster clients that can answer; the
// single-node Noop does not (a single node has no older peer to fail over
// through).
type TokenPortGate interface {
	TokenPortsAllowed() bool
}

// TokenPortsAllowed reports whether every live member keeps a port's
// visibility through failover.
func (c *Cluster) TokenPortsAllowed() bool {
	if c == nil {
		return false
	}
	return c.gossip.liveMembersAtLeast(tokenPortFSMOpsVersion)
}

// TokenPortsAllowed is the same gate on a worker or ingress node.
func (a *Agent) TokenPortsAllowed() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(tokenPortFSMOpsVersion)
}
