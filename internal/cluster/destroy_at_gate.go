package cluster

// The destroy_at gate (plans/agent-sandbox-feature-parity.md L6).
//
// A lifecycle update that sets destroy_at is forwarded to the sandbox's
// owner as it came. An owner on a build before L6 decodes the body without
// the field and applies a lifecycle with no timers at all, so the update
// clears every timer the sandbox had. So a node takes destroy_at in a
// lifecycle update only once every live member, any role, runs a build with
// L6. L6 has no FSM op of its own; it ships in the same release as the
// token-port gate, so it names that version. Creates need no gate: the node
// that takes a create turns destroy_at into destroy_at_age before it passes
// the create on, and every build reads that.

// destroyAtFSMOpsVersion is the first build that understands destroy_at.
const destroyAtFSMOpsVersion = tokenPortFSMOpsVersion

// DestroyAtGate is implemented by the cluster clients that can answer; the
// single-node Noop does not (a single node forwards to no older owner).
type DestroyAtGate interface {
	DestroyAtAllowed() bool
}

// DestroyAtAllowed reports whether every live member understands destroy_at.
func (c *Cluster) DestroyAtAllowed() bool {
	if c == nil {
		return false
	}
	return c.gossip.liveMembersAtLeast(destroyAtFSMOpsVersion)
}

// DestroyAtAllowed is the same gate on a worker or ingress node.
func (a *Agent) DestroyAtAllowed() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(destroyAtFSMOpsVersion)
}
