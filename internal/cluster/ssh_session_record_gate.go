package cluster

// The SSH session owner-record gate (UC-287 on a cluster).
//
// An SSH session the gateway on one node bridges to a sandbox another node
// owns used to be recorded on the gateway's node, which the sandbox's audit
// read never asks (it reaches the nodes that owned the sandbox, and never
// an ingress node). A build at sshSessionOwnerRecordFSMOpsVersion instead
// hands the record to the owner with the session's first bridged call
// (HeaderSSHGateway), and the owner writes it in the sandbox's audit. An
// older owner does not know the marker and would write nothing, so during
// a rolling upgrade the gateway keeps recording locally until every live
// member, ingress nodes included, advertises a build that honours it. The
// boot-window rule of liveMembersAtLeast applies: a node that has just
// restarted and knows only itself keeps recording locally too.

// SSHSessionRecordGate is implemented by the cluster clients that can
// answer; the single-node Noop does not (a single node bridges nothing).
type SSHSessionRecordGate interface {
	SSHSessionOwnerRecordAllowed() bool
}

// SSHSessionOwnerRecordAllowed reports whether every live member writes
// the ssh record of a session another node's gateway bridged to it.
func (c *Cluster) SSHSessionOwnerRecordAllowed() bool {
	if c == nil {
		return false
	}
	return c.gossip.liveMembersAtLeast(sshSessionOwnerRecordFSMOpsVersion)
}

// SSHSessionOwnerRecordAllowed is the same gate on a worker or ingress
// node, which is where most gateways run.
func (a *Agent) SSHSessionOwnerRecordAllowed() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(sshSessionOwnerRecordFSMOpsVersion)
}
