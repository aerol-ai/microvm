package cluster

// The server-key ring gate (plans/customer-key-custody.md §13, eng D26).
//
// `sandboxd key rotate --stage` turns the server-key file into a ring that
// older builds refuse to boot from, and once a staged key is promoted every
// node seals blobs that name their key, which older builds cannot open. So
// the stage refuses until every live member, workers and ingress included
// (they hold sealed rows too), advertises a build that reads both. The CLI
// asks the local daemon over the API (the members response carries this
// answer), so the boot-window rule of liveMembersAtLeast applies: a node
// that has just restarted and knows only itself does not open the gate.

// ServerKeyRingGate is implemented by the cluster clients that can answer;
// the single-node Noop does not (a single node has no one to wait for).
type ServerKeyRingGate interface {
	ServerKeyRingAllowed() bool
}

// ServerKeyRingAllowed reports whether every live member reads a server-key
// ring and key-id sealed blobs.
func (c *Cluster) ServerKeyRingAllowed() bool {
	if c == nil {
		return false
	}
	return c.gossip.liveMembersAtLeast(ServerKeyRingFSMOpsVersion)
}

// ServerKeyRingAllowed is the same gate on a worker or ingress node.
func (a *Agent) ServerKeyRingAllowed() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(ServerKeyRingFSMOpsVersion)
}
