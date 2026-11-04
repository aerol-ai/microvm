package cluster

// The audit caller write gate (plans/identity-and-access.md §5.8, §12 I6).
//
// An audit record's hash covers every field. A build that predates the
// caller field drops it when it decodes a record and computes a different
// hash, so a node that wrote callers cannot be rolled back to that build
// (its strict boot verification fails), and an older reader of the record
// sees a chain that does not verify. During a rolling upgrade both kinds of
// node exist at once, so no node writes the field until every live member,
// workers and ingress included (they read peers' records too), advertises
// the release that understands it. Until then records are written exactly
// as before.
//
// The gate is evaluated on every audit record, so it reads two atomics the
// member index refreshes on membership churn: never a lock, a scan or a
// network call. Single-node mode does not ask (the service writes at once).

// AuditCallerGate is implemented by cluster clients that can tell whether
// every member can read the audit caller field. The service layer asserts
// it rather than adding it to Client: the single-node Noop does not
// implement it, so a cluster-mode service that has not attached its real
// client yet stays closed.
type AuditCallerGate interface {
	AuditCallerWritesAllowed() bool
}

// AuditCallerWritesAllowed reports whether this node may write the audit
// caller field.
func (c *Cluster) AuditCallerWritesAllowed() bool {
	if c == nil {
		return false
	}
	return c.gossip.liveMembersAtLeast(auditCallerFSMOpsVersion)
}

// AuditCallerWritesAllowed reports whether this node may write the audit
// caller field. Workers and ingress nodes gate on the same gossip view.
func (a *Agent) AuditCallerWritesAllowed() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(auditCallerFSMOpsVersion)
}

// liveMembersAtLeast reports whether every alive member advertises fv >= v
// and this node has actually seen its cluster.
//
// The second condition closes the boot window. A node that has just
// restarted knows only itself until its first join completes; judged on
// that view alone it would open the gate and write callers into its log,
// and if the restart was the first step of an upgrade that is then rolled
// back, that log would no longer verify. So a node that is alone opens the
// gate only when it has nowhere to join (no configured or remembered
// peers): the first node of a new cluster, or a cluster of one.
func (g *gossipNode) liveMembersAtLeast(v int) bool {
	if g == nil {
		return false
	}
	floor, alive := g.currentMemberIndex().featureFloor()
	if alive == 0 || floor < int64(v) {
		return false
	}
	if alive > 1 {
		return true
	}
	return len(g.rejoinPeers()) == 0
}
