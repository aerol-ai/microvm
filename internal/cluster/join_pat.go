package cluster

import "github.com/aerol-ai/microvm/pkg/volumes"

// What a join answer says about the operator PAT
// (plans/kubectl-style-cluster-ops.md §8, peer_cert_auth.go).
//
//	joiner's role       every live member at fv 14     an older member is live
//	server              pat_token                      pat_token
//	worker, ingress     pat_sha256 + volume scope      pat_token (as before)
//
// A server keeps the PAT: it already gets the CA key, and the operator's
// tools on it use the PAT. A worker or ingress node does not need it, and
// its token often sits in an autoscaler's or Terraform's user data for good
// (--ttl 0), so a leak of that token must not yield an admin credential that
// also works from outside.

// PATFreeJoin reports whether a join may leave the operator PAT out of a
// non-server's answer: every live member accepts a cert-only call, and the
// cluster cannot roll back to a build that does not. The active version
// moves only forward and only at finalize, so once it reaches the gate no
// rollback goes below it; before the first write, every Raft server must
// run the build.
func (c *Cluster) PATFreeJoin() bool {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return false
	}
	if !c.gossip.liveMembersAtLeast(peerCertAuthFSMOpsVersion) {
		return false
	}
	return c.raftServersSupport(peerCertAuthFSMOpsVersion, "joins without the operator PAT") == nil
}

// addJoinPAT puts the operator PAT in a server's answer. A worker or
// ingress node gets it only while some member would refuse its cert-only
// calls (PATFreeJoin); otherwise it gets the PAT's hashes and the operator
// volume scope. A server that holds no PAT itself can only hand out the
// hashes, to any role.
func (c *Cluster) addJoinPAT(out *JoinResponse, server bool) {
	if c.patToken != "" && (server || !c.PATFreeJoin()) {
		out.PATToken = c.patToken
		return
	}
	out.PATSHA256 = c.cfg.OperatorPATSHA256()
	if scope, err := volumes.OperatorScope(c.cfg.OperatorVolumeScope, c.patToken); err == nil {
		out.OperatorVolumeScope = scope
	}
}
