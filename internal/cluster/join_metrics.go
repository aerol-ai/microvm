package cluster

import (
	"expvar"
	"sync"
	"sync/atomic"
	"time"
)

// Join and renewal metrics (plans/kubectl-style-cluster-ops.md §10.1).
// expvar maps export positional labels (key, key2), like every other
// aerolvm_ map: aerolvm_join_attempts_total{key=result,key2=reason} and
// aerolvm_join_tokens{key=role,key2=ttl_kind}.
var (
	joinAttempts   = expvar.NewMap("aerolvm_join_attempts_total")
	joinAttemptsMu sync.Mutex

	// certRenewFailures counts renewals that failed; certRenewFailingSince
	// is when the current run of failures began (0 while renewals work),
	// which the "failing for more than a day" alert reads.
	certRenewFailures     = expvar.NewInt("aerolvm_cert_renew_failures_total")
	certRenewFailingSince = expvar.NewInt("aerolvm_cert_renew_failing_since_unix")
	// certRenewals counts certs renewed; certRenewSkipped counts renewals
	// a scripted cluster can't do yet (no admitted record before adopt).
	certRenewals     = expvar.NewInt("aerolvm_cert_renewals_total")
	certRenewSkipped = expvar.NewInt("aerolvm_cert_renew_skipped_total")
)

// recordJoinAttempt counts one POST /v1/join by result and reason.
func recordJoinAttempt(result, reason string) {
	joinAttemptsMu.Lock()
	defer joinAttemptsMu.Unlock()
	inner, ok := joinAttempts.Get(result).(*expvar.Map)
	if !ok {
		inner = new(expvar.Map).Init()
		joinAttempts.Set(result, inner)
	}
	inner.Add(reason, 1)
}

// joinTokenSource is the FSM the token gauge reads: the last server to
// start in this process (one per process in production).
var joinTokenSource atomic.Pointer[placementFSM]

// joinTokenGauge is aerolvm_join_tokens{role, ttl_kind}: usable tokens (not
// expired, and not a used-up single-use token), read at scrape time.
var joinTokenGauge = func() *expvar.Map {
	root := expvar.NewMap("aerolvm_join_tokens")
	for _, role := range []string{JoinRoleServer, JoinRoleWorker, JoinRoleIngress} {
		inner := new(expvar.Map).Init()
		for _, kind := range []string{"expiring", "never"} {
			inner.Set(kind, expvar.Func(func() any { return countJoinTokens(joinTokenSource.Load(), role, kind, time.Now()) }))
		}
		root.Set(role, inner)
	}
	return root
}()

// countJoinTokens counts usable tokens of role and TTL kind.
func countJoinTokens(f *placementFSM, role, kind string, now time.Time) int {
	if f == nil {
		return 0
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	n := 0
	for _, t := range f.joinTokens {
		never := t.ExpiresUnixNano == 0
		if t.Role != role || never != (kind == "never") || t.expiredAt(now.UnixNano()) || (!t.Reusable && len(t.UsedBy) > 0) {
			continue
		}
		n++
	}
	return n
}

// recordJoinAudit hands a join call to the service's audit writer, when one
// is attached (AttachRecreator).
func (c *Cluster) recordJoinAudit(ev JoinAuditEvent) {
	if rec, ok := c.currentRecreator().(JoinAuditRecorder); ok {
		rec.RecordClusterJoin(ev)
	}
}
