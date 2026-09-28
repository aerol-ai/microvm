package service

import (
	"errors"
	"expvar"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Per-sandbox egress evidence budget.
//
// One egress record per dial with no budget lets a busy or compromised sandbox
// grow the node-global evidence file without bound: its records fill the
// bounded writer queue so other tenants' secret-open records take the
// overflow path (spill or gap), every O(file) pass over the log — boot
// verification, retention, index rebuild — slows for everyone on the node,
// and the export receiver pays for the flood. The budget is a token bucket
// per sandbox, applied on the writer goroutine at the single funnel every
// egress record passes through (the channel batch and the spill drain, which
// is also how worker-spilled records arrive), so no ingress path can route
// around it. Records over budget are not written; they are counted and later
// reported as one coalesced egress record for that sandbox
// (reason=rate_limited, dropped=n), indexed under the sandbox itself so the
// loss is visible to whoever reads that sandbox's history and to nobody else.
// Secret-open records and gap markers are never subject to it: the request
// path emits a handful of those per sandbox lifetime, and they are the
// evidence the budget exists to protect.

const (
	// egressQuotaMarkerDelay is how long a sandbox's suppressed count
	// accumulates before it is written as one record. Bounds marker churn
	// under a steady flood to one record per delay per sandbox.
	egressQuotaMarkerDelay = 5 * time.Second
	// egressQuotaIdleTTL is how long an idle sandbox keeps its bucket.
	egressQuotaIdleTTL = 10 * time.Minute
	// egressQuotaMaxEntries bounds the bucket map. Past it, idle entries are
	// swept; if the map is still full, new sandboxes are admitted untracked
	// rather than refused — the cap protects memory, not the log.
	egressQuotaMaxEntries = 100_000
	egressQuotaSweepEvery = time.Minute
)

var (
	// auditEgressRateLimitedTotal counts egress records not written because
	// their sandbox was over budget; each is reported by a coalesced record.
	auditEgressRateLimitedTotal = expvar.NewInt("aerolvm_audit_egress_rate_limited_total")
	auditEgressRateLimitMarkers = expvar.NewInt("aerolvm_audit_egress_rate_limit_markers_total")
	auditEgressQuotaEntries     = expvar.NewInt("aerolvm_audit_egress_quota_entries")

	// errAuditRateLimited is what a durable emit returns for a record the
	// budget refused. The loss is not silent: it is owed to the sandbox's
	// next coalesced record.
	errAuditRateLimited = errors.New("audit egress budget for this sandbox is exhausted; the record is counted in its next rate_limited entry")
)

type egressQuotaEntry struct {
	lim             *rate.Limiter
	suppressed      int64
	firstSuppressed time.Time
	lastSeen        time.Time
	// Identity for the coalesced record, taken from the last refused one.
	actor, nodeID, incarnationID, ownerRef string
}

// egressAuditQuota is owned by the writer goroutine: no locking, and every
// method must be called from it (or before the writer starts).
type egressAuditQuota struct {
	limit       rate.Limit
	burst       int
	markerDelay time.Duration
	entries     map[string]*egressQuotaEntry
	lastSweep   time.Time
	now         func() time.Time
}

// newEgressAuditQuota returns nil when perSecond <= 0 (no budget), which every
// method tolerates as "admit everything".
func newEgressAuditQuota(perSecond float64, burst int, markerDelay time.Duration) *egressAuditQuota {
	if perSecond <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	if markerDelay <= 0 {
		markerDelay = egressQuotaMarkerDelay
	}
	return &egressAuditQuota{
		limit:       rate.Limit(perSecond),
		burst:       burst,
		markerDelay: markerDelay,
		entries:     map[string]*egressQuotaEntry{},
		now:         time.Now,
	}
}

// subjectToEgressQuota reports whether a record spends the sandbox's budget:
// egress records that name a sandbox and are not themselves a coalesced
// marker. Everything else passes.
func subjectToEgressQuota(ev SecretAuditEvent) bool {
	return ev.Kind == secretAuditKindEgress && strings.TrimSpace(ev.SandboxID) != "" &&
		ev.Reason != secretAuditReasonRateLimited && ev.Dropped == 0 && ev.Result != secretAuditResultGap
}

// admit filters one batch in order. suppressed[i] is true for a record the
// budget refused; kept holds the rest, order preserved. A nil quota keeps
// everything.
func (q *egressAuditQuota) admit(events []SecretAuditEvent) (kept []SecretAuditEvent, suppressed []bool) {
	if q == nil || len(events) == 0 {
		return events, nil
	}
	now := q.now()
	kept = make([]SecretAuditEvent, 0, len(events))
	for i := range events {
		ev := events[i]
		if !subjectToEgressQuota(ev) {
			kept = append(kept, ev)
			continue
		}
		e := q.entry(strings.TrimSpace(ev.SandboxID), now)
		if e == nil || e.lim.AllowN(now, 1) {
			kept = append(kept, ev)
			continue
		}
		if suppressed == nil {
			suppressed = make([]bool, len(events))
		}
		suppressed[i] = true
		if e.suppressed == 0 {
			e.firstSuppressed = now
		}
		e.suppressed++
		e.actor, e.nodeID = ev.Actor, ev.NodeID
		e.incarnationID, e.ownerRef = ev.IncarnationID, ev.OwnerRef
		auditEgressRateLimitedTotal.Add(1)
	}
	return kept, suppressed
}

// entry returns the sandbox's bucket, creating it under the size cap. nil
// means "untracked, admit": the map is full of live sandboxes.
func (q *egressAuditQuota) entry(sandboxID string, now time.Time) *egressQuotaEntry {
	if e, ok := q.entries[sandboxID]; ok {
		e.lastSeen = now
		return e
	}
	if len(q.entries) >= egressQuotaMaxEntries {
		q.sweep(now, true)
		if len(q.entries) >= egressQuotaMaxEntries {
			return nil
		}
	}
	e := &egressQuotaEntry{lim: rate.NewLimiter(q.limit, q.burst), lastSeen: now}
	q.entries[sandboxID] = e
	auditEgressQuotaEntries.Set(int64(len(q.entries)))
	return e
}

// owedMarkers returns one coalesced record per sandbox whose suppressed
// count has aged past the marker delay (or every owed one when force is set,
// for shutdown) and resets those counts. It also sweeps idle buckets.
func (q *egressAuditQuota) owedMarkers(force bool) []SecretAuditEvent {
	if q == nil {
		return nil
	}
	now := q.now()
	var markers []SecretAuditEvent
	for id, e := range q.entries {
		if e.suppressed == 0 || (!force && now.Sub(e.firstSuppressed) < q.markerDelay) {
			continue
		}
		markers = append(markers, SecretAuditEvent{
			Time:          now,
			Actor:         e.actor,
			NodeID:        e.nodeID,
			SandboxID:     id,
			IncarnationID: e.incarnationID,
			OwnerRef:      e.ownerRef,
			Kind:          secretAuditKindEgress,
			Result:        secretAuditResultSuccess,
			Reason:        secretAuditReasonRateLimited,
			Dropped:       e.suppressed,
		})
		e.suppressed = 0
		e.firstSuppressed = time.Time{}
	}
	q.sweep(now, false)
	if len(markers) > 0 {
		auditEgressRateLimitMarkers.Add(int64(len(markers)))
	}
	return markers
}

// sweep drops buckets idle past the TTL that owe nothing. Runs at most once
// per egressQuotaSweepEvery unless forced by the size cap.
func (q *egressAuditQuota) sweep(now time.Time, force bool) {
	if !force && now.Sub(q.lastSweep) < egressQuotaSweepEvery {
		return
	}
	q.lastSweep = now
	for id, e := range q.entries {
		if e.suppressed == 0 && now.Sub(e.lastSeen) > egressQuotaIdleTTL {
			delete(q.entries, id)
		}
	}
	auditEgressQuotaEntries.Set(int64(len(q.entries)))
}
