package service

import (
	"context"
	"errors"
	"expvar"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"golang.org/x/sync/singleflight"
)

// Egress audit binding: making the check cost O(lifecycle), not O(events).
//
// validateEgressAuditBinding runs on every ingested egress record, and in
// cluster mode it resolved the placement each time. On an agent that is a
// control-plane round trip PER EVENT: at one event per second for each of
// 100k sandboxes the fleet issues ~100k placement reads/s, ahead of the
// sink's own rate limiter, so the limiter cannot protect the control plane.
//
// The check itself has a real security purpose — a capability retained by a
// terminated or reassigned worker must not keep appending evidence under its
// old sandbox — so it cannot simply be dropped. Instead it is answered from a
// short-lived, explicitly fenced local lease:
//
//   - The lease records the (owner, incarnation) pair the control plane last
//     confirmed, and is valid for auditOwnershipLeaseTTL.
//   - Every local lifecycle boundary invalidates it immediately
//     (see invalidateAuditOwnershipLease), so a destroyed or recreated
//     sandbox is rejected on the very next event rather than at TTL. That is
//     the common case by far.
//   - The residual window is only "Raft moved ownership while this node's row
//     is still live" — i.e. the dead-owner path, where the node has already
//     been declared dead by gossip. auditOwnershipLeaseTTL is deliberately far
//     shorter than that grace period.
//   - Refreshes are single-flighted per sandbox, so an event flood produces at
//     most ONE in-flight control-plane read for that sandbox no matter how
//     many records arrive. That is the overload admission: it bounds expensive
//     remote validation structurally, ahead of the work, instead of relying on
//     a limiter that only runs after it.
//   - A refresh that cannot reach an authoritative answer fails CLOSED, exactly
//     as the per-event read did.

const (
	// auditOwnershipLeaseTTL bounds how long a confirmed (owner, incarnation)
	// answer is reused. It is orders of magnitude below the dead-owner grace
	// period, and local lifecycle boundaries pre-empt it entirely.
	auditOwnershipLeaseTTL = 15 * time.Second
	// auditOwnershipLeaseMaxEntries bounds the map. Entries are normally
	// dropped by the sandbox's own lifecycle boundary; the cap is the backstop
	// for ids whose boundary this process never observed (a crash between
	// create and destroy, say). Past it, expired entries are swept.
	auditOwnershipLeaseMaxEntries = 100_000
)

var (
	auditBindingLeaseHits   = expvar.NewInt("aerolvm_audit_binding_lease_hits_total")
	auditBindingLeaseMisses = expvar.NewInt("aerolvm_audit_binding_lease_misses_total")
)

// auditOwnershipLease is one sandbox's last authoritative binding answer.
type auditOwnershipLease struct {
	incarnationID string
	// ownedBySelf records whether the authoritative view named THIS node as
	// the owner. A false lease is cached too: a fenced worker must keep being
	// rejected without re-reading the control plane for every record it
	// retries.
	ownedBySelf bool
	expiresAt   time.Time
}

// auditOwnershipLeases holds the per-sandbox leases and the single-flight
// group that collapses concurrent refreshes.
type auditOwnershipLeases struct {
	mu      sync.Mutex
	entries map[string]auditOwnershipLease
	group   singleflight.Group
}

func (s *Service) ownershipLeases() *auditOwnershipLeases {
	s.auditLeaseOnce.Do(func() {
		s.auditLeases = &auditOwnershipLeases{entries: make(map[string]auditOwnershipLease)}
	})
	return s.auditLeases
}

// invalidateAuditOwnershipLease drops a sandbox's binding lease. Called at
// every local lifecycle boundary so the common cases — destroyed, recreated,
// reclaimed — are rejected on the next event instead of at TTL.
func (s *Service) invalidateAuditOwnershipLease(sandboxID string) {
	if s == nil || strings.TrimSpace(sandboxID) == "" {
		return
	}
	l := s.ownershipLeases()
	l.mu.Lock()
	delete(l.entries, sandboxID)
	l.mu.Unlock()
}

func (l *auditOwnershipLeases) get(sandboxID string, now time.Time) (auditOwnershipLease, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[sandboxID]
	if !ok || !now.Before(entry.expiresAt) {
		return auditOwnershipLease{}, false
	}
	return entry, true
}

func (l *auditOwnershipLeases) put(sandboxID string, entry auditOwnershipLease, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= auditOwnershipLeaseMaxEntries {
		for id, e := range l.entries {
			if !now.Before(e.expiresAt) {
				delete(l.entries, id)
			}
		}
	}
	if len(l.entries) < auditOwnershipLeaseMaxEntries {
		l.entries[sandboxID] = entry
	}
}

// validateEgressAuditBinding prevents a capability retained by a terminated or
// reassigned worker from continuing to append evidence under its old sandbox.
// Cluster placement is authoritative when enabled; standalone mode uses the
// local sandbox row. Incarnation and owner checks also fence failover races.
//
// The authoritative answer is leased (see the file comment): the check is now
// proportional to sandbox lifecycles, not to sandbox traffic.
func (s *Service) validateEgressAuditBinding(ctx context.Context, sandboxID, incarnationID string) error {
	sandboxID = strings.TrimSpace(sandboxID)
	incarnationID = strings.TrimSpace(incarnationID)
	if s == nil || sandboxID == "" || incarnationID == "" {
		return errAuditIngestBindingStale
	}
	now := time.Now()
	leases := s.ownershipLeases()
	if lease, ok := leases.get(sandboxID, now); ok {
		auditBindingLeaseHits.Add(1)
		return bindingVerdict(lease, incarnationID)
	}
	auditBindingLeaseMisses.Add(1)
	// Collapse concurrent refreshes for this sandbox into one. A flood of
	// records with an expired lease must not become a flood of reads.
	resolved, err, _ := leases.group.Do(sandboxID, func() (any, error) {
		// Re-check under the flight: a concurrent refresh may have just
		// installed a fresh lease.
		if lease, ok := leases.get(sandboxID, time.Now()); ok {
			return lease, nil
		}
		lease, err := s.resolveAuditBinding(ctx, sandboxID)
		if err != nil {
			return auditOwnershipLease{}, err
		}
		leases.put(sandboxID, lease, time.Now())
		return lease, nil
	})
	if err != nil {
		return err
	}
	lease, _ := resolved.(auditOwnershipLease)
	return bindingVerdict(lease, incarnationID)
}

func bindingVerdict(lease auditOwnershipLease, incarnationID string) error {
	if !lease.ownedBySelf || lease.incarnationID == "" || lease.incarnationID != incarnationID {
		return errAuditIngestBindingStale
	}
	return nil
}

// resolveAuditBinding reads the authoritative (owner, incarnation) pair. An
// unavailable authority is an error, never a lease: failing open here would
// let a fenced worker append for a full TTL.
func (s *Service) resolveAuditBinding(ctx context.Context, sandboxID string) (auditOwnershipLease, error) {
	expiresAt := time.Now().Add(auditOwnershipLeaseTTL)
	if s.cfg.EnableCluster {
		c := s.Cluster()
		if c == nil {
			return auditOwnershipLease{}, errAuditIngestBindingStale
		}
		p, ok := c.PlacementOf(sandboxID)
		// An orphan has no active owner and therefore no legitimate worker. Do
		// not let a capability retained by the dead owner's process continue to
		// append after Raft has fenced that owner.
		if !ok {
			return auditOwnershipLease{expiresAt: expiresAt}, nil
		}
		owner := strings.TrimSpace(p.OwnerNodeID)
		self := strings.TrimSpace(c.SelfNodeID())
		return auditOwnershipLease{
			incarnationID: strings.TrimSpace(p.IncarnationID),
			// An orphan has a blank owner. Requiring both sides to be
			// non-empty keeps a node that has not learned its own id from
			// matching one.
			ownedBySelf: owner != "" && self != "" && owner == self,
			expiresAt:   expiresAt,
		}, nil
	}
	if s.store == nil {
		return auditOwnershipLease{}, errAuditIngestBindingStale
	}
	sandbox, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// A deleted sandbox is a settled answer, so it is worth leasing:
			// a worker retrying a stale capability gets rejected without
			// re-reading the row each time.
			return auditOwnershipLease{expiresAt: expiresAt}, nil
		}
		return auditOwnershipLease{}, err
	}
	// Standalone has exactly one node, so a live local row is self-owned.
	return auditOwnershipLease{
		incarnationID: strings.TrimSpace(sandbox.AuditIncarnationID),
		ownedBySelf:   true,
		expiresAt:     expiresAt,
	}, nil
}
