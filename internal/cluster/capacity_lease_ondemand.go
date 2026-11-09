package cluster

import (
	"context"
	"time"
)

// On-demand capacity leases for the leader's admission.
//
// The leader re-checks every reservation against its own capacity lease for
// the owner (admitReservationCommands: "has no fresh capacity heartbeat").
// Leases come from the background sweep (refreshCapacityLeases), and a
// server can be without one for a worker it could reach in milliseconds: it
// started a moment ago and its sweeps have not got to the worker yet, or two
// failed fetches while it was starting put the worker in the sweep's 15 s
// backoff. If that server is elected, every create onto the worker was
// refused with a retryable 503 until a sweep caught up, although the router
// that picked the worker had a fresh view of it. The cluster-chaos runs
// measured about 20 s of that after a leader change (UC-477, UC-481).
//
// So before admission, the leader fetches the lease of any owner it has no
// fresh one for, straight from that worker, and admission then reads it as
// it reads a sweep's. The fetch:
//
//   - runs before the admission lock is taken, so a slow worker cannot stall
//     admissions onto every other worker;
//   - is shared by every create waiting on the same worker, and runs on its
//     own context, so the first caller going away does not fail the others;
//   - is not repeated within capacityLeaseOnDemandGap of a failed one, so a
//     worker that keeps failing costs a create the 503 it got before, plus
//     at most one shared fetch per gap;
//   - never touches the sweep's backoff on failure (the sweep decides how to
//     pace a failing peer), and clears it on success, as a sweep's success
//     does.
//
// A leader whose leases are fresh does one map read per owner, under the
// cache's read lock, and nothing else.

// capacityLeaseOnDemandGap is the shortest time between two on-demand fetches
// of one worker after the first of them failed.
const capacityLeaseOnDemandGap = time.Second

// leaseFlight is one on-demand fetch in progress; done closes when it ends.
type leaseFlight struct {
	done chan struct{}
}

// freshLease reports whether nodeID has a lease admission would accept as
// fresh at now: the same rule apply uses for CapacityStale, plus a snapshot
// that says something.
func (c *capacityLeaseCache) freshLease(nodeID string, now time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	lease, ok := c.leases[nodeID]
	return ok && now.Sub(lease.updated) <= c.ttl && hasCapacitySnapshot(lease.snapshot)
}

// joinOnDemand returns the fetch of nodeID to wait for. own is true when the
// caller started it and must run it and call endOnDemand. It returns nil when
// the last on-demand fetch of nodeID failed less than
// capacityLeaseOnDemandGap ago.
func (c *capacityLeaseCache) joinOnDemand(nodeID string, now time.Time) (flight *leaseFlight, own bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.onDemand[nodeID]; ok {
		return f, false
	}
	if failed, ok := c.onDemandFailed[nodeID]; ok && now.Sub(failed) < capacityLeaseOnDemandGap {
		return nil, false
	}
	if c.onDemand == nil {
		c.onDemand = make(map[string]*leaseFlight)
	}
	f := &leaseFlight{done: make(chan struct{})}
	c.onDemand[nodeID] = f
	return f, true
}

// endOnDemand ends the fetch joinOnDemand started and wakes its waiters.
func (c *capacityLeaseCache) endOnDemand(nodeID string, f *leaseFlight, failedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.onDemand[nodeID] == f {
		delete(c.onDemand, nodeID)
	}
	if failedAt.IsZero() {
		delete(c.onDemandFailed, nodeID)
	} else {
		if c.onDemandFailed == nil {
			c.onDemandFailed = make(map[string]time.Time)
		}
		c.onDemandFailed[nodeID] = failedAt
	}
	close(f.done)
}

// ensureOwnerLeases fetches, before admission, the lease of every owner in
// cmd's reservations that this server has no fresh lease for, and waits for
// the fetches or ctx. Owners gossip does not list as alive placement targets
// are left alone: admission refuses those whatever their lease says.
func (c *Cluster) ensureOwnerLeases(ctx context.Context, cmd command) {
	if c == nil || c.capacityLeases == nil || c.gossip == nil {
		return
	}
	now := time.Now()
	var flights []*leaseFlight
	seen := make(map[string]bool)
	for _, r := range reservationCommands(cmd) {
		owner := r.OwnerNodeID
		// This server's own lease is re-read from its admitter on every
		// admission (refreshLocal).
		if owner == "" || owner == c.nodeID || seen[owner] {
			continue
		}
		seen[owner] = true
		if c.capacityLeases.freshLease(owner, now) {
			continue
		}
		m, ok := c.gossip.lookupMember(owner)
		if !ok || !m.Alive || !CanOwnSandboxRole(m.Role) || m.InternalURL == "" {
			continue
		}
		f, own := c.capacityLeases.joinOnDemand(owner, now)
		if f == nil {
			continue
		}
		if own {
			go c.fetchLeaseOnDemand(m, f)
		}
		flights = append(flights, f)
	}
	for _, f := range flights {
		select {
		case <-f.done:
		case <-ctx.Done():
			return
		}
	}
}

// fetchLeaseOnDemand runs one on-demand fetch of m's lease and ends flight.
func (c *Cluster) fetchLeaseOnDemand(m Member, flight *leaseFlight) {
	var failedAt time.Time
	defer func() { c.capacityLeases.endOnDemand(m.NodeID, flight, failedAt) }()
	// Taken before the request, as the sweep takes it: the answer covers
	// every promote applied up to here and maybe not one applied meanwhile.
	mark := c.capacityLeases.unreportedMark()
	dialled := time.Now()
	snap, err := c.fetchMemberCapacity(context.Background(), m, capacityLeaseFetchTimeout)
	if err != nil {
		failedAt = time.Now()
		if c.logger != nil {
			c.logger.Debug("cluster: on-demand capacity fetch failed", "node_id", m.NodeID, "error", err)
		}
		return
	}
	c.capacityLeases.recordResponsiveness(m.NodeID, time.Since(dialled) <= capacityLeaseQuickProbeTimeout)
	c.capacityLeases.recordFetchResult(m.NodeID, time.Now(), nil)
	c.capacityLeases.setReported(m.NodeID, snap, time.Now(), mark)
	capacityLeaseOnDemandFetches.Add(1)
}
