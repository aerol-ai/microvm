package cluster

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// "The machine is gone" (C19, plans/kubernetes-v2-architecture.md §9.6).
//
// On Kubernetes the operator sees a machine leave (its Node object deleted)
// before gossip has judged the node dead and long before the dead-owner grace
// runs out. It tells the leader (POST /v1/cluster/nodes/{id}/gone), and the
// leader may start the failover early. Never at once: deleting a Node object
// does not prove the machine stopped, and a node cut off from the cluster
// keeps running its sandboxes until its ownership lease runs out
// (internal/service/ownership_lease.go). That happens at most lease +
// lease/15 (16 s by default) after the node's last proven contact: the send
// time of the last authoritative read the leader answered for it. So that is
// the earliest the leader moves anything (eng review OV-E1).
//
// Three limits keep that bound true:
//
//   - The lease must hold with sandboxd down. On a plain VM it does not:
//     the runtime keeps running every container when sandboxd stops (the
//     TODOS.md P1 entry). So the early start applies only to a node whose
//     last heartbeat said its runtime freezes recreate-policy sandboxes on
//     its own (capacity.Snapshot.OwnershipLeaseFile, the worker pod's
//     runtime supervisor). Any other node waits the usual grace.
//   - The leader knows only the reads it answered itself. A read the old
//     leader answered can be later than any this leader saw, but not later
//     than a moment after this leader took over: the old one steps down
//     within raft's LeaderLeaseTimeout (500 ms) once it loses its quorum. So
//     the last contact counts as no earlier than this leader's start plus
//     leaderHandoverMargin.
//   - The node must have been renewing its lease by reads. A worker reads
//     every lease/3 only while a recreate-policy sandbox runs on it; with
//     none it keeps its lease without a read, which this leader never sees.
//     A sandbox that starts there later (one whose image pull finished)
//     would run on that unseen lease, past any bound taken from the
//     contacts. So the early start needs the node to have been reading
//     until the leader last heard from it: its last two contacts no more
//     than a read interval apart, and the last one no more than a read
//     interval before its last heartbeat. A read that fails then leaves
//     its lease where the last answer put it. A node that was not reading
//     (it ran no recreate-policy sandbox, or went idle and kept
//     heartbeating) waits the grace.
//
// Gossip still decides liveness: a node marked gone that gossip sees alive is
// not failed over, and a gone node rejoining clears the mark. The mark lives
// in the leader's memory only. A new leader has none, and the operator sends
// it again on its next pass; until then the node gets the grace, which is
// slower and never less safe.

// leaderHandoverMargin is how long after this server became leader an old
// leader may still have answered an authoritative read. Raft's
// LeaderLeaseTimeout is 500 ms; the rest is slack for the 5 s dead-owner tick
// that records the start, which only makes the start later and so the bound
// safer.
const leaderHandoverMargin = 2 * time.Second

// maxGoneMarks bounds the gone and contact maps the same way zoneMemory is
// bounded: a fleet that churns node IDs cannot grow them forever.
const maxGoneMarks = 8192

// contact is the last authoritative read this leader answered for a node,
// and how long after the previous one it came (zero for the first).
type contact struct {
	at  time.Time
	gap time.Duration
}

// ErrNodeGoneSelf refuses a "gone" for the leader itself: it is answering.
var ErrNodeGoneSelf = errors.New("cluster: this server is the leader and is running; it is not gone")

// NodeGoneMarker is the leader side of POST /v1/cluster/nodes/{id}/gone.
type NodeGoneMarker interface {
	MarkNodeGone(nodeID string) (NodeGoneResult, error)
}

// OwnershipContactRecorder is told, on the leader, each time it answers an
// authoritative placement read for a node: that is the node's ownership
// lease renewing.
type OwnershipContactRecorder interface {
	NoteOwnershipContact(nodeID string)
}

// NodeGoneResult answers a "gone".
type NodeGoneResult struct {
	NodeID string `json:"node_id"`
	// Early is true when the leader may fail the node over before the
	// grace: its runtime enforces the ownership lease with sandboxd down.
	Early bool `json:"early"`
	// NotBefore is the earliest that failover may start, when Early.
	NotBefore time.Time `json:"not_before,omitzero"`
	// Reason says why the failover is not early, when it is not.
	Reason string `json:"reason,omitempty"`
}

// goneTracker is the leader's state for C19.
type goneTracker struct {
	mu sync.Mutex
	// gone is when the operator first said each node's machine is gone.
	gone map[string]time.Time
	// contacts is when this server, as leader, last answered an
	// authoritative read for each node, and the gap since the one before.
	contacts map[string]contact
	// leaderSince is when this server was first seen leading in raft term
	// term; zero while it is not the leader. Keyed by the term so a
	// leadership lost and won back between two looks is a new start: the
	// other leader may have answered reads in between.
	leaderSince time.Time
	term        uint64
}

func (g *goneTracker) markGone(nodeID string, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gone == nil {
		g.gone = make(map[string]time.Time)
	}
	if _, ok := g.gone[nodeID]; ok || len(g.gone) >= maxGoneMarks {
		return
	}
	g.gone[nodeID] = at
}

func (g *goneTracker) isGone(nodeID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.gone[nodeID]
	return ok
}

// clearGone drops the mark: the node is back, so it was not gone.
func (g *goneTracker) clearGone(nodeID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.gone, nodeID)
}

// forget drops everything kept for nodeID once its failover is done. Each
// replaced worker on Kubernetes is a new node ID, so a mark kept after its
// node is evicted would fill the bounded map and end early failover for
// every later node.
func (g *goneTracker) forget(nodeID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.gone, nodeID)
	delete(g.contacts, nodeID)
}

// noteContact records an answered read. A full map first drops contacts
// older than stale (the lease bound): earliestFailover takes the later of
// a contact and the takeover, so a contact that old can no longer make a
// failover later than now, and dropping it changes no decision. Nodes
// churn on Kubernetes (every replaced worker is a new ID), so without that
// the map would fill and quietly end early failover.
func (g *goneTracker) noteContact(nodeID string, at time.Time, stale time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.contacts == nil {
		g.contacts = make(map[string]contact)
	}
	cur, ok := g.contacts[nodeID]
	if !ok && len(g.contacts) >= maxGoneMarks {
		for id, c := range g.contacts {
			if c.at.Before(at.Add(-stale)) {
				delete(g.contacts, id)
			}
		}
		if len(g.contacts) >= maxGoneMarks {
			return // unrecorded: that node gets no early failover
		}
	}
	if !at.After(cur.at) {
		return
	}
	next := contact{at: at}
	if ok {
		next.gap = at.Sub(cur.at)
	}
	g.contacts[nodeID] = next
}

// observeLeadership records when this server started leading in term, or
// forgets it when it no longer leads. Contacts are this leader's own
// answers, so a new term starts them over too.
func (g *goneTracker) observeLeadership(leading bool, term uint64, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case !leading:
		g.leaderSince, g.term = time.Time{}, 0
	case g.leaderSince.IsZero() || term != g.term:
		g.leaderSince, g.term = now, term
		g.contacts = nil
	}
}

// earliestFailover is the earliest the leader may move nodeID's sandboxes
// after a "gone": the latest proven contact plus lease + lease/15. ok is
// false when the node is not marked gone, this server is not leading, or
// the node was not renewing its lease by reads until lastHeard, its last
// heartbeat here (see the header).
func (g *goneTracker) earliestFailover(nodeID string, lease time.Duration, lastHeard time.Time) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, gone := g.gone[nodeID]; !gone || g.leaderSince.IsZero() {
		return time.Time{}, false
	}
	c, known := g.contacts[nodeID]
	if !known || !renewingByReads(c, lease) || c.at.Before(lastHeard.Add(-readInterval(lease))) {
		return time.Time{}, false
	}
	at := g.leaderSince.Add(leaderHandoverMargin)
	if c.at.After(at) {
		at = c.at
	}
	return at.Add(lease + lease/15), true
}

// readInterval is a reading worker's longest gap between two reads: lease/3,
// its confirm cadence (internal/service/ownership_lease.go), plus lease/15
// for the round trip.
func readInterval(lease time.Duration) time.Duration { return lease/3 + lease/15 }

// renewingByReads reports whether c came one read interval after the one
// before.
func renewingByReads(c contact, lease time.Duration) bool {
	return c.gap > 0 && c.gap <= readInterval(lease)
}

// NoteOwnershipContact records that this leader just answered an
// authoritative read for nodeID.
func (c *Cluster) NoteOwnershipContact(nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if c == nil || nodeID == "" {
		return
	}
	lease := OwnershipLease(c.cfg)
	c.gone.noteContact(nodeID, time.Now(), lease+lease/15)
}

// MarkNodeGone records the operator's word that nodeID's machine is gone.
// Idempotent: the operator repeats it each pass until the node is removed.
func (c *Cluster) MarkNodeGone(nodeID string) (NodeGoneResult, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeGoneResult{}, errors.New("cluster: node id required")
	}
	if c == nil || c.raft == nil || c.raft.raft == nil || c.raft.raft.State() != raft.Leader {
		return NodeGoneResult{}, ErrNotLeader
	}
	if nodeID == c.nodeID {
		return NodeGoneResult{}, ErrNodeGoneSelf
	}
	now := time.Now()
	c.gone.observeLeadership(true, c.raft.raft.CurrentTerm(), now)
	c.gone.markGone(nodeID, now)
	res := NodeGoneResult{NodeID: nodeID}
	if !c.capacityLeases.lastKnownLeaseFile(nodeID) {
		res.Reason = "the node's runtime does not enforce the ownership lease with sandboxd down; failover waits the dead-owner grace"
		return res, nil
	}
	if at, ok := c.gone.earliestFailover(nodeID, OwnershipLease(c.cfg), c.capacityLeases.lastHeard(nodeID)); ok {
		res.Early, res.NotBefore = true, at
	} else {
		res.Reason = "this leader has not seen the node renew its ownership lease by reads until it last heard from it (it runs no recreate-policy sandbox, or the leader is new); failover waits the dead-owner grace"
	}
	if c.logger != nil {
		c.logger.Info("cluster: operator says the node's machine is gone",
			"node_id", nodeID, "early", res.Early, "not_before", res.NotBefore)
	}
	return res, nil
}

// goneFailoverDue reports whether nodeID is marked gone, runs a runtime that
// enforces the lease on its own, and its lease limit has passed.
func (c *Cluster) goneFailoverDue(nodeID string, now time.Time) bool {
	if !c.capacityLeases.lastKnownLeaseFile(nodeID) {
		return false
	}
	at, ok := c.gone.earliestFailover(nodeID, OwnershipLease(c.cfg), c.capacityLeases.lastHeard(nodeID))
	return ok && !now.Before(at)
}
