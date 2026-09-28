package cluster

import (
	"context"
	"time"
)

// Placement change log: the server half of the versioned placement delta feed
// (plans/ingress-proxy-routing.md §3.4, task T2).
//
// Ingress nodes run cluster.Agent and hold no Raft state. They used to
// re-download the whole placement view every 5s (a page-walk of
// /internal/placements/page), which at 100 ingress × 100k placements is a
// constant, fleet-sized read load. This log lets an Agent ask "what changed
// since index N" instead:
//
//	apply(log.Index=I) ──▶ storePlacementLocked / delete ──▶ record(I, id, deleted)
//	                                                            │
//	GET changes?since=N ◀── changesSince(N) ◀───────────────────┘
//	   N <  floor  → resnapshot (the log no longer covers N)
//	   N >= floor  → latest value of every id changed at index > N, deduped
//
// Properties it relies on:
//   - Indexes are Raft log indexes (f.version = log.Index), which are
//     globally ordered, so a cursor is valid against ANY server. Each
//     server's own floor decides whether it can answer.
//   - Node-local and derived: never in the snapshot (it would bloat the
//     snapshot and change its format). Restore clears it and raises the
//     floor to the snapshot's version, so any older cursor gets resnapshot
//     and never a silent gap.
//   - It only records what apply already mutated; it never influences the
//     result of apply.
//   - It stores (index, id, deleted) only. Values are read from f.placements
//     at serve time. A value newer than the cursor's page boundary can
//     therefore be sent early, which is safe because clients merge by
//     Placement.Version.

const defaultPlacementChangeLogCap = 65536

type placementChangeEntry struct {
	index   uint64
	id      string
	deleted bool
}

// placementChangeLog is a bounded ring of changes, guarded by the FSM lock.
type placementChangeLog struct {
	buf   []placementChangeEntry
	start int // index of the oldest entry in buf
	n     int // number of live entries
	// floor: every change at index <= floor may be missing. A cursor
	// since < floor cannot be answered from the log.
	floor uint64
	last  uint64 // highest index recorded
}

func newPlacementChangeLog(capacity int) *placementChangeLog {
	if capacity <= 0 {
		capacity = defaultPlacementChangeLogCap
	}
	return &placementChangeLog{buf: make([]placementChangeEntry, capacity)}
}

// reset drops every entry and makes floor the new coverage boundary.
func (l *placementChangeLog) reset(floor uint64) {
	for i := range l.buf {
		l.buf[i] = placementChangeEntry{}
	}
	l.start, l.n = 0, 0
	l.floor, l.last = floor, floor
}

// record appends one change at index. Several changes may share an index
// (multi-row ops such as opOrphanOwner). An index that goes BACKWARDS
// (tests applying raft.Log{Index: 0}, or a log that restarted) cannot be
// ordered against what is retained, so the log resets and older cursors
// get resnapshot.
func (l *placementChangeLog) record(index uint64, id string, deleted bool) {
	if index < l.last {
		var floor uint64
		if index > 0 {
			floor = index - 1
		}
		l.reset(floor)
	}
	if l.n == len(l.buf) {
		evicted := l.buf[l.start]
		l.start = (l.start + 1) % len(l.buf)
		l.n--
		if evicted.index > l.floor {
			l.floor = evicted.index
		}
	}
	l.buf[(l.start+l.n)%len(l.buf)] = placementChangeEntry{index: index, id: id, deleted: deleted}
	l.n++
	l.last = index
}

// at returns the i-th oldest live entry.
func (l *placementChangeLog) at(i int) placementChangeEntry {
	return l.buf[(l.start+i)%len(l.buf)]
}

// PlacementChange is one sandbox's latest state since a cursor.
type PlacementChange struct {
	// Index is the Raft index of the newest change seen for this id in the
	// served range. For a delete, a client drops its row only if the row's
	// Version is not above Index.
	Index     uint64     `json:"index"`
	SandboxID string     `json:"sandbox_id"`
	Deleted   bool       `json:"deleted,omitempty"`
	Placement *Placement `json:"placement,omitempty"`
}

// PlacementChangesResponse answers GET /v1/cluster/internal/placements/changes.
type PlacementChangesResponse struct {
	Changes []PlacementChange `json:"changes"`
	// Next is the cursor to send as since on the next call.
	Next uint64 `json:"next"`
	// Resnapshot means the log no longer covers since. The client must
	// page-walk /internal/placements/page and then resume from Next.
	Resnapshot bool   `json:"resnapshot,omitempty"`
	Floor      uint64 `json:"floor"`
}

// placementChangesByteBudget bounds one response. It matches the page walk,
// so the Agent's response cap applies unchanged. A var so tests can shrink
// it to exercise pagination.
var placementChangesByteBudget = placementPageByteBudget

// changesSince serves the log. Caller holds f.mu (read).
//
// Pagination never splits an index group. If the byte budget runs out partway
// through the changes that share an index, that whole group is left for the
// next call, and Next stops at the last COMPLETE index. Otherwise a client
// could skip half of a multi-row op. A single group larger than the budget is
// still sent whole, so a response always makes progress.
func (f *placementFSM) changesSinceLocked(since uint64) PlacementChangesResponse {
	l := f.changes
	resp := PlacementChangesResponse{Changes: []PlacementChange{}, Floor: l.floor}
	if since < l.floor {
		resp.Resnapshot = true
		resp.Next = f.version
		return resp
	}

	// Walk the entries newer than since in order, grouping by index.
	first := 0
	for first < l.n && l.at(first).index <= since {
		first++
	}
	budget := placementChangesByteBudget
	pos := map[string]int{} // id -> position in resp.Changes
	lastComplete := since
	i := first
	for i < l.n {
		groupIndex := l.at(i).index
		j := i
		groupBytes := 0
		var group []placementChangeEntry
		for j < l.n && l.at(j).index == groupIndex {
			e := l.at(j)
			group = append(group, e)
			groupBytes += placementChangeSize(e.id)
			j++
		}
		if groupBytes > budget && len(resp.Changes) > 0 {
			break // leave this whole group for the next call
		}
		budget -= groupBytes
		for _, e := range group {
			ch := PlacementChange{Index: e.index, SandboxID: e.id}
			if p, ok := f.placements[e.id]; ok {
				cp := p
				ch.Placement = &cp
			} else {
				ch.Deleted = true
			}
			if k, seen := pos[e.id]; seen {
				resp.Changes[k] = ch // latest wins
				continue
			}
			pos[e.id] = len(resp.Changes)
			resp.Changes = append(resp.Changes, ch)
		}
		lastComplete = groupIndex
		i = j
	}
	if i >= l.n {
		// Consumed everything: the cursor jumps to the FSM version, so
		// applies that recorded nothing (non-placement ops) do not replay.
		resp.Next = f.version
		if resp.Next < lastComplete {
			resp.Next = lastComplete
		}
	} else {
		resp.Next = lastComplete
	}
	return resp
}

// placementChangeSize approximates one change's encoded size for the budget.
// Cheap and conservative: a row's recovery fields are never sent (hot rows
// only), so a fixed per-row allowance plus the ID is enough to keep a
// response within the transport cap.
func placementChangeSize(id string) int {
	const perRow = 1024 // measured placement ≈ 751 B on the wire, rounded up
	return perRow + len(id)
}

// recordPlacementChangeLocked notes that id changed at the current apply
// index. Caller holds f.mu. The log is created lazily, so FSMs built as
// struct literals in tests work.
func (f *placementFSM) recordPlacementChangeLocked(id string, deleted bool) {
	if f.changes == nil {
		f.changes = newPlacementChangeLog(0)
	}
	f.changes.record(f.version, id, deleted)
}

func (f *placementFSM) resetPlacementChangesLocked(floor uint64) {
	if f.changes == nil {
		f.changes = newPlacementChangeLog(0)
	}
	f.changes.reset(floor)
}

// placementChanges is the read entry point (the RLock is taken here).
func (f *placementFSM) placementChanges(since uint64) PlacementChangesResponse {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.changes == nil {
		// Nothing recorded yet: cover from the current version, so any
		// cursor below it resnapshots.
		return PlacementChangesResponse{Changes: []PlacementChange{}, Resnapshot: since < f.version, Next: f.version, Floor: f.version}
	}
	return f.changesSinceLocked(since)
}

// PublicInternalPlacementChangesPath is the long-poll delta feed endpoint.
const PublicInternalPlacementChangesPath = "/v1/cluster/internal/placements/changes"

// MaxPlacementChangesWait bounds one long-poll. It stays under the Agent's
// control-plane request timeout plus slack, so a parked poll is never cut off
// by the caller's own deadline.
const MaxPlacementChangesWait = 25 * time.Second

// PlacementChanges answers a delta-feed poll. With nothing newer than since,
// it parks until the FSM changes or wait expires. It subscribes BEFORE the
// first read, so an apply landing between read and park cannot be missed.
//
// A server that is BEHIND the cursor (a lagging follower, or an Agent that
// switched servers) waits instead of resnapshotting: since is a global Raft
// index, so "I haven't applied that far yet" is not a gap. Next never moves
// below since.
func (c *Cluster) PlacementChanges(ctx context.Context, since uint64, wait time.Duration) PlacementChangesResponse {
	if c == nil || c.fsm == nil {
		return PlacementChangesResponse{Changes: []PlacementChange{}, Resnapshot: true}
	}
	if wait < 0 {
		wait = 0
	}
	if wait > MaxPlacementChangesWait {
		wait = MaxPlacementChangesWait
	}
	wake := make(chan struct{}, 1)
	cancel := c.fsm.subscribe(wake)
	defer cancel()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		resp := c.fsm.placementChanges(since)
		if resp.Next < since {
			resp.Next = since
		}
		if len(resp.Changes) > 0 || (resp.Resnapshot && c.fsm.currentVersion() >= since) {
			return resp
		}
		resp.Resnapshot = false
		select {
		case <-wake:
		case <-timer.C:
			return resp
		case <-ctx.Done():
			return resp
		}
	}
}

// WatchPlacementChanges streams this server's own change log to fn,
// in-process (no network): a full view first, then deltas, resyncing on
// resnapshot. It runs until ctx ends.
func (c *Cluster) WatchPlacementChanges(ctx context.Context, fn PlacementChangeHandler) bool {
	if c == nil || c.fsm == nil || fn == nil {
		return false
	}
	go func() {
		var cursor uint64
		synced := false
		for ctx.Err() == nil {
			if !synced {
				head := c.fsm.placementChanges(0)
				cursor = head.Next
				fn(c.PlacementsForShards(PlacementShardFilter{}), nil)
				synced = true
				continue
			}
			resp := c.PlacementChanges(ctx, cursor, MaxPlacementChangesWait)
			if resp.Resnapshot {
				synced = false
				continue
			}
			if len(resp.Changes) > 0 {
				fn(nil, resp.Changes)
			}
			if resp.Next > cursor {
				cursor = resp.Next
			}
		}
	}()
	return true
}
