// Package kubeview is the gateway's view of sandboxes for the Kubernetes
// agent-sandbox API (plans/kubernetes-v2-architecture.md §16, C17): one
// index per owner, built from the placement feed, with resourceVersions
// every gateway agrees on and watches that resume on any gateway.
//
// A resourceVersion is a Raft log index. A row's is the larger of its
// Placement.Version and RunStateIndex; a delete's is the delete's index; a
// list's is the feed position its rows are current to. Every gateway
// applies the same Raft order, so the same number means the same state on
// any of them; they differ only in how far back their ring of recent
// changes goes.
//
//	feed event ──▶ apply: rows, owner index, ring entry per change ──▶ live watchers of that owner
//	Watch(owner, X): X < floor ──▶ ErrExpired (410: list again)
//	                 X > position ──▶ wait briefly, then ErrTooNew
//	                 else ──▶ every id of owner changed after X, at its current state, in RV order ──▶ live
//
// A feed resync (the server's change log no longer covered the cursor) or
// the real view coming back after the in-flux view replaces every row: the
// hub cannot tell what changed in between, so it closes every watch with
// ErrExpired and starts its ring at the new position. While the feed is in
// flux (no answer from the control plane past its age limit) the hub is
// not ready: it never serves rows with their owners blanked.
package kubeview

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

var (
	// ErrNotReady: the hub has no current view (before the first sync, or
	// while the feed is in flux). The API answers 503 + Retry-After.
	ErrNotReady = errors.New("kubeview: the sandbox view is not ready")
	// ErrExpired: the resourceVersion is older than this gateway's ring.
	// The API answers 410 Gone; the client lists again.
	ErrExpired = errors.New("kubeview: resource version too old")
	// ErrTooNew: the resourceVersion is ahead of this gateway's view, which
	// did not catch up in time. The API answers 504; the client retries.
	ErrTooNew = errors.New("kubeview: resource version too new")
)

// EventType is a watch event's type, named as Kubernetes names them.
type EventType string

const (
	Added    EventType = "ADDED"
	Modified EventType = "MODIFIED"
	Deleted  EventType = "DELETED"
	Bookmark EventType = "BOOKMARK"
	// Closed ends a watch: Err says why (ErrExpired after a resync, or a
	// watcher too slow to keep up).
	Closed EventType = "CLOSED"
)

// Item is one sandbox at one resourceVersion.
type Item struct {
	Placement cluster.Placement
	RV        uint64
}

// Event is one watch event. A Bookmark carries only RV.
type Event struct {
	Type EventType
	Item Item
	RV   uint64
	Err  error
}

// Defaults; Options may change them.
const (
	DefaultRingSize     = 262144
	DefaultWatchBuffer  = 1024
	DefaultTooNewWait   = 3 * time.Second
	DefaultBookmarkTick = time.Minute
)

// Options sizes a hub.
type Options struct {
	RingSize    int
	WatchBuffer int
	TooNewWait  time.Duration
}

// ringEntry is one change, kept for resuming watches. A delete keeps the row
// it removed, so a resumed watch can still say which object went.
type ringEntry struct {
	rv      uint64
	id      string
	owner   string
	created bool
	deleted bool
	gone    cluster.Placement
}

type watcher struct {
	owner string
	ch    chan Event
	done  chan struct{}
}

// Hub is one gateway's view. Its methods are safe for concurrent use; Apply
// must be called with feed events in order (cluster.PlacementFeedWatcher
// guarantees that).
type Hub struct {
	opts Options

	mu       sync.Mutex
	ready    bool
	inFlux   bool
	position uint64
	floor    uint64
	rows     map[string]cluster.Placement
	byOwner  map[string]map[string]struct{}
	ring     []ringEntry
	start    int
	n        int
	watchers map[*watcher]struct{}
	moved    chan struct{} // closed and replaced whenever position moves
}

// New returns an empty hub; it is not ready until its first full view.
func New(opts Options) *Hub {
	if opts.RingSize <= 0 {
		opts.RingSize = DefaultRingSize
	}
	if opts.WatchBuffer <= 0 {
		opts.WatchBuffer = DefaultWatchBuffer
	}
	if opts.TooNewWait <= 0 {
		opts.TooNewWait = DefaultTooNewWait
	}
	return &Hub{
		opts:     opts,
		rows:     map[string]cluster.Placement{},
		byOwner:  map[string]map[string]struct{}{},
		ring:     make([]ringEntry, opts.RingSize),
		watchers: map[*watcher]struct{}{},
		moved:    make(chan struct{}),
	}
}

// Follow feeds the hub from w until ctx ends; false means the feed is off.
func (h *Hub) Follow(ctx context.Context, w cluster.PlacementFeedWatcher) bool {
	return w.WatchPlacementFeed(ctx, h.Apply)
}

// visible says whether a row is shown: a placed sandbox (a reservation is
// not one yet) with an owner the API can map to a namespace.
func visible(p cluster.Placement) bool {
	return p.State != cluster.PlacementStateReserved && strings.TrimSpace(p.OwnerRef) != ""
}

// ItemRV is a row's resourceVersion.
func ItemRV(p cluster.Placement) uint64 {
	return max(p.Version, p.RunStateIndex)
}

// Apply takes one feed event.
func (h *Hub) Apply(ev cluster.PlacementFeedEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case ev.View && ev.InFlux:
		h.inFlux = true
	case ev.View:
		h.replaceLocked(ev.Full, ev.Next)
	default:
		for _, ch := range ev.Changes {
			h.applyChangeLocked(ch)
		}
	}
	if ev.Next > h.position {
		h.position = ev.Next
		close(h.moved)
		h.moved = make(chan struct{})
	}
}

// replaceLocked takes a whole view. The first one makes the hub ready; any
// later one ends every watch, since what changed in between is unknown.
func (h *Hub) replaceLocked(full []cluster.Placement, next uint64) {
	if h.ready {
		for w := range h.watchers {
			h.closeLocked(w, ErrExpired)
		}
	}
	h.rows = make(map[string]cluster.Placement, len(full))
	h.byOwner = map[string]map[string]struct{}{}
	for _, p := range full {
		if visible(p) {
			h.putLocked(p)
		}
	}
	h.start, h.n = 0, 0
	h.floor = next
	h.ready, h.inFlux = true, false
}

func (h *Hub) putLocked(p cluster.Placement) {
	h.rows[p.SandboxID] = p
	ids := h.byOwner[p.OwnerRef]
	if ids == nil {
		ids = map[string]struct{}{}
		h.byOwner[p.OwnerRef] = ids
	}
	ids[p.SandboxID] = struct{}{}
}

func (h *Hub) dropLocked(p cluster.Placement) {
	delete(h.rows, p.SandboxID)
	if ids := h.byOwner[p.OwnerRef]; ids != nil {
		delete(ids, p.SandboxID)
		if len(ids) == 0 {
			delete(h.byOwner, p.OwnerRef)
		}
	}
}

func (h *Hub) applyChangeLocked(ch cluster.PlacementChange) {
	old, had := h.rows[ch.SandboxID]
	if ch.Deleted || ch.Placement == nil || !visible(*ch.Placement) {
		if !had {
			return
		}
		h.dropLocked(old)
		e := ringEntry{rv: max(ch.Index, ItemRV(old)), id: old.SandboxID, owner: old.OwnerRef, deleted: true, gone: old}
		h.recordLocked(e)
		h.sendLocked(old.OwnerRef, Event{Type: Deleted, Item: Item{Placement: old, RV: e.rv}})
		return
	}
	p := *ch.Placement
	if had && old.OwnerRef != p.OwnerRef {
		// A row that changed owner leaves one namespace and joins another.
		h.dropLocked(old)
		e := ringEntry{rv: ItemRV(p), id: old.SandboxID, owner: old.OwnerRef, deleted: true, gone: old}
		h.recordLocked(e)
		h.sendLocked(old.OwnerRef, Event{Type: Deleted, Item: Item{Placement: old, RV: e.rv}})
		had = false
	}
	h.putLocked(p)
	rv := ItemRV(p)
	h.recordLocked(ringEntry{rv: rv, id: p.SandboxID, owner: p.OwnerRef, created: !had})
	typ := Modified
	if !had {
		typ = Added
	}
	h.sendLocked(p.OwnerRef, Event{Type: typ, Item: Item{Placement: p, RV: rv}})
}

// recordLocked appends to the ring; a full ring drops its oldest entry and
// raises the floor past it.
func (h *Hub) recordLocked(e ringEntry) {
	size := len(h.ring)
	if h.n == size {
		h.floor = max(h.floor, h.ring[h.start].rv)
		h.start = (h.start + 1) % size
		h.n--
	}
	h.ring[(h.start+h.n)%size] = e
	h.n++
}

// sendLocked gives an event to the owner's watchers. One too slow to take
// it is closed: dropping events would leave its cache wrong for good.
func (h *Hub) sendLocked(owner string, ev Event) {
	for w := range h.watchers {
		if w.owner != AllOwners && w.owner != owner {
			continue
		}
		select {
		case w.ch <- ev:
		default:
			h.closeLocked(w, ErrExpired)
		}
	}
}

func (h *Hub) closeLocked(w *watcher, err error) {
	delete(h.watchers, w)
	select {
	case w.ch <- Event{Type: Closed, Err: err}:
	default:
	}
	close(w.done)
}

// readyLocked is ErrNotReady unless the hub holds a current view.
func (h *Hub) readyLocked() error {
	if !h.ready || h.inFlux {
		return ErrNotReady
	}
	return nil
}

// Position is the resourceVersion a list taken now is current to.
func (h *Hub) Position() (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.readyLocked(); err != nil {
		return 0, err
	}
	return h.position, nil
}

// Get is one sandbox of owner, by ID.
func (h *Hub) Get(owner, id string) (Item, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.readyLocked(); err != nil {
		return Item{}, false, err
	}
	p, ok := h.rows[id]
	if !ok || p.OwnerRef != owner {
		return Item{}, false, nil
	}
	return Item{Placement: p, RV: ItemRV(p)}, true, nil
}

// List is up to limit of owner's sandboxes with IDs after `after`, in ID
// order, and the position they are current to. more says another page
// follows. A page read later may hold rows newer than the first page's
// position; a watch from that position sends them again, which informers
// take as an update.
func (h *Hub) List(owner, after string, limit int) (items []Item, rv uint64, more bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.readyLocked(); err != nil {
		return nil, 0, false, err
	}
	ids := make([]string, 0, len(h.byOwner[owner]))
	for id := range h.byOwner[owner] {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if limit > 0 && len(ids) > limit {
		ids, more = ids[:limit], true
	}
	items = make([]Item, 0, len(ids))
	for _, id := range ids {
		p := h.rows[id]
		items = append(items, Item{Placement: p, RV: ItemRV(p)})
	}
	return items, h.position, more, nil
}

// AllOwners watches every owner's sandboxes (a watch across namespaces).
const AllOwners = ""

// Watch streams owner's changes after resourceVersion from (AllOwners: every
// owner's). From 0 starts with every current sandbox as Added. Cancel ctx to stop; the channel is
// closed after the stream ends.
func (h *Hub) Watch(ctx context.Context, owner string, from uint64) (<-chan Event, error) {
	deadline := time.Now().Add(h.opts.TooNewWait)
	h.mu.Lock()
	for {
		if err := h.readyLocked(); err != nil {
			h.mu.Unlock()
			return nil, err
		}
		if from <= h.position {
			break
		}
		moved := h.moved
		h.mu.Unlock()
		wait := time.Until(deadline)
		if wait <= 0 {
			return nil, ErrTooNew
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-moved:
		case <-time.After(wait):
		}
		h.mu.Lock()
	}
	if from != 0 && from < h.floor {
		h.mu.Unlock()
		return nil, ErrExpired
	}
	backlog := h.backlogLocked(owner, from)
	w := &watcher{owner: owner, ch: make(chan Event, h.opts.WatchBuffer+len(backlog)), done: make(chan struct{})}
	for _, ev := range backlog {
		w.ch <- ev
	}
	h.watchers[w] = struct{}{}
	h.mu.Unlock()

	out := make(chan Event)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				h.mu.Lock()
				if _, ok := h.watchers[w]; ok {
					delete(h.watchers, w)
					close(w.done)
				}
				h.mu.Unlock()
				return
			case ev := <-w.ch:
				select {
				case out <- ev:
				case <-ctx.Done():
					continue
				}
				if ev.Type == Closed {
					return
				}
			case <-w.done:
				// Drain what is left (the Closed event among it), then end.
				for {
					select {
					case ev := <-w.ch:
						select {
						case out <- ev:
						case <-ctx.Done():
							return
						}
						if ev.Type == Closed {
							return
						}
					default:
						return
					}
				}
			}
		}
	}()
	return out, nil
}

// backlogLocked is what a watch from `from` must see before live events:
// from 0, every current sandbox as Added; otherwise each sandbox the owner
// changed after from, at its current state, in resourceVersion order.
func (h *Hub) backlogLocked(owner string, from uint64) []Event {
	var out []Event
	if from == 0 {
		add := func(p cluster.Placement) {
			out = append(out, Event{Type: Added, Item: Item{Placement: p, RV: ItemRV(p)}})
		}
		if owner == AllOwners {
			for _, p := range h.rows {
				add(p)
			}
		} else {
			for id := range h.byOwner[owner] {
				add(h.rows[id])
			}
		}
	} else {
		type seen struct {
			created bool
			gone    *cluster.Placement
			goneRV  uint64
		}
		changed := map[string]*seen{}
		for i := 0; i < h.n; i++ {
			e := h.ring[(h.start+i)%len(h.ring)]
			if e.rv <= from || (owner != AllOwners && e.owner != owner) {
				continue
			}
			s := changed[e.id]
			if s == nil {
				s = &seen{}
				changed[e.id] = s
			}
			if e.created {
				s.created = true
			}
			if e.deleted {
				g := e.gone
				s.gone, s.goneRV = &g, e.rv
			}
		}
		for id, s := range changed {
			if p, ok := h.rows[id]; ok && (owner == AllOwners || p.OwnerRef == owner) {
				typ := Modified
				if s.created && s.gone == nil {
					typ = Added
				}
				out = append(out, Event{Type: typ, Item: Item{Placement: p, RV: ItemRV(p)}})
				continue
			}
			if s.gone != nil && !s.created {
				out = append(out, Event{Type: Deleted, Item: Item{Placement: *s.gone, RV: s.goneRV}})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Item.RV != out[j].Item.RV {
			return out[i].Item.RV < out[j].Item.RV
		}
		return out[i].Item.Placement.SandboxID < out[j].Item.Placement.SandboxID
	})
	return out
}

// Owners lists the owners that have sandboxes, for a list across every
// namespace.
func (h *Hub) Owners() ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.readyLocked(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(h.byOwner))
	for o := range h.byOwner {
		out = append(out, o)
	}
	sort.Strings(out)
	return out, nil
}
