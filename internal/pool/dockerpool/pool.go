// Package dockerpool is the in-memory warm-container pool for Docker sandboxes.
package dockerpool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"
)

// Pool keeps pre-started Docker containers keyed by image identity + runtime.
type Pool struct {
	logger *slog.Logger

	mu            sync.Mutex
	defaultDepth  int
	maxImages     int
	idleTTL       time.Duration
	pinned        map[string]struct{}
	targets       map[string]Key // keyString -> Key
	lastUsed      map[string]time.Time
	ready         map[string][]*ParkedSlot
	spawning      map[string]int
	spawnFails    map[string]int // keyString -> consecutive park failures
	spawner       Spawner
	onReleasePark func(slotID string)
	metrics       *Metrics
	refillKick    chan struct{}
}

// New constructs a warm pool.
func New(logger *slog.Logger) *Pool {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pool{
		logger:     logger,
		pinned:     make(map[string]struct{}),
		targets:    make(map[string]Key),
		lastUsed:   make(map[string]time.Time),
		ready:      make(map[string][]*ParkedSlot),
		spawning:   make(map[string]int),
		spawnFails: make(map[string]int),
		metrics:    &Metrics{},
		refillKick: make(chan struct{}, 1),
	}
}

func (p *Pool) SetSpawner(s Spawner) { p.spawner = s }
func (p *Pool) SetParkReleaser(fn func(slotID string)) {
	p.onReleasePark = fn
}

func (p *Pool) releasePark(slotID string) {
	if p.onReleasePark != nil && slotID != "" {
		p.onReleasePark(slotID)
	}
}

// ReleasePark frees the capacity reservation of a slot that already left the
// pool via Acquire but was discarded by the caller (e.g. adopt failure).
// Every parked slot holds a park:<slot-id> admitter reservation; any path
// that destroys the container without releasing it leaks capacity until the
// node stops admitting creates.
func (p *Pool) ReleasePark(slotID string) { p.releasePark(slotID) }

// destroySlots tears down discarded slots outside the pool lock: the spawner
// call talks to the Docker engine and must never run under p.mu.
func (p *Pool) destroySlots(ctx context.Context, slots []*ParkedSlot) {
	for _, slot := range slots {
		if slot == nil {
			continue
		}
		if p.spawner != nil {
			_ = p.spawner.DestroyParked(ctx, slot)
		}
		p.releasePark(slot.ID)
	}
}
func (p *Pool) SetDefaultDepth(n int) {
	p.mu.Lock()
	p.defaultDepth = n
	p.mu.Unlock()
}
func (p *Pool) SetMaxImages(n int) {
	p.mu.Lock()
	p.maxImages = n
	p.mu.Unlock()
}
func (p *Pool) SetIdleTTL(d time.Duration) {
	p.mu.Lock()
	p.idleTTL = d
	p.mu.Unlock()
}
func (p *Pool) Metrics() *Metrics { return p.metrics }

// PinTarget registers a key warmed from daemon start (never idle-expires).
func (p *Pool) PinTarget(key Key) {
	ks := key.KeyString()
	p.mu.Lock()
	p.pinned[ks] = struct{}{}
	p.targets[ks] = key
	p.mu.Unlock()
}

// NoteTarget registers a miss-driven refill target with LRU bounds.
func (p *Pool) NoteTarget(key Key) {
	ks := key.KeyString()
	if ks == "" || key.Image == "" {
		return
	}
	var evicted []*ParkedSlot
	p.mu.Lock()
	if _, pinned := p.pinned[ks]; !pinned {
		if p.maxImages > 0 && len(p.targets) >= p.maxImages {
			evicted = p.evictLRUTargetLocked()
		}
	}
	p.targets[ks] = key
	p.lastUsed[ks] = time.Now().UTC()
	p.mu.Unlock()
	p.destroySlots(context.Background(), evicted)
}

// evictLRUTargetLocked removes the least-recently-used non-pinned target from
// the maps and returns its parked slots. The caller destroys them after
// releasing p.mu — destruction talks to the Docker engine, and the old
// unlock-relock-in-place pattern let concurrent map writers interleave with a
// half-finished eviction.
func (p *Pool) evictLRUTargetLocked() []*ParkedSlot {
	var oldest string
	var oldestAt time.Time
	for ks := range p.targets {
		if _, pinned := p.pinned[ks]; pinned {
			continue
		}
		used := p.lastUsed[ks]
		if oldest == "" || used.Before(oldestAt) {
			oldest = ks
			oldestAt = used
		}
	}
	if oldest == "" {
		return nil
	}
	delete(p.targets, oldest)
	delete(p.lastUsed, oldest)
	slots := p.ready[oldest]
	delete(p.ready, oldest)
	delete(p.spawning, oldest)
	delete(p.spawnFails, oldest)
	return slots
}

// maxConsecutiveSpawnFails is how many refill parks in a row may fail before
// a miss-driven target is dropped. Without eviction, a target whose image is
// gone for good (a one-off snapshot or build tag that image-GC removed)
// wedges the refill loop into a permanent every-tick retry. Six failures is
// ~30s at the default 5s interval — long enough to ride out a transient
// registry blip, short enough that a dead image stops burning engine calls.
// A later create of the same image re-registers the target via NoteMiss, so
// eviction is never sticky. Pinned targets are operator config and are
// exempt: silently dropping them would hide a config error.
const maxConsecutiveSpawnFails = 6

// NoteSpawnFailure counts a failed park for key and evicts the target once
// the consecutive-failure threshold is crossed. Returns true when the target
// was evicted. Slot destruction happens outside the lock (same rationale as
// Acquire/NoteTarget).
func (p *Pool) NoteSpawnFailure(ks string) bool {
	var evicted []*ParkedSlot
	p.mu.Lock()
	p.spawnFails[ks]++
	_, pinned := p.pinned[ks]
	evict := !pinned && p.spawnFails[ks] >= maxConsecutiveSpawnFails
	if evict {
		evicted = p.ready[ks]
		delete(p.targets, ks)
		delete(p.lastUsed, ks)
		delete(p.ready, ks)
		delete(p.spawning, ks)
		delete(p.spawnFails, ks)
		p.publishParkedLocked()
		if p.metrics != nil {
			p.metrics.recordTargetEvict()
		}
	}
	p.mu.Unlock()
	p.destroySlots(context.Background(), evicted)
	return evict
}

// ClearSpawnFailures resets the consecutive-failure count after a successful
// park, so the eviction threshold only ever measures an unbroken run.
func (p *Pool) ClearSpawnFailures(ks string) {
	p.mu.Lock()
	delete(p.spawnFails, ks)
	p.mu.Unlock()
}

// HasReady reports whether any slot is queued for key. It exists so the
// create path can skip the image-inspect engine call on a guaranteed miss —
// keeping the miss path free of added boot-path work.
func (p *Pool) HasReady(key Key) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready[key.KeyString()]) > 0
}

// NoteMiss registers a miss without scanning the queue: the target is noted
// for self-warming, the miss is counted, and refill is kicked — the same
// side effects an empty-queue Acquire would have had.
func (p *Pool) NoteMiss(key Key) {
	p.NoteTarget(key)
	p.mu.Lock()
	if p.metrics != nil {
		p.metrics.recordMiss()
	}
	p.kickRefillLocked()
	p.mu.Unlock()
}

// Acquire removes one warm slot for key. imageID is re-validated at hand-out.
// Dead and stale-image slots found along the way are pruned and destroyed —
// container, netrules, AND park reservation — otherwise their DROP rules and
// admitter reservations outlive the container object. All queue surgery
// happens under one continuous lock hold; releasing p.mu mid-scan let a
// concurrent RecordLoaded slot be clobbered by a stale slice write-back.
func (p *Pool) Acquire(ctx context.Context, key Key, currentImageID string) (*ParkedSlot, error) {
	p.NoteTarget(key)
	ks := key.KeyString()

	var picked *ParkedSlot
	var discardDead, discardStale []*ParkedSlot

	p.mu.Lock()
	p.lastUsed[ks] = time.Now().UTC()
	q := p.ready[ks]
	keep := q[:0]
	for _, slot := range q {
		switch {
		case slot == nil || slot.Handle == nil || !slot.Handle.Alive():
			if slot != nil {
				discardDead = append(discardDead, slot)
			}
		case currentImageID != "" && slot.ImageID != "" && slot.ImageID != currentImageID:
			discardStale = append(discardStale, slot)
		case picked == nil:
			picked = slot
		default:
			keep = append(keep, slot)
		}
	}
	p.ready[ks] = keep
	p.publishParkedLocked()
	if p.metrics != nil {
		for range discardDead {
			p.metrics.recordOrphan()
		}
		for range discardStale {
			p.metrics.recordStaleImage()
		}
		if picked != nil {
			p.metrics.recordHit()
		} else {
			p.metrics.recordMiss()
		}
	}
	if picked == nil {
		p.kickRefillLocked()
	}
	p.mu.Unlock()

	p.destroySlots(ctx, discardDead)
	p.destroySlots(ctx, discardStale)

	if picked == nil {
		return nil, ErrNoSlot
	}
	return picked, nil
}

func (p *Pool) kickRefillLocked() {
	if p.refillKick == nil {
		return
	}
	select {
	case p.refillKick <- struct{}{}:
	default:
	}
}

// ReturnSlot puts an acquired-but-untouched slot back into the ready queue
// (duplicate-create rename conflict: the parked container was never adopted).
// Unlike RecordLoaded it does not decrement the in-flight spawn counter — no
// spawn completed here, and skewing that counter makes SpawnBudget park past
// depth, each excess slot pinning a park reservation.
func (p *Pool) ReturnSlot(slot *ParkedSlot) {
	if slot == nil {
		return
	}
	ks := slot.Key.KeyString()
	p.mu.Lock()
	p.ready[ks] = append(p.ready[ks], slot)
	p.publishParkedLocked()
	p.mu.Unlock()
}

// RecordLoaded pushes a freshly parked slot into the ready queue.
func (p *Pool) RecordLoaded(slot *ParkedSlot) {
	if slot == nil {
		return
	}
	ks := slot.Key.KeyString()
	p.mu.Lock()
	p.ready[ks] = append(p.ready[ks], slot)
	if p.spawning[ks] > 0 {
		p.spawning[ks]--
	}
	p.publishParkedLocked()
	p.mu.Unlock()
}

func (p *Pool) publishParkedLocked() {
	total := 0
	for _, q := range p.ready {
		total += len(q)
	}
	if p.metrics != nil {
		p.metrics.setParked(total)
	}
}

// MarkSpawning increments in-flight spawn counter for key string.
func (p *Pool) MarkSpawning(ks string) {
	p.mu.Lock()
	p.spawning[ks]++
	p.mu.Unlock()
}

// UnmarkSpawning decrements in-flight spawn counter after failed warm.
func (p *Pool) UnmarkSpawning(ks string) {
	p.mu.Lock()
	if p.spawning[ks] > 0 {
		p.spawning[ks]--
	}
	p.mu.Unlock()
}

// SpawnBudget returns how many slots refill should create for key on this tick.
func (p *Pool) SpawnBudget(ks string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	depth := p.defaultDepth
	if depth <= 0 {
		return 0
	}
	if _, ok := p.targets[ks]; !ok {
		return 0
	}
	ready := len(p.ready[ks])
	inFlight := p.spawning[ks]
	want := depth - ready - inFlight
	if want < 0 {
		return 0
	}
	return want
}

// ListTargets returns keys eligible for refill.
func (p *Pool) ListTargets() []Key {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Key, 0, len(p.targets))
	for _, k := range p.targets {
		if k.Image != "" {
			out = append(out, k)
		}
	}
	return out
}

// ReapIdle drops non-pinned targets with no recent use past idleTTL.
// Map surgery happens under one lock hold; slot destruction after unlock
// (same rationale as Acquire/NoteTarget).
func (p *Pool) ReapIdle(now time.Time) int {
	if p.idleTTL <= 0 {
		return 0
	}
	var reaped []*ParkedSlot
	p.mu.Lock()
	for ks := range p.targets {
		if _, pinned := p.pinned[ks]; pinned {
			continue
		}
		last := p.lastUsed[ks]
		if !last.IsZero() && now.Sub(last) < p.idleTTL {
			continue
		}
		reaped = append(reaped, p.ready[ks]...)
		delete(p.targets, ks)
		delete(p.lastUsed, ks)
		delete(p.ready, ks)
		delete(p.spawning, ks)
		delete(p.spawnFails, ks)
	}
	p.publishParkedLocked()
	p.mu.Unlock()
	p.destroySlots(context.Background(), reaped)
	return len(reaped)
}

// Close drains all warm slots.
func (p *Pool) Close() int {
	p.mu.Lock()
	var slots []*ParkedSlot
	for _, q := range p.ready {
		for _, slot := range q {
			if slot != nil {
				slots = append(slots, slot)
			}
		}
	}
	p.ready = make(map[string][]*ParkedSlot)
	p.mu.Unlock()
	p.destroySlots(context.Background(), slots)
	if p.metrics != nil {
		p.metrics.setParked(0)
	}
	return len(slots)
}

// NewSlotID mints a unique pool slot identifier.
func NewSlotID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "park-" + hex.EncodeToString(b[:]), nil
}
