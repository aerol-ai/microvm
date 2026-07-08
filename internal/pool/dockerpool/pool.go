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
	p.mu.Lock()
	if _, pinned := p.pinned[ks]; !pinned {
		if p.maxImages > 0 && len(p.targets) >= p.maxImages {
			p.evictLRUTargetLocked()
		}
	}
	p.targets[ks] = key
	p.lastUsed[ks] = time.Now().UTC()
	p.mu.Unlock()
}

func (p *Pool) evictLRUTargetLocked() {
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
		return
	}
	delete(p.targets, oldest)
	delete(p.lastUsed, oldest)
	slots := p.ready[oldest]
	delete(p.ready, oldest)
	delete(p.spawning, oldest)
	spawner := p.spawner
	p.mu.Unlock()
	for _, slot := range slots {
		if spawner != nil && slot != nil {
			_ = spawner.DestroyParked(context.Background(), slot)
		}
	}
	p.mu.Lock()
}

// Acquire removes one warm slot for key. imageID is re-validated at hand-out.
func (p *Pool) Acquire(ctx context.Context, key Key, currentImageID string) (*ParkedSlot, error) {
	p.NoteTarget(key)
	ks := key.KeyString()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastUsed[ks] = time.Now().UTC()

	q := p.ready[ks]
	for i := len(q) - 1; i >= 0; i-- {
		slot := q[i]
		if slot == nil || slot.Handle == nil || !slot.Handle.Alive() {
			q = append(q[:i], q[i+1:]...)
			if p.metrics != nil {
				p.metrics.recordOrphan()
			}
			continue
		}
		if currentImageID != "" && slot.ImageID != "" && slot.ImageID != currentImageID {
			dead := slot
			q = append(q[:i], q[i+1:]...)
			spawner := p.spawner
			p.ready[ks] = q
			p.mu.Unlock()
			if spawner != nil {
				_ = spawner.DestroyParked(ctx, dead)
				p.releasePark(dead.ID)
			}
			if p.metrics != nil {
				p.metrics.recordStaleImage()
			}
			p.mu.Lock()
			continue
		}
		p.ready[ks] = append(q[:i], q[i+1:]...)
		p.publishParkedLocked()
		if p.metrics != nil {
			p.metrics.recordHit()
		}
		return slot, nil
	}
	p.ready[ks] = q
	if p.metrics != nil {
		p.metrics.recordMiss()
	}
	p.kickRefillLocked()
	return nil, ErrNoSlot
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
func (p *Pool) ReapIdle(now time.Time) int {
	if p.idleTTL <= 0 {
		return 0
	}
	p.mu.Lock()
	var reaped int
	spawner := p.spawner
	for ks := range p.targets {
		if _, pinned := p.pinned[ks]; pinned {
			continue
		}
		last := p.lastUsed[ks]
		if !last.IsZero() && now.Sub(last) < p.idleTTL {
			continue
		}
		slots := append([]*ParkedSlot(nil), p.ready[ks]...)
		delete(p.targets, ks)
		delete(p.lastUsed, ks)
		delete(p.ready, ks)
		delete(p.spawning, ks)
		reaped += len(slots)
		p.mu.Unlock()
		for _, slot := range slots {
			if spawner != nil && slot != nil {
				_ = spawner.DestroyParked(context.Background(), slot)
				p.releasePark(slot.ID)
			}
		}
		p.mu.Lock()
	}
	p.publishParkedLocked()
	p.mu.Unlock()
	return reaped
}

// Close drains all warm slots.
func (p *Pool) Close() int {
	p.mu.Lock()
	var slots []*ParkedSlot
	for _, q := range p.ready {
		slots = append(slots, q...)
	}
	p.ready = make(map[string][]*ParkedSlot)
	spawner := p.spawner
	p.mu.Unlock()
	drained := 0
	for _, slot := range slots {
		if spawner != nil && slot != nil {
			_ = spawner.DestroyParked(context.Background(), slot)
			p.releasePark(slot.ID)
			drained++
		}
	}
	if p.metrics != nil {
		p.metrics.setParked(0)
	}
	return drained
}

// NewSlotID mints a unique pool slot identifier.
func NewSlotID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "park-" + hex.EncodeToString(b[:]), nil
}
