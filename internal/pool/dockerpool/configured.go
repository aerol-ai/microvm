package dockerpool

import (
	"context"
	"sort"
)

// API warm-pool entries (plans/agent-sandbox-feature-parity.md W1). The
// service hands the pool the whole set every time it changes; each entry
// pins its key and sets that key's depth. Every other target keeps
// defaultDepth, so the SB_*_POOL_* settings stay the default for images no
// entry names.

// Configured is one API warm-pool entry as this pool applies it. With
// MaxDepth > 0 the depth follows demand between MinDepth and MaxDepth
// (demand.go) and Depth is unused.
type Configured struct {
	Key      Key
	Depth    int
	MinDepth int
	MaxDepth int
	// ReplaceAsUsed keeps slots holding an older image and hands them out
	// until they are used up (W3); false replaces them at once.
	ReplaceAsUsed bool
}

func (c Configured) followsDemand() bool { return c.MaxDepth > 0 }

// TargetStatus is one configured entry's state in this pool. Outdated is
// the ready slots holding an older image than the tag names now.
type TargetStatus struct {
	Key      Key
	Ready    int
	Target   int
	Outdated int
}

// SetConfigured replaces the configured entries. A new entry is pinned (it
// never idle-expires and is reclaimed last) and refill is kicked so it
// starts parking now. A removed entry's slots are destroyed at once, unless
// the same image is an env pin: then it simply drops back to the default
// depth. A lower depth is trimmed on the next refill tick.
func (p *Pool) SetConfigured(entries []Configured) {
	if p == nil {
		return
	}
	next := make(map[string]Configured, len(entries))
	for _, e := range entries {
		ks := e.Key.KeyString()
		if e.Key.Image == "" || ks == "" {
			continue
		}
		next[ks] = e
	}
	var drained []*ParkedSlot
	p.mu.Lock()
	for ks := range p.configured {
		if _, kept := next[ks]; kept {
			continue
		}
		// The image check follows entries only, so nothing reads this key's
		// image again. A key that stays (an env pin, below) must not keep
		// the last ID: containerd's Acquire falls back to it and, after a
		// retag, would throw away every newly parked slot as stale.
		delete(p.currentImage, ks)
		if _, env := p.envPins[ks]; env {
			// Back to the env pin at the default depth. trimExcess only
			// walks entries, so give back what the entry held above it here.
			if q := p.ready[ks]; len(q) > p.defaultDepth {
				drained = append(drained, q[p.defaultDepth:]...)
				p.ready[ks] = q[:p.defaultDepth:p.defaultDepth]
			}
			continue
		}
		drained = append(drained, p.ready[ks]...)
		delete(p.pinned, ks)
		delete(p.targets, ks)
		delete(p.lastUsed, ks)
		delete(p.ready, ks)
		delete(p.spawnFails, ks)
		// spawning stays: a park in flight for this key decrements it when
		// it lands, and recordParked destroys that slot because the key is
		// no longer a target.
	}
	for ks, e := range next {
		p.pinned[ks] = struct{}{}
		p.targets[ks] = e.Key
	}
	p.configured = next
	p.reconcileDemandLocked()
	p.publishParkedLocked()
	p.kickRefillLocked()
	p.mu.Unlock()
	p.destroySlots(context.Background(), drained)
}

// depthLocked is the depth refill aims for on ks: the entry's, else the
// default.
func (p *Pool) depthLocked(ks string) int {
	c, ok := p.configured[ks]
	if !ok {
		return p.defaultDepth
	}
	if c.followsDemand() {
		if st := p.demand[ks]; st != nil {
			return st.target
		}
		return c.MinDepth
	}
	return c.Depth
}

// trimExcess takes the ready slots a configured key holds beyond its depth
// (after its depth was lowered), newest first, so the slots that are left
// are the ones parked longest ago. A replace_as_used entry gives back its
// outdated slots before its current ones, so a shrink also moves the
// rollout along. Only entries are trimmed: a default-depth
// target keeps today's behaviour.
func (p *Pool) trimExcess() []*ParkedSlot {
	var out []*ParkedSlot
	p.mu.Lock()
	for ks := range p.configured {
		q := p.ready[ks]
		depth := p.depthLocked(ks)
		if len(q) <= depth {
			continue
		}
		if p.configured[ks].ReplaceAsUsed {
			q = p.currentFirstLocked(ks, q)
		}
		out = append(out, q[depth:]...)
		p.ready[ks] = q[:depth:depth]
	}
	if len(out) > 0 {
		p.publishParkedLocked()
	}
	p.mu.Unlock()
	return out
}

// recordParked queues a slot a refill just parked, unless its key stopped
// being a target while the park ran (the entry was deleted or the target
// reaped). It reports whether the slot was queued; the caller destroys one
// that was not, or it would sit unreachable holding its park reservation.
func (p *Pool) recordParked(slot *ParkedSlot) bool {
	ks := slot.Key.KeyString()
	p.mu.Lock()
	if p.spawning[ks] > 0 {
		p.spawning[ks]--
	}
	if _, ok := p.targets[ks]; !ok {
		p.mu.Unlock()
		return false
	}
	p.ready[ks] = append(p.ready[ks], slot)
	p.publishParkedLocked()
	p.mu.Unlock()
	p.notifyParkReady(slot.ID, true)
	return true
}

// ConfiguredStatus reports every configured entry's ready count and target
// on this pool, sorted by image.
func (p *Pool) ConfiguredStatus() []TargetStatus {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	out := make([]TargetStatus, 0, len(p.configured))
	for ks, c := range p.configured {
		out = append(out, TargetStatus{Key: c.Key, Ready: len(p.ready[ks]), Target: p.depthLocked(ks), Outdated: p.outdatedLocked(ks)})
	}
	p.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Key.KeyString() < out[j].Key.KeyString() })
	return out
}
