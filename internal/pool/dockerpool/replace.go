package dockerpool

import (
	"context"
	"time"
)

// Rolling replace when an entry's image changes (plans/agent-sandbox-
// feature-parity.md W3). The tag an entry names can come to mean a newer
// image on a server: a pull for a tenant create re-reads the registry, a
// build or a prepull retags it. Parked slots still run the old one.
//
//   - replace_now (the default): the refill tick resolves what each entry's
//     tag names now, destroys every ready slot holding another image and
//     parks fresh ones. A create never gets an old-image slot, whichever
//     engine serves it.
//   - replace_as_used: old slots stay and are handed out oldest first, so
//     creates keep starting warm; each one used is refilled with the new
//     image, so the pool turns over as fast as it is used.
//
// Entries only: a default-depth target keeps its engine's own check (the
// docker driver re-validates at hand-out, containerd does not).

// ImageResolver returns the image ID a key's image names on this server
// now, from local state only: it never pulls. The ID must be in the form
// the spawner records in ParkedSlot.ImageID.
type ImageResolver func(ctx context.Context, key Key) (string, error)

// imageCheckEvery bounds the lookups: a refill tick can be kicked on every
// miss, and one lookup per entry per interval is enough to notice a retag.
const imageCheckEvery = 5 * time.Second

// SetImageResolver wires the lookup the image-change check uses. Nil (the
// default) turns the check off: every slot counts as current.
func (p *Pool) SetImageResolver(r ImageResolver) {
	p.mu.Lock()
	p.resolver = r
	p.mu.Unlock()
}

// refreshImages resolves each entry's current image (outside the lock: it
// talks to the engine) and takes the ready slots a replace_now entry holds
// with another image. The caller destroys them; refill parks their
// replacements on the same tick.
func (p *Pool) refreshImages(ctx context.Context) []*ParkedSlot {
	now := p.clock()
	p.mu.Lock()
	resolver := p.resolver
	if resolver == nil || (!p.lastImageCheck.IsZero() && now.Sub(p.lastImageCheck) < imageCheckEvery) {
		p.mu.Unlock()
		return nil
	}
	p.lastImageCheck = now
	keys := make(map[string]Key, len(p.configured))
	for ks, c := range p.configured {
		keys[ks] = c.Key
	}
	p.mu.Unlock()

	resolved := make(map[string]string, len(keys))
	for ks, key := range keys {
		// A failed lookup (the image is not here yet, the engine is
		// busy) keeps the last answer: never destroy slots on a guess.
		if id, err := resolver(ctx, key); err == nil && id != "" {
			resolved[ks] = id
		}
	}

	var out []*ParkedSlot
	p.mu.Lock()
	for ks, id := range resolved {
		c, ok := p.configured[ks]
		if !ok {
			continue // deleted while resolving
		}
		p.currentImage[ks] = id
		if c.ReplaceAsUsed {
			continue
		}
		q := p.ready[ks]
		keep := q[:0]
		for _, slot := range q {
			if slot != nil && slot.ImageID != "" && slot.ImageID != id {
				out = append(out, slot)
				continue
			}
			keep = append(keep, slot)
		}
		p.ready[ks] = keep
	}
	if len(out) > 0 {
		p.publishParkedLocked()
		if p.metrics != nil {
			p.metrics.recordReplaced(len(out))
		}
	}
	p.mu.Unlock()
	return out
}

// isOutdatedLocked reports a slot holding an older image than the entry's
// tag names now. Unknown on either side is not outdated.
func (p *Pool) isOutdatedLocked(ks string, slot *ParkedSlot) bool {
	cur := p.currentImage[ks]
	return cur != "" && slot != nil && slot.ImageID != "" && slot.ImageID != cur
}

func (p *Pool) outdatedLocked(ks string) int {
	n := 0
	for _, slot := range p.ready[ks] {
		if p.isOutdatedLocked(ks, slot) {
			n++
		}
	}
	return n
}

// currentFirstLocked reorders a queue so current slots come before
// outdated ones, each group keeping its order. A trim cuts from the back,
// so it gives back outdated slots first.
func (p *Pool) currentFirstLocked(ks string, q []*ParkedSlot) []*ParkedSlot {
	out := make([]*ParkedSlot, 0, len(q))
	var old []*ParkedSlot
	for _, slot := range q {
		if p.isOutdatedLocked(ks, slot) {
			old = append(old, slot)
			continue
		}
		out = append(out, slot)
	}
	return append(out, old...)
}
