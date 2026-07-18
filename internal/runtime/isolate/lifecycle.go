package isolate

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// RunIdleReaper tears down isolate-group processes that have been idle longer
// than cfg.IdleTTL (plans/isolate-runtime.md §11 I22 / Phase 2 leftover).
// Last-member teardown already stops empty groups; this reaper covers the
// scale-to-zero case — a group that still has pinned sandboxes but has seen
// no Create/Invoke traffic for IdleTTL. Members are marked stopped and their
// bundles stay in the content-addressed store so the next Start/Create path
// can respawn the group and re-pin.
//
// Nil or non-positive IdleTTL disables the reaper (tests / operators that want
// groups sticky until last-member teardown). The loop exits when ctx is
// cancelled.
func (d *Driver) RunIdleReaper(ctx context.Context) {
	ttl := d.cfg.IdleTTL
	if ttl <= 0 {
		return
	}
	// Tick at ttl/2 so a group that crosses the threshold is reaped within
	// roughly one TTL of going idle, without waking every few ms.
	interval := ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.reapIdleGroups(ttl)
		}
	}
}

// reapIdleGroups stops every group whose lastUsed is older than ttl. Extracted
// so tests can drive a single sweep without sleeping on the ticker.
func (d *Driver) reapIdleGroups(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	now := time.Now()
	type victim struct {
		key  string
		host GroupHost
	}
	var victims []victim

	d.groupsMu.Lock()
	for key, g := range d.groups {
		if g == nil {
			continue
		}
		last := g.lastUsed
		if last.IsZero() {
			last = now // freshly spawned, give it a full TTL
			g.lastUsed = last
		}
		if now.Sub(last) < ttl {
			continue
		}
		// Remove before Stop so a concurrent acquireGroup spawns fresh
		// rather than joining a host we are about to kill.
		delete(d.groups, key)
		victims = append(victims, victim{key: key, host: g.host})
	}
	d.groupsMu.Unlock()

	for _, v := range victims {
		d.markGroupMembersStopped(v.key)
		_ = v.host.Stop()
	}
}

// markGroupMembersStopped flips every sandbox pinned to groupKey to Stopped
// and clears the groupKey so a later Destroy is a no-op against the dead host.
// The sandbox record stays in byID so Inspect/ListManaged still see it; Start
// re-acquires a group and re-loads the bundle.
func (d *Driver) markGroupMembersStopped(groupKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, rec := range d.byID {
		if rec != nil && rec.groupKey == groupKey {
			rec.state.Status = models.SandboxStatusStopped
			rec.groupKey = ""
			rec.needsReload = true
		}
	}
}

// touchGroup records activity on a live group so the idle reaper leaves it alone.
func (d *Driver) touchGroup(groupKey string) {
	d.groupsMu.Lock()
	if g := d.groups[groupKey]; g != nil {
		g.lastUsed = time.Now()
	}
	d.groupsMu.Unlock()
}
