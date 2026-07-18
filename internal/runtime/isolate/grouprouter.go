package isolate

import (
	"context"
	"fmt"
	"time"
)

// The group router (plans/isolate-runtime.md §2.1). Sandboxes are placed into
// isolate GROUPS; each group is one workerd OS process. The router maps a
// group key to its running host and single-flights the spawn so N concurrent
// first-creates for the same tenant produce ONE process, not N (§11
// "concurrent first-creates … single-flighted by the group router"). Later
// creates for a live group just join it and never spawn.

// groupKeyForCreate derives the isolate-group key from the request and the
// configured granularity (§2.1). per-tenant (default): the authorized tenant
// id, empty falling back to the shared default group; per-sandbox (the
// hostile-code tier): the sandbox id, so every sandbox is its own process.
// The key is sanitized because it becomes a chroot dir + cgroup name.
func (d *Driver) groupKeyForCreate(tenantID, sandboxID string) (string, error) {
	raw := tenantID
	if d.cfg.GroupGranularity == GroupPerSandbox {
		raw = sandboxID
	}
	return SanitizeGroupKey(raw)
}

// acquireGroup returns the running host for groupKey and registers sandboxID as
// a member of that group, spawning the group under a per-key single-flight if it
// does not exist yet. cpu/memMB are the group's resource caps for the jail spec
// (Phase 4 refines the mapping). The returned host is owned by the router;
// callers must not Stop it — teardown goes through the last-member path in
// Destroy. Registering the member here, under groupsMu and before the caller's
// out-of-lock host.Load, is what closes the join-vs-teardown race: a concurrent
// last-member release sees this id in members and does not tear the group down.
func (d *Driver) acquireGroup(ctx context.Context, groupKey, sandboxID string, cpu float64, memMB int) (GroupHost, error) {
	if d.supervisor == nil {
		return nil, fmt.Errorf("isolate: host supervisor not registered")
	}
	for {
		d.groupsMu.Lock()
		if g := d.groups[groupKey]; g != nil {
			g.members[sandboxID] = struct{}{}
			g.lastUsed = timeNow()
			d.groupsMu.Unlock()
			return g.host, nil
		}
		// A spawn is already in flight for this key: wait for it and re-check
		// rather than spawn a duplicate process.
		if ch, inflight := d.spawning[groupKey]; inflight {
			d.groupsMu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		// We own the spawn for this key.
		ch := make(chan struct{})
		d.spawning[groupKey] = ch
		d.groupsMu.Unlock()

		host, err := d.spawnGroup(ctx, groupKey, cpu, memMB)

		d.groupsMu.Lock()
		delete(d.spawning, groupKey)
		close(ch)
		if err != nil {
			d.groupsMu.Unlock()
			return nil, err
		}
		d.groups[groupKey] = &group{
			key:      groupKey,
			host:     host,
			lastUsed: timeNow(),
			members:  map[string]struct{}{sandboxID: {}},
		}
		d.groupsMu.Unlock()
		return host, nil
	}
}

// timeNow is stubbed in idle-reaper tests.
var timeNow = func() time.Time { return time.Now() }

// spawnGroup builds the group's jail spec and asks the supervisor to realize
// it. Held outside groupsMu so a slow workerd spawn does not block the router.
// When a warm pool is wired, a blank host is claimed first (group router runs
// before the pool: only a tenant's FIRST create reaches here).
func (d *Driver) spawnGroup(ctx context.Context, groupKey string, cpu float64, memMB int) (GroupHost, error) {
	if d.warmPool != nil {
		if host, ok := d.warmPool.Acquire(ctx); ok && host != nil {
			return host, nil
		}
	}
	spec, err := BuildJailSpec(d.cfg, groupKey, cpu, memMB)
	if err != nil {
		return nil, fmt.Errorf("isolate: build jail spec for group %q: %w", groupKey, err)
	}
	host, err := d.supervisor.SpawnGroup(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("isolate: spawn group %q: %w", groupKey, err)
	}
	return host, nil
}

// releaseFromGroup removes a sandbox from its group and tears the group's
// process down when it was the last member (§2.1 last-member teardown). Safe to
// call for an unknown group/sandbox.
//
// The teardown decision is made from the router's own member set under
// groupsMu, NOT from host.Unload's pinned-bundle count: the membership delete
// and the emptiness check are one atomic critical section, so a create that has
// already registered its id in acquireGroup (before its out-of-lock host.Load)
// keeps the group alive until that create either commits or releases. host is
// Unloaded (bundle pin dropped) and Stopped OUTSIDE the lock so a slow teardown
// never blocks the router.
func (d *Driver) releaseFromGroup(groupKey, sandboxID string) {
	d.groupsMu.Lock()
	g := d.groups[groupKey]
	if g == nil {
		d.groupsMu.Unlock()
		return
	}
	delete(g.members, sandboxID)
	empty := len(g.members) == 0
	if empty {
		delete(d.groups, groupKey)
	}
	d.groupsMu.Unlock()

	g.host.Unload(sandboxID)
	if empty {
		_ = g.host.Stop()
	}
}
