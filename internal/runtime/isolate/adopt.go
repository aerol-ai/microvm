package isolate

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A V8-isolate sandbox outlives the sandboxd that started it: its workerd
// keeps running (pkg/isolate, adopt.go), and at boot this driver takes the
// group hosts over and registers again each started sandbox one of them
// still holds, so its isolate keeps its in-memory state. A started sandbox
// no host holds (its workerd died, or a release before this one ran it in
// sandboxd's cgroup) is registered for a reload: its next request starts a
// fresh isolate, as after an idle-TTL reap. Before, reconcile found the
// driver empty and deleted the row 1.4 s after boot (T14).

// AdoptedGroup is a group host the supervisor took over at boot. Key is
// the host's own key (its run dir, chroot and cgroup); Loaded are the
// sandboxes it held.
type AdoptedGroup struct {
	Key    string
	Host   GroupHost
	Loaded []string
}

// groupAdopter is the supervisor half of boot adoption (workerdSupervisor).
type groupAdopter interface {
	AdoptGroups(ctx context.Context) []AdoptedGroup
}

// AdoptReport counts what AdoptSandboxes did with the started rows.
type AdoptReport struct {
	Groups    int // group hosts taken over
	Adopted   int // sandboxes whose isolate kept running
	Reloading int // sandboxes registered for a fresh isolate on next use
}

// AdoptSandboxes takes over the group hosts a previous sandboxd left running
// and registers every started isolate row: on the host that still holds it,
// or for a reload. Call it once at boot, before any create or reconcile.
// Rows that are not started isolate rows are ignored. Each adopted sandbox
// gets the egress policy the row names but no secrets; the service sets
// the full policy right after (Service.AdoptIsolateSandboxes). Its egress
// slot is the one it had, so its isolate is the same one.
func (d *Driver) AdoptSandboxes(ctx context.Context, rows []*models.Sandbox) AdoptReport {
	var report AdoptReport
	started := make(map[string]*models.Sandbox, len(rows))
	for _, sb := range rows {
		if sb != nil && sb.Runtime == models.RuntimeIsolate && sb.Status == models.SandboxStatusStarted {
			started[sb.ID] = sb
		}
	}
	var hosts []AdoptedGroup
	if adopter, ok := d.supervisor.(groupAdopter); ok {
		hosts = adopter.AdoptGroups(ctx)
	}
	adopted := make(map[string]bool)
	for _, h := range hosts {
		if d.adoptGroup(ctx, h, started, adopted) {
			report.Groups++
		}
	}
	for id, sb := range started {
		if adopted[id] {
			report.Adopted++
			continue
		}
		d.registerForReload(sb)
		report.Reloading++
	}
	if d.logger != nil && (report.Groups+report.Adopted+report.Reloading) > 0 {
		d.logger.Info("isolate adopt: sandboxes from the previous sandboxd",
			"groups", report.Groups, "adopted", report.Adopted, "reloading", report.Reloading)
	}
	return report
}

// adoptGroup re-pins the started sandboxes a host still holds and registers
// the host under their group key. A host with none left, or whose group
// key is already taken, is stopped. It reports whether the host was kept.
func (d *Driver) adoptGroup(ctx context.Context, h AdoptedGroup, started map[string]*models.Sandbox, adopted map[string]bool) bool {
	groupKey := ""
	members := map[string]struct{}{}
	type member struct {
		sb  *models.Sandbox
		rec *sandboxRecord
	}
	var kept []member
	for _, id := range h.Loaded {
		sb := started[id]
		key, keyErr := "", error(nil)
		if sb != nil {
			key, keyErr = d.groupKeyForCreate(sb.TenantID, sb.ID)
		}
		// A sandbox the row no longer runs here, or one that belongs to
		// another group (the granularity changed), leaves this host.
		if sb == nil || keyErr != nil || (groupKey != "" && key != groupKey) || d.resolver == nil {
			h.Host.Unload(id)
			continue
		}
		ref := localBundleRef(sb)
		bundle, err := d.resolver.Resolve(ctx, sb.TenantID, ref)
		if err == nil {
			err = h.Host.Load(id, bundle)
		}
		if err != nil {
			if d.logger != nil {
				d.logger.Warn("isolate adopt: bundle not pinned again; sandbox reloads on next use", "sandbox_id", id, "error", err)
			}
			h.Host.Unload(id)
			continue
		}
		groupKey = key
		members[id] = struct{}{}
		kept = append(kept, member{sb: sb, rec: &sandboxRecord{
			state: &models.SandboxRuntimeState{
				SandboxID:    sb.ID,
				Status:       models.SandboxStatusStarted,
				ModuleRef:    ref,
				ModuleDigest: bundle.Digest,
				ModulePath:   bundle.Digest,
				ContainerIP:  "127.0.0.1",
			},
			groupKey:  key,
			tenantID:  sb.TenantID,
			bundleRef: ref,
			egress:    rowPolicy(sb),
		}})
	}
	d.groupsMu.Lock()
	taken := groupKey != "" && d.groups[groupKey] != nil
	if len(kept) > 0 && !taken {
		d.groups[groupKey] = &group{key: groupKey, host: h.Host, lastUsed: timeNow(), members: members}
	}
	d.groupsMu.Unlock()
	if len(kept) == 0 || taken {
		_ = h.Host.Stop()
		return false
	}
	d.mu.Lock()
	for _, m := range kept {
		d.byID[m.sb.ID] = m.rec
		adopted[m.sb.ID] = true
	}
	d.mu.Unlock()
	return true
}

// registerForReload registers a started sandbox whose isolate did not
// survive: kept, and given a fresh isolate on its next request, like a
// sandbox whose group the idle reaper stopped.
func (d *Driver) registerForReload(sb *models.Sandbox) {
	ref := localBundleRef(sb)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byID[sb.ID] != nil {
		return
	}
	d.byID[sb.ID] = &sandboxRecord{
		state: &models.SandboxRuntimeState{
			SandboxID:    sb.ID,
			Status:       models.SandboxStatusStopped,
			ModuleRef:    ref,
			ModuleDigest: sb.ModuleDigest,
			ModulePath:   sb.ModuleDigest,
			ContainerIP:  "127.0.0.1",
		},
		tenantID:    sb.TenantID,
		bundleRef:   ref,
		egress:      rowPolicy(sb),
		needsReload: true,
	}
}

// localBundleRef is the bundle reference this node resolves: a cluster row
// stores the node-bound form.
func localBundleRef(sb *models.Sandbox) string {
	ref := strings.TrimSpace(sb.ModuleRef)
	if ref == "" {
		ref = strings.TrimSpace(sb.Image)
	}
	if _, local, ok := models.ParseJSBundleNodeRef(ref); ok {
		return local
	}
	return ref
}

// rowPolicy is the egress policy a row names, without its secrets (the
// service supplies those).
func rowPolicy(sb *models.Sandbox) EgressPolicy {
	return policyFromCreate(sb.NetworkBlockAll, sb.NetworkAllowOut, sb.NetworkDenyOut,
		sb.NetworkEgressMode == models.NetworkEgressModeLearn, ruleSpecs(sb.NetworkEgressRules), nil)
}
