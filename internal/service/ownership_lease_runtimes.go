package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Which sandboxes the runtime supervisor can freeze on its own (review N2).
//
// On a node that writes the ownership lease file (SB_OWNERSHIP_LEASE_FILE, a
// Kubernetes worker), the runtime supervisor freezes every failover.policy=
// recreate sandbox the file fences once the lease runs out, even with
// sandboxd down (internal/supervisor/lease.go). It freezes a cgroup, so a
// sandbox can be fenced only if it runs in a group of its own under the
// sandboxes' parent:
//
//   - a container: its container's group, named by its container ref;
//   - a Firecracker VM: its own group, aerolvm-vmm/<sandbox> (the driver's
//     FenceGroup), when the VMs' cgroup sits under that same parent (the
//     default: SB_HOST_PROCESS_CGROUP_PARENT unset, or the containerd one);
//   - a WASM or V8-isolate sandbox: never. Their host processes (a WASM
//     resident host, a workerd group host) run many sandboxes, so no group
//     holds one sandbox alone, and freezing a shared one would stop the
//     others.
//
// Before, a Firecracker VM's file entry named a group that did not exist
// and WASM and isolate sandboxes were fenced in name only: each could run
// on after the cluster recreated it elsewhere. Now a recreate-policy create
// of a runtime the supervisor cannot freeze is refused on such a node, and
// a Firecracker VM is fenced in its own group.

// fenceRef is the group the lease file names for sb, under the sandboxes'
// cgroup parent: the runtime's own (FenceGrouper), or the container ref.
func (s *Service) fenceRef(sb *models.Sandbox) string {
	if rt, err := s.runtimeForSandbox(sb); err == nil {
		if g, ok := rt.(runtime.FenceGrouper); ok {
			return g.FenceGroup(sb.ID)
		}
	}
	return s.runtimeRef(sb)
}

// leaseFreezable reports whether the runtime supervisor can freeze a
// sandbox of runtime alone, on this node.
func (s *Service) leaseFreezable(chosenRuntime string) bool {
	switch chosenRuntime {
	case models.RuntimeWasm, models.RuntimeIsolate:
		return false
	case models.RuntimeFirecracker:
		return s.cfg.HostProcessCgroupParent == "" || s.cfg.HostProcessCgroupParent == s.cfg.ContainerdCgroupParent
	}
	return true
}

// Sandboxes made before the refusal (review V4). refuseUnfencedRecreate
// stops new recreate-policy creates of a runtime the supervisor cannot
// freeze alone, but rows an older release made keep the policy and keep
// running. If this node then lost its lease, nothing here could stop them
// while the cluster recreated them elsewhere: two copies. Before, sandboxd
// only logged them at start.
//
// Now each such sandbox has its failover policy turned off, and keeps
// running: if its node dies it is lost, rather than possibly running twice.
// The cluster's replicated spec changes first (an ordinary opUpsertSpec,
// which every server applies, so no leader of any version recreates it
// after), then the local row, then its status reason (on a running one),
// an audit record and a log line. Each step reads what it changes, so a
// retry or a restart repeats nothing that is done.
//
// The same applies to a Firecracker VM a release before the per-VM groups
// left in the VMs' shared group, whose move into its own group failed at
// adoption: it is running, and nothing can freeze it alone.
//
// Until the cluster takes the change (its leader out of reach at start),
// the row keeps its policy and the lease still covers it. If the lease runs
// out first, the fence stops it (stopUnfenceable): a stopped sandbox cannot
// run twice.

const (
	// statusReasonFailoverDisabled is the reason on a running sandbox
	// whose recreate policy this node turned off.
	statusReasonFailoverDisabled = "failover_disabled"
	// statusReasonOwnershipLeaseExpired is the reason on a recreate-policy
	// sandbox the fence stopped because nothing could freeze it.
	statusReasonOwnershipLeaseExpired = "ownership_lease_expired"
	// systemActionFailoverDisabled and systemActionLeaseStop are their audit
	// records (SYSTEM <action>).
	systemActionFailoverDisabled = "failover.disabled"
	systemActionLeaseStop        = "failover.lease_stop"
)

var (
	// failoverDisabledTotal counts recreate policies this node turned off.
	failoverDisabledTotal = expvar.NewInt("aerolvm_failover_disabled_unfenceable_total")
	// errSpecUnread: the cluster holds a placement, but its spec was not
	// read (a worker's spec read reports a failed lookup as no spec).
	errSpecUnread = errors.New("the cluster's copy of the sandbox's spec could not be read")
	// errDisarmLater: the placement is between owners (reserved, or
	// orphaned but this node's to claim back); the next pass tries again.
	errDisarmLater = errors.New("its placement is between owners")
	// errPlacementMoved: read again under the spec lock, the placement
	// names another node or lifetime. Not this node's to change.
	errPlacementMoved = errors.New("its placement moved to another node or lifetime")
)

// unfenceableRecreate reports whether sb is a recreate-policy sandbox this
// node cannot freeze alone: its runtime (leaseFreezable), or, for a running
// Firecracker VM, the VM itself (recreateFenceReady).
func (s *Service) unfenceableRecreate(sb *models.Sandbox) bool {
	if sb == nil || sb.Failover == nil || !sb.Failover.ShouldRecreate() {
		return false
	}
	if !s.leaseFreezable(sb.Runtime) {
		return true
	}
	return sb.Status == models.SandboxStatusStarted && s.recreateFenceReady(sb) != nil
}

// recreateFenceReady is nil unless sb is a recreate-policy sandbox on a node
// that writes the lease file and its runtime reports a running instance
// outside the group the supervisor freezes (runtime.FenceChecker: a
// Firecracker VM whose move into aerolvm-vmm/<sandbox> failed). Only the
// instance shows that; config says only where it should be.
func (s *Service) recreateFenceReady(sb *models.Sandbox) error {
	if !s.ownershipLeaseFileOn() || sb == nil || sb.Failover == nil || !sb.Failover.ShouldRecreate() {
		return nil
	}
	rt, err := s.runtimeForSandbox(sb)
	if err != nil {
		return nil
	}
	fc, ok := rt.(runtime.FenceChecker)
	if !ok {
		return nil
	}
	if err := fc.FenceReady(s.runtimeRef(sb)); err != nil {
		return fmt.Errorf("failover.policy=recreate cannot run here: %w; if this node lost touch with the cluster, its runtime supervisor could not stop it while the cluster recreated it elsewhere", err)
	}
	return nil
}

// startDisarmUnfencedRecreate runs disarmUnfencedRecreate now and every
// interval until a pass leaves nothing to do, in its own goroutine: a
// leader out of reach must not hold up the daemon's start.
func (s *Service) startDisarmUnfencedRecreate(ctx context.Context, every time.Duration) {
	if !s.ownershipLeaseFileOn() {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			pass, cancel := context.WithTimeout(ctx, every)
			done := s.disarmUnfencedRecreate(pass)
			cancel()
			if done {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
}

// disarmUnfencedRecreate turns off the recreate policy of every local
// sandbox this node cannot freeze alone (unfenceableRecreate), on a node
// that writes the lease file. It reports whether nothing is left to retry.
// One authoritative read covers them all; a sandbox whose placement belongs
// to another node or lifetime is left to the paths that remove stale rows.
func (s *Service) disarmUnfencedRecreate(ctx context.Context) bool {
	if !s.ownershipLeaseFileOn() {
		return true
	}
	rows, err := s.localRecreateSandboxes(ctx)
	if err != nil {
		return false
	}
	var todo []*models.Sandbox
	for _, sb := range rows {
		if s.unfenceableRecreate(sb) {
			todo = append(todo, sb)
		}
	}
	if len(todo) == 0 {
		return true
	}
	c := s.Cluster()
	ids := make([]string, 0, len(todo))
	for _, sb := range todo {
		ids = append(ids, sb.ID)
	}
	placements, err := authoritativePlacementsForLease(ctx, c, ids)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: cannot turn off the recreate policy of sandboxes this node cannot freeze alone yet (no answer from the control plane); will retry, and the ownership lease stops them if it runs out first",
				"count", len(todo), "error", err)
		}
		return false
	}
	self := strings.TrimSpace(c.SelfNodeID())
	done := true
	for _, sb := range todo {
		p, placed := placements[sb.ID]
		if err := s.disarmRecreate(ctx, c, sb.ID, p, placed, self); err != nil {
			done = false
			if s.logger != nil && !errors.Is(err, errDisarmLater) {
				s.logger.Warn("cluster: could not turn off a recreate policy this node cannot enforce; will retry", "sandbox_id", sb.ID, "error", err)
			}
		}
	}
	return done
}

// disarmRecreate turns off id's recreate policy under its lifecycle
// boundary: the cluster's spec first when the cluster holds a placement
// this node owns, then the local row. Without a placement nothing in the
// cluster can recreate it, and the ownership replay rebuilds the spec from
// the row, so the row alone is enough.
func (s *Service) disarmRecreate(ctx context.Context, c cluster.Client, id string, p cluster.Placement, placed bool, self string) error {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	sb, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !s.unfenceableRecreate(sb) {
		return nil
	}
	if placed {
		err := disarmPlacementCheck(p, self, sb)
		if err == nil {
			err = s.writeFailoverNoneSpec(ctx, c, sb, self)
		}
		if errors.Is(err, errPlacementMoved) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	changed, err := s.clearRecreateFailover(ctx, sb)
	if err != nil || !changed {
		return err
	}
	if sb.Status == models.SandboxStatusStarted {
		if _, err := s.store.SetStatusReasonIfStatus(ctx, id, models.SandboxStatusStarted, statusReasonFailoverDisabled, nil); err != nil && s.logger != nil {
			s.logger.Warn("cluster: recreate policy turned off, but its status reason was not recorded", "sandbox_id", id, "error", err)
		}
	}
	why := "this node cannot freeze it alone if it loses touch with the cluster (" + s.unfenceableWhy(sb) + "), so a recreated copy could run beside it"
	s.beginSystemActionReason(withAuditSubsystem(ctx, auditSubsystemFailover), id, systemActionFailoverDisabled, why)(nil)
	failoverDisabledTotal.Add(1)
	if s.logger != nil {
		s.logger.Warn("cluster: failover.policy=recreate turned off for a sandbox this node cannot freeze alone; it keeps running, and is lost rather than recreated if this node dies",
			"sandbox_id", id, "runtime", sb.Runtime, "reason", why)
	}
	return nil
}

// disarmPlacementCheck says whether this node may turn off the recreate
// policy in p, sb's placement: nil when p is placed on this node in sb's
// lifetime, errDisarmLater while it is between owners and this node's
// (reserved, or an orphan it can claim back), and errPlacementMoved when it
// is another node's, another lifetime's, or being deleted. The stale-row
// paths remove a local row in that last case.
func disarmPlacementCheck(p cluster.Placement, self string, sb *models.Sandbox) error {
	local, remote := strings.TrimSpace(sb.AuditIncarnationID), strings.TrimSpace(p.IncarnationID)
	switch {
	case p.IsDeleting() || (local != "" && remote != "" && local != remote):
		return errPlacementMoved
	case p.IsOrphaned() || p.IsReserved():
		if strings.TrimSpace(p.OwnerNodeID) == self || placementCanBeClaimedBySelf(p, self) {
			return errDisarmLater
		}
		return errPlacementMoved
	case strings.TrimSpace(p.OwnerNodeID) != self:
		return errPlacementMoved
	}
	return nil
}

// writeFailoverNoneSpec sets the cluster's spec of sb to failover.policy=
// none, under the spec lock (writeReplicatedSpec). A spec already without
// the policy is left alone; a spec that could not be read is an error, so
// the row is not changed on a guess.
//
// The pass read sb's placement before it took any lock, and the leader can
// hand a sandbox to another node meanwhile (a dead-owner reassign while
// this node's reads still reach it). So each write attempt reads the owner
// again, after it has read the spec's version: a reassign before that read
// is seen here, and one after it moves the version, which the leader's
// version check refuses (every server at the spec version fence), so the
// next attempt sees it. The answer is disarmPlacementCheck's: a placement
// gone or now another node's is errPlacementMoved.
func (s *Service) writeFailoverNoneSpec(ctx context.Context, c cluster.Client, sb *models.Sandbox, self string) error {
	unlock, err := s.lockSpec(ctx, sb.ID)
	if err != nil {
		return err
	}
	defer unlock()
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.writeReplicatedSpec(commitCtx, c, sb.ID, func(spec *models.CreateSandboxRequest) (bool, error) {
		placements, err := c.AuthoritativePlacementsByIDs(commitCtx, []string{sb.ID})
		if err != nil {
			return false, err
		}
		p, ok := placements[sb.ID]
		if !ok {
			return false, errPlacementMoved
		}
		if err := disarmPlacementCheck(p, self, sb); err != nil {
			return false, err
		}
		if spec == nil {
			return false, errSpecUnread
		}
		if !spec.ShouldRecreateOnFailover() {
			return false, nil
		}
		spec.Failover = &models.Failover{Policy: models.FailoverPolicyNone}
		return true, nil
	})
}

// unfenceableWhy names why sb cannot be frozen alone, for its records.
func (s *Service) unfenceableWhy(sb *models.Sandbox) string {
	switch {
	case sb.Runtime == models.RuntimeWasm || sb.Runtime == models.RuntimeIsolate:
		return "its host process runs other sandboxes too"
	case !s.leaseFreezable(sb.Runtime):
		return "its VMs' cgroup is not under the sandboxes' cgroup parent"
	}
	if err := s.recreateFenceReady(sb); err != nil {
		return "its VM is not in a group of its own"
	}
	return "its runtime cannot freeze it"
}

// stopUnfenceable stops sb, a recreate-policy sandbox the fence could not
// freeze, on a node that writes the lease file: only a sandbox whose policy
// disarmUnfencedRecreate has not turned off yet (new creates of such
// sandboxes are refused). Its lease ran out, so the cluster may be
// recreating it elsewhere, and a frozen-in-name sandbox would run on beside
// the copy. Its policy stays; it stays stopped until someone starts it.
// The caller holds the lifecycle boundary; f is sb's fence entry. It
// reports whether sb stopped.
func (s *Service) stopUnfenceable(ctx context.Context, sb *models.Sandbox, f *fencedSandbox) bool {
	if !s.ownershipLeaseFileOn() || sb.Status != models.SandboxStatusStarted {
		return false
	}
	why := "no authoritative read from the control plane within the ownership lease, and this node cannot freeze it alone (" + s.unfenceableWhy(sb) + ")"
	record := func(err error) {
		s.beginSystemActionReason(withAuditSubsystem(ctx, auditSubsystemFailover), sb.ID, systemActionLeaseStop, why)(err)
	}
	_, err := s.stopSandboxLocked(ctx, sb.ID, stopModeManual, statusReasonOwnershipLeaseExpired)
	s.ownership.mu.Lock()
	firstFailure := err != nil && !f.stopFailed
	f.stopFailed = err != nil
	s.ownership.mu.Unlock()
	if err != nil {
		// Tried again at every check (lease/15, 1 s by default): one
		// record and one log line for the run, not one per check.
		if firstFailure {
			record(err)
			if s.logger != nil {
				s.logger.Warn("cluster: could not stop a sandbox the ownership lease no longer covers and nothing can freeze; will retry", "sandbox_id", sb.ID, "error", err)
			}
		}
		return false
	}
	record(nil)
	if s.logger != nil {
		s.logger.Warn("cluster: stopped a failover.policy=recreate sandbox the ownership lease no longer covers; nothing on this node could freeze it alone", "sandbox_id", sb.ID, "runtime", sb.Runtime)
	}
	return true
}

// refuseUnfencedRecreate refuses a failover.policy=recreate create, on a
// node that writes the lease file, of a runtime whose sandboxes the runtime
// supervisor cannot freeze alone: such a sandbox could run on here after
// the cluster recreated it elsewhere. A field check, nothing more; it runs
// on the failover recreate path too, so a sandbox is never recreated onto
// a node that could not fence it. 400, as every create validation.
func (s *Service) refuseUnfencedRecreate(failover *models.Failover, chosenRuntime string) error {
	if !s.ownershipLeaseFileOn() || failover == nil || !failover.ShouldRecreate() || s.leaseFreezable(chosenRuntime) {
		return nil
	}
	why := "its host process runs other sandboxes too"
	if chosenRuntime == models.RuntimeFirecracker {
		why = "its VMs' cgroup (SB_HOST_PROCESS_CGROUP_PARENT) is not under the sandboxes' cgroup parent"
	}
	return fmt.Errorf("failover.policy=recreate is not available for runtime %q on this node: if the node lost touch with the cluster, its runtime supervisor could not stop such a sandbox alone (%s), so it could run on here after being recreated elsewhere; use failover.policy=none, or a container or Firecracker runtime", chosenRuntime, why)
}
