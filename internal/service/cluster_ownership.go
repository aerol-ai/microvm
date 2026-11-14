package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	secretspkg "github.com/aerol-ai/microvm/pkg/secrets"
)

// ReplayClusterOwnership pushes local sandbox truth into the cluster placement
// FSM. It is the local-store -> global-index repair path used at boot and by
// the periodic reconciler after Docker confirms a container still exists.
func (s *Service) ReplayClusterOwnership(ctx context.Context) (int, error) {
	ctx = withAuditSubsystem(ctx, auditSubsystemBootRestore)
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		return 0, err
	}
	return s.assertClusterOwnership(ctx, sandboxes, nil)
}

func (s *Service) reconcileLocalClusterOwnership(ctx context.Context, sandboxes []*models.Sandbox, managed map[string]*models.SandboxRuntimeState) {
	count, err := s.assertClusterOwnership(ctx, sandboxes, managed)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: local ownership reconcile failed; will retry", "error", err)
		}
		return
	}
	if count > 0 && s.logger != nil {
		s.logger.Info("cluster: local ownership reconciled", "sandboxes", count)
	}
}

func (s *Service) assertClusterOwnership(ctx context.Context, sandboxes []*models.Sandbox, managed map[string]*models.SandboxRuntimeState) (int, error) {
	if !s.cfg.EnableCluster {
		return 0, nil
	}
	c := s.Cluster()
	if c == nil {
		return 0, nil
	}
	states := make([]cluster.LocalSandboxState, 0)
	var firstErr error
	now := time.Now()
	for _, sb := range sandboxes {
		if sb == nil || sb.ID == "" || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
		if sb.RollbackPending {
			// The client was told this create failed. Publishing the row
			// would promote its reservation or place it afresh: the failed
			// create would come back. reconcileRollbackPending destroys it.
			continue
		}
		if managed != nil {
			if _, ok := managed[sb.ID]; !ok {
				if !isStoppedFirecrackerSnapshotRow(sb) {
					continue
				}
			}
		}
		placement, placed := c.PlacementOf(sb.ID)
		if !placementNeedsReplay(c.SelfNodeID(), placement, placed, sb) {
			continue
		}
		if !placed {
			// Decided before the row is sealed: a row that is destroyed must
			// not get its secrets fanned out to peers again on the way out.
			place, err := s.settleUnplacedRow(ctx, c, sb, now)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			if !place {
				continue
			}
		}
		state, stateErr := s.localSandboxStateForCluster(ctx, c, sb)
		if stateErr != nil {
			// One corrupt or temporarily unreadable local row must not starve
			// ownership repair for every other sandbox on the node. Keep that row
			// out of Raft, reconcile the safe rows, and report the failure for retry.
			if firstErr == nil {
				firstErr = stateErr
			}
			continue
		}
		states = append(states, state)
	}
	if len(states) == 0 {
		return 0, firstErr
	}
	return len(states), errors.Join(firstErr, c.AssertOwnership(ctx, states))
}

// clusterLifecycleDeleted reports whether the cluster deleted the lifecycle of
// a local row that has no placement: a post-delete record exists for its exact
// incarnation. That happens when this node was cut off while the sandbox was
// moved and deleted, or deleted as an orphan. It also returns the incarnation
// it asked about. Never asks without an incarnation: the newest record for the
// id could belong to another lifetime.
//
// A server answers from its own replica, so it must have caught up first: a
// restarted node that has not applied the delete yet would answer "no record",
// and settleUnplacedRow would then decide on a false premise.
func (s *Service) clusterLifecycleDeleted(ctx context.Context, c cluster.Client, sb *models.Sandbox) (string, bool, error) {
	if !cluster.CaughtUp(c) {
		return "", false, fmt.Errorf("ownership replay of %s: %w", sb.ID, cluster.ErrNotCaughtUp)
	}
	incarnationID, err := s.localSandboxAuditIncarnation(ctx, sb)
	if err != nil || incarnationID == "" {
		return "", false, err
	}
	_, deleted, err := c.AuditACLForSandbox(ctx, sb.ID, incarnationID)
	if err != nil {
		return "", false, fmt.Errorf("ownership replay of %s: post-delete record lookup: %w", sb.ID, err)
	}
	return incarnationID, deleted, nil
}

// Outcomes for a local row with no placement that the replay does not place,
// counted in aerolvm_cluster_ownership_replay_unplaced_total.
const (
	unplacedDestroyedDeleted  = "destroyed_deleted"
	unplacedDestroyedUnproven = "destroyed_unproven"
	unplacedKeptGraceOff      = "kept_grace_off"
	unplacedKeptNoIncarnation = "kept_no_incarnation"
)

var clusterUnplacedRows = expvar.NewMap("aerolvm_cluster_ownership_replay_unplaced_total")

// unplacedReplayClockSkew is the clock difference unplacedRowPlaceable allows
// between the node that stamped a post-delete record's expiry (the deleter),
// the leader that prunes it, and this node, which stamped the row's
// CreatedAt.
const unplacedReplayClockSkew = time.Minute

// unplacedRowPlaceable reports whether a local row with no placement and no
// post-delete record is provably not a deleted sandbox, so it may be placed:
//
//   - soleServer: this node is the only Raft server. Nothing commits without
//     it, so no delete happened while it was away. This is how a single node
//     turned into a cluster seed (setup/cluster.md) keeps its sandboxes.
//   - the row is younger than grace less clock skew. A delete after it was
//     created would still have its record.
//
// The zero CreatedAt counts as old.
func unplacedRowPlaceable(createdAt, now time.Time, grace time.Duration, soleServer bool) bool {
	if soleServer {
		return true
	}
	window := grace - unplacedReplayClockSkew
	if window <= 0 || createdAt.IsZero() {
		return false
	}
	return now.Sub(createdAt) < window
}

// settleUnplacedRow decides what happens to a local row the cluster has no
// placement for, and reports whether the caller should hand it to
// AssertOwnership to be placed. Everything else it does itself.
//
// The rule (user decision on C2): destroy the row unless it is provably not
// a deleted sandbox. A post-delete record for its incarnation means deleted;
// unplacedRowPlaceable is the proof of the opposite; anything in between is
// unproven and destroyed too. A cut-off node's placements are orphaned or
// moved, not removed, so an old row with no placement at all is one that was
// deleted, or a create that never finished, in almost every case.
//
// Two guards keep the rule from destroying on no evidence at all:
//
//   - SB_AUDIT_DELETED_GRACE=0 keeps no records, so every outage, however
//     short, would count as "away longer than the grace". The row is kept
//     and logged.
//   - A row with no incarnation cannot be matched to a record, nor finalized
//     by the cluster destroy path. It is kept and logged.
//
// A failed lookup, or a replica that has not caught up, changes nothing.
func (s *Service) settleUnplacedRow(ctx context.Context, c cluster.Client, sb *models.Sandbox, now time.Time) (bool, error) {
	incarnationID, deleted, err := s.clusterLifecycleDeleted(ctx, c, sb)
	if err != nil {
		return false, err
	}
	if deleted {
		return false, s.destroyUnplacedLocalSandbox(ctx, sb.ID, incarnationID, unplacedDestroyedDeleted)
	}
	if unplacedRowPlaceable(sb.CreatedAt, now, s.cfg.AuditDeletedGrace, cluster.SoleRaftServer(c)) {
		return true, nil
	}
	switch {
	case s.cfg.AuditDeletedGrace <= 0:
		s.keepUnplacedRow(sb, unplacedKeptGraceOff,
			"cluster: local sandbox has no placement; SB_AUDIT_DELETED_GRACE=0 keeps no delete records, so it is neither placed nor destroyed")
		return false, nil
	case incarnationID == "":
		s.keepUnplacedRow(sb, unplacedKeptNoIncarnation,
			"cluster: local sandbox has no placement and no incarnation to check; it is neither placed nor destroyed")
		return false, nil
	}
	return false, s.destroyUnplacedLocalSandbox(ctx, sb.ID, incarnationID, unplacedDestroyedUnproven)
}

func (s *Service) keepUnplacedRow(sb *models.Sandbox, outcome, message string) {
	clusterUnplacedRows.Add(outcome, 1)
	if s.logger != nil {
		s.logger.Warn(message, "sandbox_id", sb.ID, "created_at", sb.CreatedAt,
			"audit_deleted_grace", s.cfg.AuditDeletedGrace)
	}
}

// destroyUnplacedLocalSandbox destroys this node's copy of a sandbox the
// cluster has no placement for: one whose lifecycle it deleted
// (unplacedDestroyedDeleted), or one nothing proves is live
// (unplacedDestroyedUnproven). It is the ordinary destroy: with no
// placement, its delete fence and placement delete are no-ops, and the
// lifetime-wide cleanup (exact-incarnation secrets, routes, runtime) is right
// because no node owns that lifetime.
//
// Under the lifecycle lock it reads the row again (left alone if gone or
// another lifetime by now) and asks the cluster authoritatively whether the
// id has a placement. A worker's PlacementOf reports "none" when its lookup
// fails, and destroying a placed sandbox from here would run the full user
// delete, placement included. Any placement leaves the row to the paths that
// handle placed rows.
func (s *Service) destroyUnplacedLocalSandbox(ctx context.Context, sandboxID, incarnationID, outcome string) error {
	c := s.Cluster()
	if c == nil {
		return fmt.Errorf("%w: placement client unavailable", ErrClusterFinalizationUnavailable)
	}
	unlock, err := s.lifecycleLocks.lockCtx(ctx, sandboxID)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := s.store.Get(ctx, sandboxID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	currentIncarnation, err := s.localSandboxAuditIncarnation(ctx, current)
	if err != nil {
		return err
	}
	if currentIncarnation != incarnationID {
		return nil
	}
	placements, err := c.AuthoritativePlacementsByIDs(ctx, []string{sandboxID})
	if err != nil {
		return fmt.Errorf("ownership replay of %s: confirm no placement before destroy: %w", sandboxID, err)
	}
	if _, ok := placements[sandboxID]; ok {
		return nil
	}
	action := systemActionClusterDeleted
	message := "cluster: destroying local sandbox; the cluster deleted it while this node was away"
	if outcome == unplacedDestroyedUnproven {
		action = systemActionClusterUnproven
		message = "cluster: destroying local sandbox; it has no placement and nothing proves it was not deleted while this node was away"
	}
	if s.logger != nil {
		s.logger.Warn(message, "sandbox_id", sandboxID, "incarnation_id", incarnationID, "created_at", current.CreatedAt)
	}
	done := s.beginSystemAction(ctx, sandboxID, action)
	err = s.destroySandboxLocked(ctx, sandboxID)
	if errors.Is(err, store.ErrNotFound) {
		err = nil
	}
	done(err)
	if err == nil {
		clusterUnplacedRows.Add(outcome, 1)
	}
	return err
}

// placementNeedsReplay reports whether the ownership replay must hand sb to
// AssertOwnership, given the placement (p, ok) this node sees for it.
func placementNeedsReplay(self string, p cluster.Placement, ok bool, sb *models.Sandbox) bool {
	if !ok {
		return true
	}
	if placementCanBeClaimedBySelf(p, self) {
		return true
	}
	if p.OwnerNodeID != self || p.IsOrphaned() {
		return false
	}
	if p.IsReserved() {
		return true
	}
	if p.Spec == nil {
		return true
	}
	if isStoppedFirecrackerSnapshotRow(sb) && p.Spec.ShouldRecreateOnFailover() {
		return true
	}
	if p.Spec.TemplateID != sb.TemplateID || p.Spec.OverlaySizeGB != sb.OverlaySizeGB {
		return true
	}
	if placementMissingLocalPorts(p, sb) {
		return true
	}
	return placementMissingLocalCustomHostnames(p, sb)
}

func placementCanBeClaimedBySelf(p cluster.Placement, self string) bool {
	if !p.IsOrphaned() {
		return false
	}
	return p.OrphanedOwnerNodeID == "" || p.OrphanedOwnerNodeID == self
}

// placementMissingLocalCustomHostnames returns true when the local sandbox
// has bound hostnames the FSM placement doesn't yet list. This is the boot
// catch-up signal: the FSM was added after the sandbox already had domains
// (cluster mode flipped on, or PR #3 deploy), or a prior AssertOwnership
// failed to ship them. Force a replay so the failover-recreate target has
// the user's TLS matchers.
func placementMissingLocalCustomHostnames(p cluster.Placement, sb *models.Sandbox) bool {
	local := sandboxCustomHostnamesList(sb)
	if len(local) == 0 {
		return false
	}
	have := make(map[string]struct{}, len(p.CustomHostnames))
	for _, h := range p.CustomHostnames {
		have[h] = struct{}{}
	}
	for _, h := range local {
		if _, ok := have[h]; !ok {
			return true
		}
	}
	return false
}

func placementMissingLocalPorts(p cluster.Placement, sb *models.Sandbox) bool {
	if len(sb.ExposedPorts) == 0 {
		return false
	}
	routes := cluster.ExposedPortRoutesForPlacement(p)
	for _, port := range sb.ExposedPorts {
		if port.Port <= 0 {
			continue
		}
		route, ok := routes[port.Port]
		if !ok {
			return true
		}
		if route.Protocol != port.Protocol || route.HostPort != port.HostPort || route.PublicURL != port.PublicURL {
			return true
		}
	}
	return false
}

func (s *Service) localSandboxStateForCluster(ctx context.Context, c cluster.Client, sb *models.Sandbox) (cluster.LocalSandboxState, error) {
	spec, err := s.specFromSandbox(ctx, sb)
	if err != nil {
		return cluster.LocalSandboxState{}, err
	}
	var secrets cluster.PlacementSecrets
	if spec != nil {
		// Reuse the exact durable seal when possible and otherwise preserve (or
		// restore) the HA recipient width. Boot replay has no reservation from
		// which RecordPlacement could recover that set. Never put the unredacted
		// recovery spec into Raft: a sealing failure leaves this row pending for
		// the next reconciliation pass instead of leaking credentials.
		handle, sealErr := s.secretHandleForOwnershipReplay(ctx, c, sb, *spec)
		if sealErr != nil {
			return cluster.LocalSandboxState{}, fmt.Errorf("seal sandbox %s for ownership replay: %w", sb.ID, sealErr)
		}
		if handle.Ref != "" {
			secrets = handle
		}
		redacted := RedactClusterSecrets(*spec)
		spec = &redacted
	}
	// A sandbox without credentials still has a lifecycle. Carry the durable
	// audit incarnation into Raft so a later credential rotation and audit
	// authorization cannot attach to two different lifetimes.
	if secrets.IncarnationID == "" {
		var err error
		secrets.IncarnationID, err = s.localSandboxAuditIncarnation(ctx, sb)
		if err != nil {
			return cluster.LocalSandboxState{}, err
		}
	}
	secrets.OwnerRef = sb.OwnerRef
	return cluster.LocalSandboxState{
		ID:              sb.ID,
		Spec:            spec,
		Secrets:         secrets,
		ExposedPorts:    clusterPortsFromSandbox(sb),
		CustomHostnames: sandboxCustomHostnamesList(sb),
	}, nil
}

func (s *Service) secretHandleForOwnershipReplay(ctx context.Context, c cluster.Client, sb *models.Sandbox, spec models.CreateSandboxRequest) (cluster.PlacementSecrets, error) {
	if secretsFromRequest(spec).IsEmpty() {
		return cluster.PlacementSecrets{}, nil
	}
	selfID := strings.TrimSpace(c.SelfNodeID())
	placement, placed := c.PlacementOf(sb.ID)
	incarnationID := strings.TrimSpace(sb.AuditIncarnationID)
	if placed && strings.TrimSpace(placement.IncarnationID) != "" {
		incarnationID = strings.TrimSpace(placement.IncarnationID)
	}

	var local *store.ClusterSecretRecord
	if s.store != nil && incarnationID != "" {
		rec, err := s.store.GetClusterSecretForSandboxIncarnation(ctx, sb.ID, incarnationID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return cluster.PlacementSecrets{}, fmt.Errorf("load durable secret for ownership replay: %w", err)
		}
		local = rec
	}

	recipients := secretspkg.NormalizeRecipients(placement.SecretRecipients)
	if local != nil && (len(recipients) == 0 || local.SealGeneration > placement.SecretSealGeneration) {
		recipients = secretspkg.NormalizeRecipients(local.Recipients)
	}
	if len(recipients) == 0 {
		recipients = []string{selfID}
	}

	// A previously buggy replay may have published only self. Widen active or
	// missing placements immediately; an orphan is first reclaimed with its
	// existing valid seal and the periodic recipient reconciler widens it once
	// peers will accept owner-authorized PUTs again.
	if spec.ShouldRecreateOnFailover() && (!placed || !placement.IsOrphaned()) &&
		len(nonSelfRecipients(recipients, selfID)) < s.SecretRecipientBackupCount() {
		if replacements := s.selectReplacementRecipients(sb.ID, selfID, s.SecretRecipientBackupCount()); len(nonSelfRecipients(replacements, selfID)) > len(nonSelfRecipients(recipients, selfID)) {
			recipients = replacements
		}
	}

	if local != nil && sameStringSlice(secretspkg.NormalizeRecipients(local.Recipients), secretspkg.NormalizeRecipients(recipients)) {
		return cluster.PlacementSecrets{
			Ref: local.Ref, Version: local.Version, Recipients: append([]string(nil), local.Recipients...),
			IncarnationID: incarnationID, SealGeneration: local.SealGeneration,
		}, nil
	}
	return s.sealAndDistributeForIncarnation(ctx, sb.ID, spec, recipients, incarnationID)
}

func (s *Service) specFromSandbox(ctx context.Context, sb *models.Sandbox) (*models.CreateSandboxRequest, error) {
	if sb == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	spec := &models.CreateSandboxRequest{
		Image:              sb.Image,
		CPU:                sb.CPU,
		MemoryMB:           sb.MemoryMB,
		DiskGB:             sb.DiskGB,
		Env:                sb.Env,
		OSUser:             sb.OSUser,
		NetworkBlockAll:    sb.NetworkBlockAll,
		NetworkAllowOut:    sb.NetworkAllowOut,
		NetworkDenyOut:     sb.NetworkDenyOut,
		NetworkEgressMode:  sb.NetworkEgressMode,
		NetworkEgressRules: sb.NetworkEgressRules,
		AllowPublicTraffic: sb.AllowPublicTraffic,
		ContainerCommand:   sb.ContainerCommand,
		Runtime:            sb.Runtime,
		GPUs:               sb.GPUs,
		Failover:           sb.Failover,
		TemplateID:         sb.TemplateID,
		OverlaySizeGB:      sb.OverlaySizeGB,
	}
	// The row stores the effective allow list; a replay needs the inline
	// list and the references, so profile changes keep reaching it.
	if s.store != nil {
		profiles, err := s.store.GetSandboxEgressProfiles(ctx, sb.ID)
		if err != nil {
			return nil, fmt.Errorf("load egress profiles for ownership replay %s: %w", sb.ID, err)
		}
		if st, err := s.store.GetEgressState(ctx, sb.ID); err == nil {
			spec.EgressWithheldEnv = st.Withheld
		}
		if len(profiles.Refs) > 0 {
			// Profiles and block-all are exclusive; a block-all row with
			// references is a replay held until its profiles resolve.
			spec.NetworkBlockAll = false
			spec.NetworkAllowOut = profiles.Inline
			for _, r := range profiles.Refs {
				spec.EgressProfiles = append(spec.EgressProfiles, r.Name)
			}
		}
	}
	lc := sb.Lifecycle
	spec.Lifecycle = &lc
	if isStoppedFirecrackerSnapshotRow(sb) {
		spec.Failover = nil
	}

	auth, err := s.UnsealRegistry(ctx, sb.ID, sb.RegistryAuthSealed)
	if err != nil {
		return nil, fmt.Errorf("unseal registry auth for ownership replay %s: %w", sb.ID, err)
	}
	spec.Registry = auth
	if s.store != nil && s.cipher != nil {
		mounts, err := s.loadMounts(ctx, sb.ID)
		if err != nil {
			return nil, fmt.Errorf("load mounts for ownership replay %s: %w", sb.ID, err)
		} else if len(mounts) > 0 {
			spec.Mounts = mounts
		}
		if env, envErr := s.loadEnv(ctx, sb.ID, sb.AuditIncarnationID); envErr != nil {
			return nil, fmt.Errorf("load environment for ownership replay %s: %w", sb.ID, envErr)
		} else if len(env) > 0 {
			spec.Env = env
		}
	}
	return spec, nil
}

func isStoppedFirecrackerSnapshotRow(sb *models.Sandbox) bool {
	return sb != nil && sb.Runtime == models.RuntimeFirecracker && sb.Status == models.SandboxStatusStopped
}

func clusterPortsFromSandbox(sb *models.Sandbox) map[int]cluster.ExposedPortRoute {
	if sb == nil || len(sb.ExposedPorts) == 0 {
		return nil
	}
	out := make(map[int]cluster.ExposedPortRoute, len(sb.ExposedPorts))
	for _, p := range sb.ExposedPorts {
		if p.Port <= 0 {
			continue
		}
		out[p.Port] = cluster.ExposedPortRoute{
			Protocol:   p.Protocol,
			HostPort:   p.HostPort,
			PublicURL:  p.PublicURL,
			Visibility: p.Visibility,
		}
	}
	return out
}
