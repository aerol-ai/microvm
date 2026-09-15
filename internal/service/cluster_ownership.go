package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	secretspkg "github.com/aerol-ai/microvm/pkg/secrets"
)

// ReplayClusterOwnership pushes local sandbox truth into the cluster placement
// FSM. It is the local-store -> global-index repair path used at boot and by
// the periodic reconciler after Docker confirms a container still exists.
func (s *Service) ReplayClusterOwnership(ctx context.Context) (int, error) {
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
	for _, sb := range sandboxes {
		if sb == nil || sb.ID == "" || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
		if managed != nil {
			if _, ok := managed[sb.ID]; !ok {
				if !isStoppedFirecrackerSnapshotRow(sb) {
					continue
				}
			}
		}
		if !s.clusterOwnershipNeedsReplay(c, sb) {
			continue
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

func (s *Service) clusterOwnershipNeedsReplay(c cluster.Client, sb *models.Sandbox) bool {
	p, ok := c.PlacementOf(sb.ID)
	if !ok {
		return true
	}
	self := c.SelfNodeID()
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
		AllowPublicTraffic: sb.AllowPublicTraffic,
		ContainerCommand:   sb.ContainerCommand,
		Runtime:            sb.Runtime,
		GPUs:               sb.GPUs,
		Failover:           sb.Failover,
		TemplateID:         sb.TemplateID,
		OverlaySizeGB:      sb.OverlaySizeGB,
	}
	lc := sb.Lifecycle
	spec.Lifecycle = &lc
	if isStoppedFirecrackerSnapshotRow(sb) {
		spec.Failover = nil
	}

	auth, err := s.UnsealRegistry(sb.ID, sb.RegistryAuthSealed)
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
		if env, envErr := s.loadEnv(ctx, sb.ID); envErr != nil {
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
			Protocol:  p.Protocol,
			HostPort:  p.HostPort,
			PublicURL: p.PublicURL,
		}
	}
	return out
}
