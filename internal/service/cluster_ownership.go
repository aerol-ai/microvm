package service

import (
	"context"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
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
		states = append(states, s.localSandboxStateForCluster(ctx, c, sb))
	}
	if len(states) == 0 {
		return 0, nil
	}
	return len(states), c.AssertOwnership(ctx, states)
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

func (s *Service) localSandboxStateForCluster(ctx context.Context, c cluster.Client, sb *models.Sandbox) cluster.LocalSandboxState {
	spec := s.specFromSandbox(ctx, sb)
	var secrets cluster.PlacementSecrets
	if spec != nil {
		handle, err := s.PutClusterSecretsForRecipient(ctx, sb.ID, *spec, c.SelfNodeID())
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: store secret ref during ownership replay failed; placement will ship without secret ref",
					"sandbox_id", sb.ID, "err", err)
			}
		} else {
			secrets = handle
			redacted := RedactClusterSecrets(*spec)
			spec = &redacted
		}
	}
	return cluster.LocalSandboxState{
		ID:              sb.ID,
		Spec:            spec,
		Secrets:         secrets,
		ExposedPorts:    clusterPortsFromSandbox(sb),
		CustomHostnames: sandboxCustomHostnamesList(sb),
	}
}

func (s *Service) specFromSandbox(ctx context.Context, sb *models.Sandbox) *models.CreateSandboxRequest {
	if sb == nil {
		return nil
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

	auth, err := s.UnsealRegistry(sb.RegistryAuthSealed)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: unseal registry auth failed; spec backfill will omit credentials",
				"sandbox_id", sb.ID, "err", err)
		}
	} else {
		spec.Registry = auth
	}
	if s.store != nil && s.cipher != nil {
		mounts, err := s.loadMounts(ctx, sb.ID)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: load sandbox mounts failed; spec backfill will omit mounts",
					"sandbox_id", sb.ID, "err", err)
			}
		} else if len(mounts) > 0 {
			spec.Mounts = mounts
		}
	}
	return spec
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
