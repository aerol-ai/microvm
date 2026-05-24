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
				continue
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
	return placementMissingLocalPorts(p, sb)
}

func placementCanBeClaimedBySelf(p cluster.Placement, self string) bool {
	if !p.IsOrphaned() {
		return false
	}
	return p.OrphanedOwnerNodeID == "" || p.OrphanedOwnerNodeID == self
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
	spec := s.specFromSandbox(sb)
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
		ID:           sb.ID,
		Spec:         spec,
		Secrets:      secrets,
		ExposedPorts: clusterPortsFromSandbox(sb),
	}
}

func (s *Service) specFromSandbox(sb *models.Sandbox) *models.CreateSandboxRequest {
	if sb == nil {
		return nil
	}
	spec := &models.CreateSandboxRequest{
		Image:            sb.Image,
		CPU:              sb.CPU,
		MemoryMB:         sb.MemoryMB,
		DiskGB:           sb.DiskGB,
		Env:              sb.Env,
		OSUser:           sb.OSUser,
		NetworkBlockAll:  sb.NetworkBlockAll,
		ContainerCommand: sb.ContainerCommand,
		Runtime:          sb.Runtime,
		GPUs:             sb.GPUs,
		Failover:         sb.Failover,
	}
	lc := sb.Lifecycle
	spec.Lifecycle = &lc

	auth, err := s.UnsealRegistry(sb.RegistryAuthSealed)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: unseal registry auth failed; spec backfill will omit credentials",
				"sandbox_id", sb.ID, "err", err)
		}
	} else {
		spec.Registry = auth
	}
	return spec
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
